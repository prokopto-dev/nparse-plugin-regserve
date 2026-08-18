# Canonical conventions

**Status:** normative. This document is the tie-breaker. When another document disagrees with it,
this one wins and the disagreement is a bug worth reporting. `AGENTS.md` outranks it only on the
short list of rules it states directly.

Every section here is either enforced by a named gate or explicitly marked as a review rule.

## 1. The wire format is not ours to change

`GET /index.json` is parsed by nParse+ installs already in the field. The parser is the pydantic
model in `nparseplus.core.plugins.registry`; the schema generated from it is vendored at
`internal/registry/testdata/index-v1.schema.json`.

- `schema_version` is `1`. A client that sees a higher number refuses the whole index and tells the
  user to update. Bumping it strands every release that has ever shipped.
- Adding a field is safe (the client ignores unknown keys). Renaming or removing one is not.
- Only `latest` goes on the wire — one release per plugin, no history, no downgrade path.
- Budgets belong to the client, not to us: **< 5 MiB** body, **15 s** to first byte through last,
  at most **5 redirect hops, every one `https`**.

Gate: `SCHEMA001` validates rendered output against the vendored schema; `SIZE001` fails as the
rendered index approaches the size cap. The vendored schema is generated upstream and copied in —
editing it here to make a test pass inverts the point of the gate.

## 2. Time

Times are stored as `INTEGER` Unix **microseconds** UTC, in a column suffixed `_at`. The Go type is
`core.Micros`. On the wire they are RFC 3339 strings; the conversion happens at the API edge and
nowhere else.

`time.Now` exists only in `internal/clock`. Gate: `CLOCK001`, an AST analyser, so aliasing the
import does not defeat it. Services take a `clock.Clock`; tests inject a fixed one.

## 3. Identifiers

- Internal primary keys are **ULIDs** in `TEXT` columns, generated from `crypto/rand`.
- **Plugin ids are different and are not ours.** A plugin id is the string the plugin declares in
  `PluginMeta.id`, matching `^[a-z][a-z0-9_-]{1,39}$`, and it is the plugin's identity in every
  installed copy on every user's machine. It is permanent, first-come, and **never recycled**.
- The regex lives in exactly one place, `internal/core`, and everything else refers to it. It
  mirrors `nparseplus_sdk.plugin.PLUGIN_ID_RE`; if that changes, this is a coordinated change.

## 4. Enums

Enum values are lowercase `snake_case`, identical in the DB `CHECK`, the JSON, and the OpenAPI
document. They are `TEXT + CHECK` in SQLite, never integers — a number in a database means nothing
to the person reading it at 2am.

The Go constants are the source; `make gen` writes the CHECK constraints into `db/schema.hcl`
between `GENERATED` markers. Do not hand-edit inside those markers.

## 5. Permissions and scopes — one catalogue, generated

There is exactly one source: `internal/authz/catalogue.go`. It generates the permission-table seed,
the OpenAPI `x-regserve-permission` metadata, the PAT scope enum, and
`docs/reference/permissions.md`. A hand-written permission list anywhere else is forbidden.

- Permissions are `<resource>.<action>`, dot-separated, lowercase: `plugin.publish`, `owner.manage`.
- Scopes are `<family>:<verb>`, colon-separated: `plugin:publish`, `plugin:read`.
- Scopes are coarser than permissions on purpose. A scope narrows a *token*; a permission narrows a
  *role*; effective capability is the intersection.
- **Every key is written as a whole quoted literal.** The spec gate reads the file as text and
  asserts the exact quoted string appears. A composed key (`resource + "." + action`) produces the
  right runtime value and fails the gate. Do not "tidy" the catalogue into fields.

### The capability floor

Some operations carry **no scope at all** and are session-only, because a token that could perform
them would be equivalent to the account:

- minting, listing and revoking PATs
- adding, removing or transferring plugin owners
- setting an account's trust level
- approving or rejecting a release

There is no `admin:*` scope and no all-powerful token. An operation in the floor declares
`x-regserve-pat-forbidden: true` and no scopes; a PAT-callable operation declares a non-empty scope
list; a session-only-by-omission operation declares neither. The architectural test asserts all
three cases against the route registry.

## 6. HTTP conventions

- Base path `/api/v1` for the product API. The client-facing index endpoints (`/index.json`,
  `/plugins/{id}/index.json`) sit **outside** it, at stable paths, because their shape is pinned by
  a schema we do not own and must not move when the product API versions.
- Errors are RFC 9457 `application/problem+json` with a stable machine `code` from the closed enum
  in `internal/api/errors.go`. Adding a code is a spec change and needs a docs page (`DOC001`).
- **Never return 200 with an error body.**
- Every operation sets an explicit `OperationID` in lowerCamelCase (`publishRelease`). The generated
  SDK method name derives from it, so **it is public API and must never be renamed.**
- `Authorization: Bearer nprs_pat_…` only. **A token in a query string is rejected with 401, no
  exception** — query strings land in access logs, proxy logs and browser history.
- Session cookie is `__Host-regserve_session`.
- **Every mutating POST that creates domain state requires `Idempotency-Key`.** The dominant caller
  is a release workflow, and workflows are re-run. A re-run must not mint a second pending release.
- Handlers return Huma error types; they never touch `http.ResponseWriter`.
- One file per resource in `internal/api`, each exporting `registerXxx`. Never a shared registration
  file — it conflicts on every parallel feature PR.

## 7. Database conventions

- Tables singular (`plugin_owner`), columns `snake_case`, times suffixed `_at`, byte counts suffixed
  `_bytes`.
- Every table is `STRICT`. Booleans are `INTEGER CHECK (x IN (0,1))`.
- `db/schema.hcl` is the single declarative truth. Atlas diffs it and writes a numbered migration
  into `db/migrations-sqlite/`; goose, embedded via `go:embed`, applies them at boot.
- Migrations are **forward-only**. Every `Down` block is `RAISE(ABORT, …)` naming the backup path.
  Recovery is restoring the snapshot taken immediately before the migration ran.
- A migration that has shipped in a tagged release is never edited. `db/SHIPPED.lock` freezes them
  by sha256; gate `MIG003`.
- Raw SQL lives in `db/queries/*.sql` and is typed by sqlc into `internal/store/sqlitegen/`. Never
  hand-edit generated code; never write SQL elsewhere.
- Mutations go through `store.Tx`, which hands the callback a `store.Queries` and never a `*sql.Tx`.
- Reads go through `store.Read()`, whose connections are `PRAGMA query_only`. The writer is a single
  connection with `_txlock=immediate` ([ADR-0001](../adr/0001-go-single-binary-and-sqlite.md)).

### A column is never named after a wire field

`release.sdk_specifier` and `release.minimum_app_version` carry what the index document calls
something else, and the difference is load-bearing: sqlc writes column names into Go **string
literals** in `internal/store/sqlitegen`, so a column named after a wire field would put that field
name in a second package and fail `SCHEMA002`. The database describes a release; `internal/registry`
decides how a release is spelled to a client.

### What `db/schema.hcl` cannot say

The community build of Atlas models neither triggers nor data. A `trigger` block in `schema.hcl` is
parsed and then **silently ignored**, which is worse than absent because a reader would believe it.

So the append-only triggers, the no-delete triggers, and the single `identity_provider` row are
hand-authored in the initial migration, below a marked boundary, and each is asserted by a test in
`internal/store` that issues the forbidden statement and requires the abort. Atlas replays the
migration directory to compute its next diff, so it sees those objects and leaves them alone.

### `make migration` post-processes what Atlas writes

Atlas writes correct SQLite that is not ours. `scripts/finish-migration.sh` runs after every diff,
is idempotent, and does three things — each one a bug somebody would otherwise hit:

1. **Backticks become double quotes.** sqlc's SQLite parser does not understand backtick quoting and
   reports the table as not existing, which reads like a missing migration rather than a quoting
   style.
2. **A redundant `NULL` column constraint is removed.** `text NULL` and `text` are identical to
   SQLite, but sqlc stops resolving the type at the explicit keyword and emits `interface{}`. That
   compiles, so nothing fails until somebody type-asserts one at runtime.
3. **The `Down` block is replaced** with the `RAISE(ABORT, …)` that `MIG002` requires, rather than
   the `DROP` statements Atlas generates.

## 8. Ownership and the trust model

The property inherited from the static registry, which nothing here may quietly discard:

> An author cannot change the bytes a user receives without a fresh review of those bytes.

The mechanism is that the stored sha256 is one the *server* computed, from an artifact the *server*
downloaded, and a change to it is a new release row with its own approval state.

- A **new plugin id** always requires human approval. Trust levels never bypass this.
- A **version bump of an approved plugin** by a sufficiently trusted owner publishes automatically,
  but only after the artifact is fetched and re-hashed clean.
- If the artifact **could not be fetched**, the release is not published. It goes to review with the
  reason recorded. Reporting success on an unverified artifact is the one failure mode this whole
  design exists to prevent.
- Quarantine triggers — artifact host change, large size delta, version regression, hash mismatch —
  send a release to review regardless of trust.

## 9. Outbound requests

Only `internal/identity/*` and `internal/artifact` may make them. Gate: `NET001`. Today that is
`internal/identity/github`, the only provider
([ADR-0011](../adr/0011-github-is-the-only-identity-provider.md)); the gate is written against the
tree, so a second provider needs no change to it.

Every outbound request:

- carries the caller's `ctx` (`noctx` lints this),
- goes through the guarded client, whose dialer refuses private, link-local, loopback, multicast and
  cloud-metadata addresses — the URL being user-supplied is the normal case, not the exception,
- re-asserts `https` on **every** redirect hop and caps the hop count,
- caps the response size **during** the read, not after, and
- has an explicit timeout.

This is deliberately one package wider than the sibling projects' rule, because this service must
fetch artifacts to hash them. The widening is recorded in `docs/concepts/invariants.md` so it stays
deliberate rather than becoming precedent.

## 10. Secrets

The GitHub OAuth client secret and the token pepper are the security model. They come from the
environment, are held in `core.Secret` (whose `String()` and `MarshalJSON` redact), and are never
logged, never returned by an endpoint, and never written to the database.

PATs are `nprs_pat_<8-char public prefix>_<43 chars base64url of 32 random bytes>`, stored as
`HMAC-SHA256(pepper, secret)` — a keyed hash rather than bcrypt, because verification is on the hot
path of every publish. The prefix is loggable and is how a leaked token is found in a log; the
secret never is.

## 11. Health checks

`/healthz` is liveness: it touches nothing and answers 200 as long as the process is up.
`/readyz` is readiness: it checks the database and reports *why* it is not ready. A missing or
unopenable database logs and still serves, so `/healthz` stays green and `/readyz` explains; only a
failed migration or a schema downgrade is fatal at boot.

## 12. Naming quick reference

| Thing | Convention | Example |
|---|---|---|
| Internal id | ULID in `TEXT` | `01JQ8…` |
| Plugin id | `^[a-z][a-z0-9_-]{1,39}$`, permanent | `merchant-mode` |
| Table | singular, `snake_case` | `plugin_owner` |
| Timestamp column | `_at`, INTEGER micros | `verified_at` |
| Byte count | `_bytes` | `artifact_bytes` |
| Permission | `<resource>.<action>` | `plugin.publish` |
| Scope | `<family>:<verb>` | `plugin:publish` |
| OperationID | lowerCamelCase, never renamed | `publishRelease` |
| Enum value | lowercase `snake_case` | `needs_review` |
| PAT | `nprs_pat_<prefix>_<secret>` | — |

## What to do when two rules conflict

The invariant wins, and the conflict is a bug: say so in the PR rather than picking one silently.
If the conflict is between this document and `AGENTS.md`, `AGENTS.md` wins on the rules it states
directly and this document wins on everything else.
