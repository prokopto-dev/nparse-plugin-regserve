# Working in this repository

**Status:** normative. Read this before changing anything. `CLAUDE.md` includes this file.

`nparse-plugin-regserve` is the live plugin registry for [nParse+](https://github.com/prokopto-dev/nparse-plus).
It replaces a static, PR-gated `index.json` with a server: plugin CI publishes a release with a
scoped token, ownership is a database row, and publishing is a pipeline step instead of a pull
request. One Go binary, SQLite, API-first. Apache-2.0.

Much of this codebase is written by AI agents under human review, which is why the repository is
unusually explicit about invariants and unusually aggressive about mechanical enforcement.

**The governing rule: a rule without a gate is a wish.** If you add a rule, add the test, lint rule,
CI gate or database trigger that enforces it, and name it in
[`docs/concepts/invariants.md`](docs/concepts/invariants.md). If you cannot, say so in the PR rather
than writing it down as though it were enforced.

**Full conventions:** [`docs/design/00-canonical-conventions.md`](docs/design/00-canonical-conventions.md)
is normative. When this file and another document disagree, this file and that one win over the
other document — and the conflict is a bug worth reporting.

## The one contract that outranks everything

A released nParse+ desktop client, already in users' hands, parses what `GET /index.json` returns.
Its parser is the pydantic model in `nparseplus.core.plugins.registry`; the JSON Schema generated
from it is vendored here at `internal/registry/testdata/index-v1.schema.json`.

- **`schema_version` is `1` and changing it breaks every released client.** They refuse the index
  outright and tell the user to update nParse+. A bump needs a deprecation plan, not a commit.
- Additive fields are tolerated (pydantic ignores unknown keys). Renaming or removing one is not.
- The rendered index must stay **under 5 MiB** and answer within **15 seconds** — those are the
  client's hard limits, not ours. `SIZE001` gates the first.
- If you change what `internal/registry` emits — **or anything between it and the socket** —
  `SCHEMA001` is the test that decides whether you were allowed to. It runs a real server, makes a
  real request, and validates the response bytes, so the HTTP layer is inside the gate rather than
  downstream of it. Do not edit the vendored schema to make it pass; it is generated upstream by
  `tools/gen_registry_schema.py` in `nparse-plus` and copied here.
- The index endpoints return their body as **raw bytes** that Huma writes verbatim
  ([ADR-0012](docs/adr/0012-huma-v2-everywhere-with-the-index-bytes-pinned.md)). That is not an
  oversight to tidy into a typed response body: a typed body would be marshalled by the framework,
  which content-negotiates, escapes differently and can add members to the document.

## Where things are

| Path | Holds |
|---|---|
| `cmd/regserve/` | The only binary. Cobra wiring, no logic |
| `internal/api/` | Every HTTP route, registered with Huma v2 ([ADR-0012](docs/adr/0012-huma-v2-everywhere-with-the-index-bytes-pinned.md)). `routes.go` holds the only registration helper, and its signature demands an access declaration; `security.go` is the middleware that ENFORCES that same declaration. ETag and idempotency (canonical §6) are not built yet |
| `internal/authz/` | **The** catalogue — permissions and PAT scopes, in `catalogue.go`, every key a whole quoted literal (`AUTHZ001`). It generates the scope list, the `x-regserve-permission` metadata and [`docs/reference/permissions.md`](docs/reference/permissions.md). Nothing else may hold a permission list |
| `internal/auth/` | PAT mint and verify, sessions, OAuth state and PKCE. A credential's secret is never stored: what is, is `HMAC-SHA256(pepper, secret)`. The 8-character token prefix is the public half and the only part that may be logged |
| `internal/audit/` | The ONE writer of `audit_log` rows. Append-only, and `detail` never carries a secret |
| `internal/identity/{,github,guard}/` | Provider registry, credential dispatch, identity resolution. GitHub is the only provider ([ADR-0011](docs/adr/0011-github-is-the-only-identity-provider.md)). `guard` builds the client every outbound request goes through, and `internal/artifact` will use the same one |
| `internal/artifact/` | Artifact download and re-hash. Never extracts, never executes |
| `internal/registry/` | schema-v1 index rendering. The wire format lives here and nowhere else |
| `internal/plugin/`, `ownership/` | Domain services. `ownership` answers who may change a listing, checked per request (ADR-0005), and refuses to leave a plugin with no owners |
| `internal/api/webtmpl/` | The account surface's `html/template` pages, embedded. No JavaScript build, no separate deploy target. `template.HTML` appears nowhere |
| `internal/store/` | The only holder of `*sql.DB`: two pools, `store.Tx`, migrations. `sqlitegen/` is generated and never hand-edited; `storetest/` builds real databases for tests |
| `internal/core/` | Typed ids (`PluginID`, `ULID`), `Micros`, and `Secret` |
| `internal/clock/` | The only `time.Now` |
| `db/` | `schema.hcl` is the single schema truth; `queries/*.sql`; `migrations-sqlite/`, embedded and applied at boot; `SHIPPED.lock` |
| `test/repo/` | Tests about the repository itself, not the product: they assert the gates below actually fire |

`internal/identity/` and `internal/artifact/` are **the only packages permitted to make outbound
HTTP requests.** Everything else that needs a remote fact asks one of them.

## The laws

Each has a mechanism. The mechanism is authoritative; this list is a description of it.

1. **HTTP routes are declared only in `internal/api`.** Route-registry architectural test, `ROUTE001`.
2. **`*sql.DB` is held only by `internal/store`.** Import-graph test; `SQL001`.
3. **Outbound HTTP only from `internal/identity/*` and `internal/artifact`,** through the guarded
   client whose dialer denies private, link-local, loopback and cloud-metadata addresses. `NET001`.
   This is wider than the sibling projects' rule by exactly one package, because this service must
   fetch artifacts to hash them; the reason is recorded in `docs/concepts/invariants.md` so the
   widening stays deliberate.
4. **`internal/registry` is the only package that knows the wire format.** No other package may
   marshal a `schema_version`, a `latest` object, or anything else a client parses. `SCHEMA002`
   enforces that; `SCHEMA001` validates the bytes of a real HTTP **response** against the vendored
   schema, so what leaves the server is what is checked — not the renderer's return value on its
   way there.
5. **`time.Now` appears only in `internal/clock`.** `CLOCK001`, an AST analyser, so an aliased
   import does not defeat it.
6. **Every operation declares `Security` and `x-regserve-permission`.** Coverage is derived from the
   route registry, so a new uncovered route is a red test, not a missing one. `PERM001` walks the
   OpenAPI document `api.Spec()` generates from the same registration code the server runs, so an
   operation cannot be in one and not the other; `OAPI001` pins the `OperationID`s, which are SDK
   method names and therefore public API. Register through `register()` in `internal/api/routes.go`
   and pass an `Access` — `Public()`, `Requires()` or `Floor()`. There is no overload that omits it.
   The declaration is stored twice from one value: as extensions, which the document renders, and
   as operation metadata, which `security.go`'s middleware enforces. The spec and the server cannot
   disagree, because there is one value and two readers.

   **And what it declares has to RESOLVE.** `PERM001` also asks `internal/authz` whether the
   permission exists, whether its floor flag agrees, and whether the scopes offered to a token
   actually satisfy it. Declaring was gated and resolving was not, and the gap shipped: the publish
   route named `release.publish`, a permission the catalogue has never held, so `authz.Satisfies`
   missed and every scoped token was answered 403 — publishing, the point of this service, closed,
   with no test red. A permission that fails closed is safe and still broken.

7. **A permission or a scope is a whole quoted literal in `internal/authz/catalogue.go`.**
   `AUTHZ001` reads that file as text. A composed key produces the right runtime value and answers
   no question anybody asks while grepping for it at 2am.

8. **Nothing in `db/queries/*.sql` is non-ASCII.** `QRY001`. This is not style: sqlc slices each
   query out of the file using character positions as byte offsets, so one em dash silently
   scrambles the SQL in the generated bindings, and the result fails at runtime rather than at
   generation.

## Non-negotiable invariants

- **A submitted sha256 is never trusted.** The server downloads the artifact itself and computes the
  hash. The hash is the security boundary — the URL is only transport. A release whose bytes could
  not be fetched is *not* published; it goes to review. Never derive the stored hash from the
  submission.
- **Artifacts are hashed and discarded.** Never extracted, never written to a persistent path,
  never executed, never imported. The 50 MiB cap is enforced *during* the read, not after.
- **Plugin ids are permanent and never recycled.** Delisting removes the listing and keeps the
  claim. An id whose plugin is gone must never become available to someone else — that is how you
  ship an update to somebody else's users.
- **`audit_log` is append-only.** Never `UPDATE` or `DELETE` it, in Go, in SQL, or in a migration.
  Corrections are new rows. A DB trigger raises if you try; a test asserts the trigger fires.
- **Release history is kept even though only `latest` ships.** The wire format carries one release
  per plugin; the database carries all of them. Do not "clean up" superseded rows — they are the
  audit trail for what was approved and by whom.
- **There is no all-powerful token.** Ownership changes, token minting and trust-level changes are
  session-only and carry no scope at all. There is no `admin:*`.
- **A new plugin id always gets human review.** Trust levels govern version bumps of an
  already-approved plugin, never the first appearance of an id.
- **The seed file is imported once, into an empty database, and never again.** A database that
  already holds plugins is never overwritten by a file on disk. That is what let the live
  deployment cross from `--seed` to the store with no maintenance window, and it is why leaving the
  file mounted afterwards is harmless rather than a loaded gun.
- **Only GitHub identities may publish, and GitHub is the only provider.** This is a CHECK against
  `identity_provider.kind`, not an operator toggle. The `(provider, subject)` model still holds any
  number of providers; one ships. See
  [ADR-0011](docs/adr/0011-github-is-the-only-identity-provider.md).

## Go idioms

House Go, not general Go. Inherited from Dragon Kill Party and tod-serve, where each rule has a
mechanism.

- **Errors:** wrap with `%w` *and* context — `fmt.Errorf("rehash artifact %s: %w", releaseID, err)`.
  Context is a lowercase noun phrase, no punctuation. Sentinels live in the owning package. Compare
  with `errors.Is`/`errors.As`, never `==`. Never discard: `_ = f()` is a waiver, not a default, and
  it needs a comment saying why. Never `panic` outside `main` wiring.
- **Context:** `ctx context.Context` is the first parameter of every function that does I/O, with no
  exceptions for ones that "don't need it yet". Never store a `ctx` in a struct field.
  `context.Background()` appears only in `main`, `TestMain` and job-worker roots.
- **The clock is injected, always.** Time-dependent tests use `testing/synctest`; `time.Sleep` is
  grep-banned in tests.
- **Logging:** `slog`, structured. No `fmt.Printf`, no `log.` package. **Never log a token secret, a
  session id, an OAuth access token, a client secret, or the server pepper.** The 8-character public
  token prefix is loggable and is how a leaked token is found; the secret never is.
- **Randomness is `crypto/rand`.** `math/rand` is depguard-banned. Token secrets, OAuth `state` and
  PKCE verifiers have no non-cryptographic variant.
- **Tests:** table-driven, `TestThing_Condition_Expectation`. `t.Parallel()` everywhere. **`require`,
  never `assert`** — `assert` continues after failure and buries the real first failure under a page
  of cascading noise. Whole-value comparisons with `go-cmp` over cherry-picked fields. No mocks of
  the database; integration tests use real SQLite in `t.TempDir()`. Use `t.Context()`.
- **Banned:** naked returns, package-level mutable state, `any` in domain signatures, a second type
  for the same concept, manual formatting (`gofumpt` + `goimports` win every disagreement).

## House style for prose

- **Comments say why, not what.** Name the failure the line prevents. A change that removes a reason
  should replace it with a better one.
- **Say when you don't know.** The failure mode designed against throughout is a *confident mistake*,
  not a miss. An artifact that could not be downloaded reports "not verified" and goes to review; it
  never reports success.
- **Never hide a row silently.** If a filter drops a plugin from the index, count it somewhere
  visible. A listing that vanishes without explanation is indistinguishable from a bug.
- **Write down why not, alongside why.** Every design document names what it rejected.
- 100-column wrap. Tables are fine over it.

## Security posture

This service holds one OAuth client secret, a token pepper, and every publisher's identity. It
also fetches URLs supplied by users, which is an SSRF surface by construction.

- The artifact fetcher re-asserts `https` on **every** redirect hop, caps redirects, caps bytes
  during the read, and dials through a resolver that refuses private, link-local, loopback,
  multicast and cloud-metadata addresses. Removing any one of those is a security change and needs
  to be argued in the PR.
- Treat every field of a publish request as hostile input, including the ones that look structural.
- When you are unsure whether something is a vulnerability, write the test that demonstrates it and
  open an issue. Do not quietly harden and move on — the test is what stops it regressing.

## When you are uncertain

Stop and ask. Do not guess at: the wire format a released client parses, a scope that does not exist
in `internal/authz`, or what should happen to an id whose owner has vanished.

If two instructions conflict, the invariant wins and the conflict is a bug: say so.

## Out-of-scope findings: file an issue

A finding you are *not* uncertain about — real, actionable, and genuinely not this PR's job — does
not stop anything: **file the issue yourself, with `gh issue create`, and carry on.** One issue per
distinct actionable item, using the existing labels. Do not expand the PR to fix it; link it from
the PR body instead. Filing is expected, not noise.

## Do not

- Do not edit generated files (`internal/store/sqlitegen/`, `openapi/openapi.json`,
  `db/migrations-sqlite/`). Change the source and run `make gen`. Gate `GEN001` regenerates in CI
  and fails on any diff, so a hand-edit is caught rather than reviewed for. `openapi/openapi.json`
  is generated from the route registry by the binary itself: `make gen-openapi` needs no toolchain
  beyond Go.
- Do not edit a migration that has shipped in a tagged release. Write a new one.
- Do not edit `internal/registry/testdata/index-v1.schema.json` to make a test pass. It is generated
  upstream; a mismatch means the renderer is wrong, not the schema.
- Do not weaken, skip, delete, or `-update` a test to make CI green. A failing test is information.
- Do not add a dependency. Propose it with the reason and the licence; a human decides.
- Do not disable a lint rule, a hook, or a CI gate to land a change.
- Do not push to `main`, force push, push a tag, cut a release, publish an image, or deploy. Pushing
  a feature branch and opening a PR is the normal way work leaves this machine, and is fine.

**Most of these are now yours to keep.** `.claude/settings.json` used to refuse them outright; its
only remaining `deny` entries are reads of `.env`, keys and database files. Editing a generated file
or `go.mod` asks first — a question, not a wall, and `go get` rewrites `go.mod` without ever reaching
that question. `git push`, `git tag`, `gh release`, `docker push` and `go mod tidy` run unprompted.
Three of the rules above now have mechanisms. `MIG003` hashes shipped migrations against
`db/SHIPPED.lock`; `MIG004` refuses to build a release image for a `v*` tag whose migrations were
never frozen into that file, which is what stopped `MIG003` from reporting `vacant` forever; and
`GEN001` regenerates with the pinned sqlc and Atlas and fails on any diff, so "do not edit a
generated file" is enforced rather than requested. The rest are honour rules, and by this file's
own governing rule that makes them wishes — so they are recorded here as what they are rather than
as gates that no longer exist. If you want one back, add the gate and register it in
[`docs/concepts/invariants.md`](docs/concepts/invariants.md).

## Working on it

```bash
make help      # every target, documented
make status    # what is still stubbed — derived from notyet call sites, never hand-maintained
make check     # what CI runs
make gen       # regenerate the OpenAPI document, the permissions page and the sqlc bindings
make seed OWNERS=./owners.json   # import ownership records; the catalogue is seeded at boot
make gen-authz # the permissions page alone; needs no generator toolchain
make gen-openapi  # the OpenAPI document alone; needs no generator toolchain
```

Commits are signed off (`git commit -s`, DCO). Conventional Commits are enforced on the **PR title
only** — squash-merge makes it the commit subject. WIP commits can say anything.

Docs change in the same PR as the behaviour they describe.
