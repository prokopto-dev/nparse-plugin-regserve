# Invariants and their gates

**The governing rule: a rule without a gate is a wish.** Every row below names the mechanism that
enforces it. A rule with no mechanism belongs in the "review rules" section at the bottom, honestly
labelled, not in the table pretending to be enforced.

Gates live in four places, and which one a gate belongs in is decided by what it has to read:

- **`test/repo/`** — anything about Go source or about what the Go code declares. `arch_test.go`
  parses the tree with `go/ast`, because a grep matches the rule's own name inside the comment
  explaining the rule, and a grep for `time.Now` misses `clk "time"` followed by `clk.Now()`. Both
  happened here. `openapi_test.go` reads the generated OpenAPI document instead, because the rule
  it enforces is about what an operation *declares*, not about how the file is written.
- **`scripts/repo-gates.sh`** — files Go cannot parse: workflow YAML, migration SQL.
- **`scripts/docs-check.sh`** — documentation shape.
- **`scripts/gen-check.sh`** — the generators themselves. Separate because it is the only gate
  needing a toolchain (`make tools`), and `make check` must stay runnable without one. CI runs it
  as its own job; a gate that skips when its tools are missing would report success for a
  regeneration that never happened.

`make check` runs all three. Each also asserts it is not **vacant**: a gate that inspected nothing
fails rather than reporting a green tick it has not earned.

A gate with nothing to check reports **`vacant`** in yellow, never a green tick it has not earned.
A green run that checked nothing is worse than a red one, because it teaches people to trust it.

## Architectural gates

| Gate | Rule | Mechanism |
|---|---|---|
| `ROUTE001` | HTTP routes are declared only in `internal/api` | AST analyser: registrar calls outside that tree |
| `SQL001` | `*sql.DB` is held only by `internal/store` | AST analyser: `database/sql` in a file's import set |
| `NET001` | Outbound HTTP only from `internal/identity/*`, `internal/artifact`, and `cmd/regserve/healthcheck.go` | AST analyser: `http.Get`/`Post`/`Head`/`PostForm`, `http.Client` literals and `net.Dial*` outside those trees |
| `CLOCK001` | `time.Now` appears only in `internal/clock` | AST analyser, resolving the import alias, so `clk "time"` does not defeat it |
| `AUTHZ001` | Every permission and scope in the catalogue is written as a whole quoted literal | Test in `test/repo` reading `internal/authz/catalogue.go` as TEXT and requiring the exact quoted string. It looks for the QUOTED form, so the prose naming a key — including the comment explaining the rule — is not a match. `TestAUTHZ001_FiresOnAComposedKey` runs the same judgement over four shapes that must all be rejected |
| `QRY001` | Nothing in `db/queries/*.sql` is non-ASCII | Test in `test/repo` over the query files. **Not a style rule:** sqlc v1.31.1 slices each query out of the file using the parser's character positions as byte offsets, so one multi-byte character shifts every query after it. The generated Go compiles and the SQL inside it does not parse — observed here as `SQL logic error: near "C": syntax error` from a query nobody edited, caused by an em dash in a comment. Every other prose file in this repository uses em dashes freely, which is why this is a gate and not a note |
| `PIN001` | Every GitHub Action is pinned to a 40-character SHA | Grep over `.github/workflows/` |
| `MIG002` | Migrations are forward-only; every `Down` block aborts | Each migration's `Down` block must contain `RAISE(ABORT, …)` |
| `MIG003` | A migration that has shipped is never edited | sha256 of each file compared against `db/SHIPPED.lock`, by `lint-repo` in normal CI and by `scripts/freeze-migrations.sh --check` in the release workflow — CI does not run on tags, so the release gate is the only check a `v*` push gets |
| `MIG004` | A tagged release never ships a migration that is not frozen | `scripts/freeze-migrations.sh --check` validates every existing lock entry, then fails on any migration the lock does not name. Run by `lint-repo` on a `v*` commit and by the release workflow before the image builds |
| `GEN001` | Checked-in generated code matches the source it is generated from — the sqlc bindings, `db/schema.hcl` against the migrations, `openapi/openapi.json` against the route registry, and `docs/reference/permissions.md` against the authz catalogue | `scripts/gen-check.sh` regenerates and fails on any diff. The generators themselves are pinned: sqlc through the Go checksum database, Atlas by sha256 in `scripts/atlas.sums`, verified before it is made executable — a required gate is only as trustworthy as the binary that answers it |

## Wire-format gates

These protect the one contract this project does not own. See
[canonical §1](../design/00-canonical-conventions.md#1-the-wire-format-is-not-ours-to-change).

| Gate | Rule | Mechanism |
|---|---|---|
| `SCHEMA001` | The index document a client **receives** validates against the vendored `index-v1.schema.json` | Test in `internal/api` that runs a real `httptest` server, makes a real request, and validates the response bytes — plus the exact-bytes, content-negotiation and pinned-path assertions below |
| `SCHEMA002` | Only `internal/registry` knows the wire format | AST analyser: those field names in a string literal or struct tag outside that package |
| `SIZE001` | The rendered index stays under the client's 5 MiB cap | Test that renders a synthetic catalogue and fails as the size approaches the limit |


The vendored schema is generated upstream by `tools/gen_registry_schema.py` in `nparse-plus`, from
the pydantic models the client actually parses with. **Editing it here to make a test pass inverts
the point of the gate** — a mismatch means the renderer is wrong.

### The two NET001 exceptions, and why each is narrow

`internal/artifact` is allowed because publishing *requires* fetching the artifact to hash it
([ADR-0008](../adr/0008-server-rehashes-every-artifact.md)). That is one package wider than the
sibling projects' rule, and the widening is written down here rather than absorbed silently.

`cmd/regserve/healthcheck.go` is allowed **by exact filename**, not by directory. The container
image is `FROM scratch` and has no curl, so the `HEALTHCHECK` is the binary probing itself. It dials
a fixed loopback address that no request can influence — the opposite of the SSRF this gate exists
to prevent. Allowing it by filename rather than by tree means a second outbound call cannot hide
behind the exception.

## Route-registry gates

Law 6 says coverage of the permission declaration is *derived from the route registry*. These are
what derives it: `api.Spec()` runs the same registration code the server runs, so an operation
appears in the generated OpenAPI document the moment it is registered — declared or not.

| Gate | Rule | Mechanism |
|---|---|---|
| `PERM001` | Every operation declares who may call it, its security matches that declaration, and the middleware enforces the same value | Test in `test/repo` walking `api.Spec()`: exactly one of `x-regserve-permission` / `x-regserve-public`, a `security` key that is present (empty for public, non-empty otherwise), permissions and scopes spelled per canonical §12, every scheme defined in `components.securitySchemes`, and a capability-floor operation accepting no PAT. A second AST half asserts nothing in `internal/api` calls Huma's registrars except `register()` in `routes.go`, whose signature demands an `Access`. `TestPERM001_FiresOnADeliberatelyBrokenOperation` runs the same judgement over nine shapes that must all be rejected. `register()` stores the same `Access` as operation metadata, which the middleware in `internal/api/security.go` reads back — so the document and the enforcement are one value with two readers rather than two lists to keep in step |
| `OAPI001` | Every `OperationID` is a unique lowerCamelCase name, and the two pinned index paths are in the document | Test in `test/repo` over `api.Spec()`. An `OperationID` is the generated SDK's method name, so renaming one breaks callers in their language rather than ours; the path half asserts ADR-0009's permanent URLs against the document rather than against the constants that are supposed to produce them |

## Documentation gates

| Gate | Rule |
|---|---|
| `ADR000` | There is at least one ADR |
| `ADR001` | No ADR exceeds 1000 words |
| `ADR002` | Every ADR contains `- **Bad, because` and `### Reversal cost` |
| `ADR003` | Every ADR contains `## Considered options` |
| `DOC001` | Every error code in the closed enum has a documentation page |
| `DOC002` | Every gate defined in `scripts/repo-gates.sh` is recorded in this file |
| `CMD001` | Every `make <target>` named in the docs resolves to a real Makefile target |

## Data invariants

Enforced in the schema and by tests, not by convention. Every row below is exercised by
`TestSchema_RefusedStatements` in `internal/store`, which issues the forbidden statement as **raw
SQL** — not through the generated query set. A guarantee that only holds for the statements this
repository happens to generate is not a guarantee: a migration, a later phase, or a hand-run
`UPDATE` during an incident does not go through sqlc.

| Invariant | Mechanism |
|---|---|
| `audit_log` is append-only | `BEFORE UPDATE` and `BEFORE DELETE` triggers that `RAISE(ABORT)`; a test asserts each trigger fires, and another asserts `INSERT` still works |
| A plugin id is never recycled | The `plugin` row **is** the claim, and a `BEFORE DELETE` trigger aborts. Delisting sets `delisted_at`, which clears the listing and keeps the claim |
| A delisting states its reason | `CHECK`: `delisted_at` and `delisted_reason` are set together or not at all. A listing that vanishes with no reason is indistinguishable from a bug |
| Only `github` identities may publish | `identity_provider.can_publish` is a `CHECK` against `kind`, not a column an operator sets. `github` is also the *only* provider ([ADR-0011](../adr/0011-github-is-the-only-identity-provider.md)); the `CHECK` stays because a provider added later is non-publishing until someone argues otherwise |
| A stored sha256 was computed by the server | `internal/artifact` returns the hash it computed. **Not yet built** — the enforcing test lands with the publish path in Phase 3. Two parts of it exist now: `release.source` records `import` for the rows carried over from the static registry, whose hashes this server did **not** compute, and a `CHECK` refuses an approved release with no hash at all |
| A stored sha256 is 64 lowercase hex characters | `CHECK` with a negated `GLOB`. A hash the client would refuse cannot be stored, so it cannot be served |
| An artifact URL is `https` | `CHECK`: `artifact_url LIKE 'https://%'`. The URL is transport, but a row that could never be served has no business existing |
| Every release row keeps its history | A `BEFORE DELETE` trigger on `release` aborts; superseding is a state change |
| Exactly one release per plugin is live | Partial unique index on `(plugin_id) WHERE state = 'approved'`. `latest` on the wire is derived from that row, and ADR-0010 names the derivation as the risk it accepts — the index makes the ambiguous case unrepresentable rather than unlikely |
| A version is never reused for a plugin | Unique index on `(plugin_id, version)`, over a table nothing deletes from |
| A credential secret is never stored | `session.token_hash`, `oauth_flow.state_hash` and `pat.token_hash` hold `HMAC-SHA256(pepper, secret)`, with a `CHECK` requiring 64 lowercase hex characters. The pepper is in the environment and the rows are on a disk, so a stolen database is not a stolen session. Tested by reading the column back and by resolving a cookie under a second pepper |
| A login flow is single use | The `oauth_flow` row is deleted in the same transaction it is read, and the rejection is carried out of that transaction rather than returned from it — returning it would roll the delete back, leaving an expired flow to be probed. Tested both ways |
| A login is bound to the browser that started it | `state` is required in the URL **and** in the `__Host-regserve_oauth` cookie, compared in constant time. Without the cookie the state is a nonce anybody can supply, which is login CSRF. Tested |
| A post-login redirect is same-site | `CHECK` on `oauth_flow.redirect_to`: one leading slash, and the second character is neither another slash nor a backslash. `auth.SafeRedirect` says the same thing at the edge and also refuses control characters, which are header injection |
| There is no scope that reaches the capability floor | Asserted three ways: `authz.Satisfies` returns false for a floor permission holding *every* scope in the catalogue; `PERM001` fails an operation that is floor and accepts a PAT; and `TestCapabilityFloor_ARealTokenWithEveryScope_IsStillRefused` mints a real token carrying every scope and watches a real server refuse it over HTTP — then signs in with a session and watches the same route succeed, because a middleware that refused everything would pass the first half |
| A token's scopes are the catalogue's | `CHECK` on `pat_scope.scope`, **generated** from `internal/authz` by `make gen-authz` between `GENERATED` markers, with `GEN001` failing on drift and a test minting a token carrying every catalogue scope to prove the generated list is what the database enforces |
| A token cannot be revoked by somebody who does not hold it | The account is in the `UPDATE`'s `WHERE`, not only in a Go check above it. The id comes from a URL; zero rows affected is reported as `ErrNoSuchToken`, the same answer as "already revoked", so it is not an oracle for other people's token ids |
| A token pinned to a plugin cannot act on another | `auth.Principal` carries the pin, and `internal/api`'s middleware compares it against the path parameter the route DECLARES with `Access.OnPlugin` — before any handler runs, because a check a handler performs is a check the next handler forgets, and an unenforced pin fails open silently. A pinned token calling an operation that declares no plugin parameter is refused: "cannot check" must not resolve to "allow". `PERM001` fails a token-callable operation under `/plugins/{…}` that declares no parameter, so the Phase 3 publish route cannot be written without one |
| Every mutating form carries a CSRF token bound to its session | `auth.Sessions.CSRFToken` derives it from the session id under the pepper with a domain-separating prefix, and `CheckCSRF` compares in constant time. Checked on EVERY mutating form, before anything is read from the body. The session cookie's `SameSite=Lax` is the first defence and is a browser behaviour this repository neither controls nor can test; this is the half that is ours. Tested across all four forms against no token, a wrong token, and a token from another session |
| A token secret is shown once and exists in one response | The mint form answers with the page rather than a redirect. A redirect would have to carry the secret in a URL — refused by this service's own middleware — or in a cookie, or in a server-side flash, which would mean storing it. The cost, stated: a browser refresh mints a second token, which is visible and revocable on the page it lands on |
| The account surface refuses a personal access token | Every authenticated page is `Floor(...)`, so the middleware refuses a token whatever it carries. A browser surface is not a token surface, and each of these pages exists to perform an operation the floor already covers. Tested |
| A page renders only messages this repository wrote | Redirects carry a message CODE, looked up in a fixed table. Prose in a query string is prose an attacker chose: escaped, rendered inside our page, under our domain, and saying what they wrote |
| Only an `owner` may change who holds a plugin | `requireOwnerRoleTx` demands `role = 'owner'` inside the same transaction as the change, for both `Add` and `Remove`. Checking only that a `plugin_owner` row EXISTS admitted a `maintainer`, who could add an account they controlled and then remove the owner — a full takeover through the door marked "may publish", and irreversible, because plugin ids are permanent. A maintainer may still READ the owner list: a co-maintainer publishing to a plugin needs to know who else holds it. The page and the refusal read one fact through `Role.CanManageOwners`, so a control is never offered that the service will refuse |
| A plugin is never left with no owners | `ownership.Remove` counts the owners inside the same transaction and refuses the last one. Ids are never recycled, so an ownerless plugin is not one somebody else can take over — it is a listing nobody can update or delist, and the only repair is a maintainer writing SQL against production |
| Ownership is granted only to an account that has signed in | `ownership.Add` resolves a GitHub handle against `identity`, case-insensitively, and refuses a handle nobody has authenticated with. A grant to a name nobody has proved they hold is a grant to whoever registers it next |
| A bearer token never falls back to a session cookie | `auth.Authenticator` resolves the token when one is presented and does not try the cookie. A fallback would authenticate a caller as the account with the account's authority — an escalation performed by an error path. Tested |
| Reads cannot write | The reader pool is opened `PRAGMA query_only`, so a write reaching the read path fails instead of becoming a second writer. Tested |
| The database file is `0600` | `internal/store` creates it at that mode and tightens an existing looser one, logging when it does. Tested |
| Migrations are forward-only | Every `Down` block is `RAISE(ABORT, …)`; gate `MIG002`. `TestMigrate_DownBlock_CannotRun` goes further and executes each block against a real database, because `MIG002` is a shape check and would pass a file whose abort sat behind a `DROP TABLE` |
| A schema newer than the binary is fatal | `store.ErrSchemaAhead` at boot. An older binary against a newer database is a rollback that skipped the snapshot restore, and serving anyway fails one request at a time |

## Review rules — real rules, no mechanism yet

Listed here deliberately. Do not move a row up to a table above without adding the gate.

- **Errors wrap with `%w` and a lowercase noun-phrase context.** `wrapcheck` is off (too many false
  positives at this size), so this is a review rule.
- **No package-level mutable state.** `gochecknoglobals` cannot distinguish a mutable registry from a
  const-like var, so this is a review rule.
- **Comments say why, not what.** Unmechanisable by construction.
- **Quarantine thresholds are tuned by judgement.** The rules are tested; the *numbers* are a
  judgement call reviewed when they produce a false positive.

## Adding a gate

1. Write the check in `scripts/repo-gates.sh` with a named id, and make it report `vacant` when it
   has nothing to inspect.
2. Add a test in `test/repo/` that asserts the gate fires on a deliberately broken input. A gate
   nobody has seen fail is a gate nobody knows works.
3. Add the row here.
4. If it is a rule an agent will meet while writing code, add it to `AGENTS.md` too.
