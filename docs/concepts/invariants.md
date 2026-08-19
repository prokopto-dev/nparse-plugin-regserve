# Invariants and their gates

**The governing rule: a rule without a gate is a wish.** Every row below names the mechanism that
enforces it. A rule with no mechanism belongs in the "review rules" section at the bottom, honestly
labelled, not in the table pretending to be enforced.

Gates live in four places, and which one a gate belongs in is decided by what it has to read:

- **`test/repo/arch_test.go`** — anything about Go source. These parse the tree with `go/ast`. A
  grep matches the rule's own name inside the comment explaining the rule, and a grep for
  `time.Now` misses `clk "time"` followed by `clk.Now()`. Both happened here.
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
| `PIN001` | Every GitHub Action is pinned to a 40-character SHA | Grep over `.github/workflows/` |
| `MIG002` | Migrations are forward-only; every `Down` block aborts | Each migration's `Down` block must contain `RAISE(ABORT, …)` |
| `MIG003` | A migration that has shipped is never edited | sha256 of each file compared against `db/SHIPPED.lock` |
| `MIG004` | A tagged release never ships a migration that is not frozen | `scripts/freeze-migrations.sh --check`, run by `lint-repo` on a `v*` commit and by the release workflow before the image builds |
| `GEN001` | Checked-in generated code matches the source it is generated from | `scripts/gen-check.sh` regenerates with the pinned sqlc and Atlas and fails on any diff |

## Wire-format gates

These protect the one contract this project does not own. See
[canonical §1](../design/00-canonical-conventions.md#1-the-wire-format-is-not-ours-to-change).

| Gate | Rule | Mechanism |
|---|---|---|
| `SCHEMA001` | The rendered index validates against the vendored `index-v1.schema.json` | Test in `internal/registry` marshalling real fixtures and validating the output |
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
