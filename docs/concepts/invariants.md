# Invariants and their gates

**The governing rule: a rule without a gate is a wish.** Every row below names the mechanism that
enforces it. A rule with no mechanism belongs in the "review rules" section at the bottom, honestly
labelled, not in the table pretending to be enforced.

Gates live in three places, and which one a gate belongs in is decided by what it has to read:

- **`test/repo/arch_test.go`** — anything about Go source. These parse the tree with `go/ast`. A
  grep matches the rule's own name inside the comment explaining the rule, and a grep for
  `time.Now` misses `clk "time"` followed by `clk.Now()`. Both happened here.
- **`scripts/repo-gates.sh`** — files Go cannot parse: workflow YAML, migration SQL.
- **`scripts/docs-check.sh`** — documentation shape.

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

Enforced in the schema and by tests, not by convention.

| Invariant | Mechanism |
|---|---|
| `audit_log` is append-only | `BEFORE UPDATE` and `BEFORE DELETE` triggers that `RAISE(ABORT)`; a test asserts each trigger fires |
| A plugin id is never recycled | `id_claim` rows are never deleted; delisting clears the listing, not the claim. Unique index plus a test |
| Only `github` identities may publish | `identity_provider.can_publish` is a `CHECK` against `kind`, not a column an operator sets. `github` is also the *only* provider ([ADR-0011](../adr/0011-github-is-the-only-identity-provider.md)); the `CHECK` stays because a provider added later is non-publishing until someone argues otherwise |
| A stored sha256 was computed by the server | `internal/artifact` returns the hash it computed. **Not yet built** — the enforcing test lands with the publish path in Phase 3, and until then this is a review rule wearing a table row's clothes |
| Every release row keeps its history | No `DELETE` on `release` anywhere; superseding is a state change |
| Migrations are forward-only | Every `Down` block is `RAISE(ABORT, …)`; gate `MIG002` |

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
