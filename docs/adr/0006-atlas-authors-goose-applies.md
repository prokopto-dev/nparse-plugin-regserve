# ADR-0006 — Atlas authors migrations, goose applies them

**Status:** accepted · **Date:** 2026-08-18 · **Deciders:** Courtney Caldwell

## Context and problem statement

The schema needs a single source of truth that a human reads and a machine diffs, and migrations
need to be applied by the shipped binary with nothing else installed — the deployment target is a
container on a VPS with no migration CLI on its PATH.

Those are two different jobs and the tools best at each are not the same tool.

## Considered options

| Option | For | Against |
|---|---|---|
| A — Hand-written migrations, no declarative schema | No tooling to install; total control | The current shape of the database exists only as the sum of N files. Reviewing "what does this table look like now" means replaying history in your head |
| B — Atlas authors from `db/schema.hcl`, goose applies at runtime | `schema.hcl` is the reviewable truth; Atlas computes the diff; goose is a library the binary embeds, so nothing is needed at runtime | Two tools to learn, and Atlas is a build-time dependency contributors must install |
| C — An ORM with automigrate | Nothing to author | Automigrate against the only copy of the ownership records is not a thing to do, and the ORM would own the schema instead of us |

## Decision outcome

**Chosen: B**, matching Dragon Kill Party and tod-serve. `db/schema.hcl` is the single declarative
truth. Atlas diffs it and writes a numbered migration into `db/migrations-sqlite/`. goose, embedded
via `go:embed` in `db/embed.go`, applies them at boot. sqlc generates typed Go from `db/queries/*.sql`
into `internal/store/sqlitegen/`, which is never hand-edited.

Migrations are **forward-only**: every `Down` block contains `RAISE(ABORT, …)` naming the backup
path, because a down migration is code that runs exactly once, in an emergency, on data that cannot
be reproduced, written months earlier by someone who never tested it. Recovery is restoring the
snapshot taken immediately before the migration ran.

A migration that has shipped in a tagged release is never edited; `db/SHIPPED.lock` freezes them by
sha256 and gate `MIG003` fails the build if one changes. `make freeze-migrations` is what writes
that file, and gate `MIG004` refuses to build a release image for a `v*` tag whose migrations are
not in it — without that, the lock stays empty and `MIG003` compares nothing forever.

### Consequences

- Good, because "what does the schema look like" is one file, and a schema review is a diff of it.
- Good, because the shipped binary migrates itself with nothing installed alongside it, which is the
  whole deployment story.
- Good, because generated query code cannot drift from the schema without CI noticing.
- **Bad, because contributors must install Atlas** to change the schema, and a contributor who
  hand-writes a migration instead produces a `schema.hcl` that lies about the database.
- **Bad, because generated code is checked in**, so a stale `make gen` is a drift class CI has to
  catch rather than a thing that cannot happen.
- **Bad, because forward-only means a bad migration is fixed forward under time pressure**, with
  snapshot-and-restore as the only undo — and the snapshot is only as good as the last backup.

### Reversal cost

A day to hand-write the accumulated migrations and delete `schema.hcl`; the migrations already
applied in the field are unaffected either way.
