# ADR-0001 — One Go binary with embedded SQLite

**Status:** accepted · **Date:** 2026-08-18 · **Deciders:** Courtney Caldwell

## Context and problem statement

The registry is a low-traffic catalogue: a handful of plugins, a publish every few days, and reads
dominated by desktop clients polling an index that changes rarely. It has to be cheap to run on a
VPS, cheap for one person to operate, and it must not lose the ownership records that are the only
thing standing between a plugin's users and someone else shipping them an update.

The sibling projects (`dragonkillparty`, `tod-serve`) already answered this question. Diverging
without cause costs the reviewer who moves between them.

## Considered options

| Option | For | Against |
|---|---|---|
| A — Go binary + SQLite, matching the sibling projects | One artifact to deploy, no database server to run or patch, and the operational knowledge transfers directly between three repos | A single writer, and horizontal scaling needs a rethink rather than a config change |
| B — Go binary + Postgres | Scales out, familiar to any host, managed options everywhere | A second component to run, back up and secure for a workload that will not exceed one machine for years. Backups become an operational project rather than copying a file |
| C — A serverless function plus a hosted database | Nothing to operate | Publishing needs to download and hash a 50 MiB artifact, which is the wrong shape for a short-lived function, and the ownership data ends up somewhere with a vendor's export story |

## Decision outcome

**Chosen: A.** The read path is a cached document; the write path is a few rows and one artifact
fetch. Neither needs a database server, and the deployment story that results — copy a binary,
mount a volume — is one person's evening rather than a platform.

`modernc.org/sqlite` with `CGO_ENABLED=0`, so the image is `FROM scratch` and cross-compilation is
a build flag rather than a toolchain. `internal/store` holds the only `*sql.DB` (gate `SQL001`) and
runs two pools: a **single-connection** writer with `_txlock=immediate`, and a reader sized to
`max(4, NumCPU)` so WAL readers never block the writer. The database file is chmod `0600` — it
holds PAT hashes, OAuth subjects and session records, and is the entire credential corpus.

### Consequences

- Good, because a backup is `sqlite3 .backup` or copying one file, which means backups will actually
  happen.
- Good, because the operational knowledge is shared with two sibling projects, so a reviewer moving
  between them carries the right instincts.
- Good, because with no cgo the release is a static binary for every platform from one builder.
- **Bad, because there is exactly one writer.** A publish storm serialises. At the expected rate this
  is invisible, and if it ever is not, the fix is a queue, not a database migration.
- **Bad, because scaling out is a redesign, not a config change.** Two instances cannot share a
  SQLite file over a network filesystem, so "run a second one" is not available if traffic surprises
  us.
- **Bad, because the whole service is one machine's uptime.** A VPS reboot is downtime, and the
  clients' failure mode during it is "could not reach the registry" in the plugin browser.

### Reversal cost

A week. `internal/store` is the only package holding `*sql.DB`, and `db/schema.hcl` is dialect-aware,
so the port is a second migration set plus a second sqlc target — Dragon Kill Party already carries
`migrations-postgres/` as proof the shape works. The data itself is small enough to move in one pass.
