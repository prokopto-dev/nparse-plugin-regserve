# nparse-plugin-regserve

The live plugin registry for [nParse+](https://github.com/prokopto-dev/nparse-plus). One Go binary,
SQLite, API-first. Pre-1.0.

**Status: early.** The index endpoints work end to end, are byte-compatible with the catalogue in
production today, and are served from SQLite. Authentication, publishing and moderation are
designed, specified, and not yet built — see [`ROADMAP.md`](ROADMAP.md).

## The problem

nParse+ plugins are listed in a static `index.json`, published from GitHub Pages and edited by pull
request. An author who tags `v0.6.0` has to fork a second repository and paste JSON into it, then
wait for a maintainer. Nothing can be driven from a plugin's own release pipeline.

That arrangement has real safety properties, and they are not accidents: the sha256 in the index
pins the exact bytes a human reviewed, so **changing what users receive requires another review**.
Any replacement has to keep that property or say plainly what it traded it for.

## What this does

A server, so publishing is a pipeline step:

- A plugin's release workflow `POST`s its new release with a scoped token.
- The server **downloads the artifact and hashes it itself** — a submitted hash is never stored.
- A brand-new plugin id always waits for human review. After that, version bumps from a trusted
  owner publish automatically, unless a quarantine rule fires.
- Ownership is a database row: first-come, permanent, and never recycled.

What it deliberately does **not** do is host artifacts. Those stay on GitHub Releases; the registry
stores the URL and the hash it computed. The URL is transport, the hash is the security boundary.

## Why not just keep the static file

Because the bottleneck is a person, and the thing being asked of them for a patch release —
"confirm this JSON matches that release" — is exactly the thing a machine does better. What a
person is genuinely needed for is the first time a plugin appears, and that is what
[ADR-0007](docs/adr/0007-review-new-ids-trust-gates-updates.md) keeps them for.

The full accounting of what was kept, replaced and given up is in
[`docs/concepts/trust-model.md`](docs/concepts/trust-model.md).

## Quickstart

```bash
make build

# Serve the catalogue currently in production, locally.
curl -fsS https://prokopto-dev.github.io/nparseplus-plugins/index.json -o /tmp/seed.json
./bin/regserve serve --addr 127.0.0.1:8080 --db /tmp/regserve.db --seed /tmp/seed.json

curl -fsS http://127.0.0.1:8080/index.json
curl -fsS http://127.0.0.1:8080/plugins/merchant-mode/index.json
curl -fsS http://127.0.0.1:8080/readyz
```

The catalogue lives in the database. `--seed` is imported **once**, into an empty database, and is
then ignored forever — a database that already holds plugins is never overwritten by a file, which
is what lets the running deployment cross over without a maintenance window. Delete
`/tmp/regserve.db` to import a fresh seed.

Both flags fall back to environment variables — `REGSERVE_DB_PATH` and `REGSERVE_SEED_PATH` — and
the flag wins when both are set. Started without a database, the server still comes up: `/healthz`
is `ok`, `/readyz` explains that there is no database, and the index endpoints are not registered.
`regserve migrate --db <path>` applies migrations without serving.

The document it serves is schema v1, the format a released nParse+ client already parses. Since the
client is multi-registry, a running instance can be added under *Settings → Plugins* as an extra
registry with no app change at all.

## Endpoints

| Path | Purpose |
|---|---|
| `GET /index.json` | The catalogue, schema v1. What a client reads |
| `GET /plugins/{id}/index.json` | One plugin, same format — the shape `PluginMeta.update_url` expects |
| `GET /healthz` | Liveness. Touches nothing |
| `GET /readyz` | Readiness, and it says *why* when it is not: the database answers and the catalogue still renders |

The index endpoints sit outside `/api/v1` on purpose: their shape is pinned by a parser we do not
own, so they must not move when the product API versions
([ADR-0009](docs/adr/0009-serve-schema-v1-at-a-stable-path.md)).

## Documentation

- [`AGENTS.md`](AGENTS.md) — how to work in this repository. Normative
- [`docs/design/00-canonical-conventions.md`](docs/design/00-canonical-conventions.md) — the tie-breaker
- [`docs/adr/`](docs/adr/) — why things are the way they are, including the downsides
- [`docs/concepts/invariants.md`](docs/concepts/invariants.md) — every rule and the gate enforcing it
- [`docs/concepts/trust-model.md`](docs/concepts/trust-model.md) — what replaced the PR-gated registry
- [`docs/api/errors.md`](docs/api/errors.md) — the closed error-code enum
- [`docs/operations/deployment.md`](docs/operations/deployment.md) — the DigitalOcean + Traefik runbook

## Working on it

```bash
make help      # every target, documented
make status    # what is still stubbed
make check     # everything CI runs
```

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Commits are signed off (`git commit -s`, DCO).

## Licence

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE). Documentation is CC BY 4.0.

Not affiliated with Daybreak Game Company, Darkpaw Games, or Project 1999.
