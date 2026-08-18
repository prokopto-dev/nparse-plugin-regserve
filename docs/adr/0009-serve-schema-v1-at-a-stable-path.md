# ADR-0009 — Serve schema v1 at a stable path, outside the versioned API

**Status:** accepted · **Date:** 2026-08-18 · **Deciders:** Courtney Caldwell

## Context and problem statement

Released nParse+ clients parse a document whose shape we do not control: the pydantic models in
`nparseplus.core.plugins.registry`, at `schema_version: 1`. We also want a richer API — release
history, ownership, moderation state — that can evolve at our pace.

Those are different contracts with different rates of change, and putting them on the same path
means the slower one governs the faster one forever.

## Considered options

| Option | For | Against |
|---|---|---|
| A — Only `/api/v1`, with a client update required before anything works | One API to build and document | Nothing can consume the server until an app release ships, so the service is untestable against a real client for as long as that takes |
| B — Serve schema-v1 `index.json` at a stable path outside `/api/v1`, plus the richer API alongside | Today's released client can add the server as an extra registry with no app change, so the wire format is exercised by a real parser from week one | Two documents describing overlapping data, which can disagree |
| C — Content-negotiate on the same path | One URL | The client sends no `Accept` header worth negotiating on, and versioning by header is invisible in the logs and in a bug report |

## Decision outcome

**Chosen: B.** `GET /index.json` and `GET /plugins/{id}/index.json` sit at fixed paths, outside
`/api/v1`, and emit schema v1. The product API lives under `/api/v1` and versions independently.

The reason this is nearly free is that the shipped client is **already multi-registry**: users add
`{url, name, enabled}` entries, enabled registries are fetched concurrently, and each failure is
reported separately. So a running instance is usable by a real, released client immediately — which
means the wire format is validated by the actual parser rather than by our belief about it.

`/plugins/{id}/index.json` exists because `PluginMeta.update_url` declares a per-plugin feed in the
same format, polled for one id. One handler, and an author can self-serve updates without a listing.

`internal/registry` is the **only** package that knows this format (law 4). `SCHEMA001` validates
its output against the vendored schema on every run.

The boundary: `schema_version` stays `1`. Any richer data — history, moderation state, ownership —
goes in `/api/v1` and never leaks into the index document, because a field added there is a field
some future client might come to depend on.

### Consequences

- Good, because the service can be pointed at by a real nParse+ install on day one, which turns the
  riskiest contract in the project into something continuously tested.
- Good, because the product API is free to change shape without anyone auditing whether a desktop
  client from last year still parses it.
- Good, because the migration for the app is a one-line constant change rather than a new client.
- **Bad, because two representations of the same data can disagree**, and the index is the one that
  reaches users, so a bug there is worse and less visible than the same bug in `/api/v1`.
- **Bad, because a stable path outside the versioned API is a permanent commitment.** We cannot move
  or retire `/index.json` without stranding installs, so it is a URL we own forever.
- **Bad, because clients installed from this registry record its URL as provenance**, so an install
  that arrived via the Pages URL will prompt for confirmation on its first update from here. That is
  honest — the source really did change — but it is a support question we will have to answer.

### Reversal cost

Retiring the schema-v1 endpoint requires every client in the field to have updated, which is not a
decision we can make unilaterally at any point in the foreseeable future. Treat it as permanent.
