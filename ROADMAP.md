# Roadmap

Phases, not dates. Each one ends with something that works and is tested; `make status` derives
what is still stubbed from the Makefile itself, so it cannot drift from this page by being
forgotten.

## Phase 0 — scaffolding ✅

The repository, its rules, and the mechanisms that enforce them.

- Conventions, ten ADRs, the invariants register, the trust-model accounting
- Gates: `PIN001`, `MIG002`, `MIG003`, `ADR000`–`ADR003`, `DOC001`, `DOC002`, `CMD001`, and the AST
  analysers `CLOCK001`, `SQL001`, `NET001`, `ROUTE001`, `SCHEMA002`
- `internal/core`, `internal/clock`, `internal/registry` with `SCHEMA001` and `SIZE001`
- The index endpoints, health and readiness, request ids, the closed error enum
- Container image, release pipeline, approved deploy to the droplet, with the deploy asserting
  `/readyz` and `schema_version: 1` against the live host before it reports success

**What works now:** the deployed server serves the production catalogue, byte-identical, to a real
client. The catalogue reaches it as `/opt/regserve/seed.json` on the droplet, mounted read-only and
loaded at boot — deliberately temporary, and replaced by the store-backed catalogue in Phase 1.

## Phase 1 — persistence

- `db/schema.hcl` as declarative truth; Atlas authors, goose applies at boot
- sqlc bindings into `internal/store/sqlitegen`; the two-pool store with `store.Tx`
- Test template database cloned per test; `goleak` in `TestMain`
- `make gen`, `make migration`, `make migrate` do real work
- The store-backed catalogue replaces `plugin.Static`

## Phase 2 — identity

- `internal/identity/{discord,google,github}` behind the guarded dialer
- OAuth with `state` and PKCE; sessions on `__Host-regserve_session`
- Accounts with linked `(provider, subject)` identities
- `internal/authz` catalogue; PAT mint and verify; the capability floor
- Seeding ownership from the existing `owners.json`, resolving handles to numeric ids

## Phase 3 — publishing

- `internal/artifact`: fetch, re-hash, size cap during read, https per redirect hop, SSRF-denying
  dialer
- `POST /api/v1/plugins/{id}/releases` with `Idempotency-Key`
- Id claims, ownership checks, transfers
- Quarantine rules and the review queue; trust levels
- The gate for **"a stored sha256 was computed by the server"** — currently a review rule, and the
  only row in the invariants register without a mechanism

## Phase 4 — the ecosystem

- A reusable workflow for plugin repositories that publishes on tag
- `prokopto-dev/nparseplus-plugin-template` wired to it
- The client update repointing `DEFAULT_REGISTRY_URL`
- Admin surface for the review queue

## Not scheduled

- **Artifact hosting.** The schema and API leave room; the commitment is storage, egress and
  becoming a distributor ([ADR-0002](docs/adr/0002-index-only-artifacts-stay-on-github.md))
- **Index signing** (minisign/ed25519, public key shipped in the app). Already on the nParse+
  roadmap; it is what would survive a compromise of the registry itself
- **Mirroring the rendered index back to the Pages repo**, so the pinned URL keeps answering and
  existing installs see no provenance-change prompt
