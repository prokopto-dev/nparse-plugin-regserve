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

## Phase 1 — persistence ✅

- `db/schema.hcl` as declarative truth; Atlas authors, goose applies at boot
- sqlc bindings into `internal/store/sqlitegen`; the two-pool store with `store.Tx`
- Test template database cloned per test; `goleak` in `TestMain`
- `make gen`, `make migration`, `make migrate` do real work
- The store-backed catalogue replaces `plugin.Static`
- **Not in the original plan, and required by it:** the seed importer. Phase 1 removes the file the
  live catalogue is served from and Phase 2 owned the importer, so nothing would have put the
  catalogue into the new database. `--seed` is now imported **once**, into an empty database, and
  ignored thereafter — a non-empty database is never overwritten by a file, which makes the
  transition zero-touch and the rollback a snapshot restore rather than a data-entry exercise.

**What works now:** the full schema exists — `account`, `identity`, `identity_provider`, `plugin`,
`release`, `plugin_owner`, `account_trust`, `audit_log` — with the append-only and no-delete
triggers, and tests that make each of them fire. Only `plugin` and `release` have code; the rest is
structure for Phases 2–3. `/readyz` reports the database. The deployed server serves the same
catalogue it served before, out of SQLite.

## Phase 2 — identity

- ✅ `internal/identity/github` behind the guarded dialer — the only provider
  ([ADR-0011](docs/adr/0011-github-is-the-only-identity-provider.md))
- ✅ OAuth with `state` and PKCE; sessions on `__Host-regserve_session`
- ✅ Accounts with linked `(provider, subject)` identities
- ✅ `internal/authz` catalogue, generating `docs/reference/permissions.md`; the capability floor
  declared and enforced from the same value the OpenAPI document renders
- ✅ PAT mint and verify, with the scope `CHECK` generated from the catalogue
- ✅ A server-rendered account surface, because the capability floor is session-only and therefore
  browser-required: without pages, nothing can reach it
- ✅ Release notes as an additive wire-format field, with its own ADR
  ([ADR-0013](docs/adr/0013-release-notes-are-plain-text-with-a-hard-cap.md)). The column and the
  cap land now; populating them is Phase 3 and rendering them is Phase 4
- ✅ Seeding ownership from the existing `owners.json`, resolving handles to numeric ids
  (`make seed OWNERS=...`; the catalogue itself is already imported at boot)

**What works now:** a GitHub account can sign in and hold a session, and personal access tokens
mint, authenticate and revoke — with a real token carrying every scope in the catalogue still
refused at the capability floor, proven over HTTP rather than argued. Every operation's access
declaration is enforced by middleware reading the same value the document renders. Sign-in is off
in the live deployment until an OAuth application is configured — the routes are not registered at
all rather than registered and failing.

An account can now sign in, see its plugins, mint a token — shown once, in one response, never in a
URL — revoke one, and add or remove a plugin's owners, all from pages served by the same binary.
Every mutating form carries a session-bound CSRF token, and every authenticated page refuses a
personal access token outright.

## Phase 3 — publishing

- `internal/artifact`: fetch, re-hash, size cap during read, https per redirect hop, SSRF-denying
  dialer — through the client already built in `internal/identity/guard`
- `POST /api/v1/plugins/{id}/releases` with `Idempotency-Key`
- Id claims, ownership checks, transfers
- Quarantine rules and the review queue; trust levels
- Populating `release.notes`, and surfacing it as `release_notes` on `latest`
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
