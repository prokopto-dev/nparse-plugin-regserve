-- The publish path: the reads a release submission needs, and the two writes it makes.
--
-- ASCII only: gate QRY001. sqlc slices queries out of this file by byte offset, so one em dash in
-- a comment scrambles every query after it and the failure arrives at runtime.
--
-- "release" is quoted throughout because RELEASE is a SQLite keyword (RELEASE SAVEPOINT).

-- name: CanAccountPublish :one
-- Whether this account holds an identity from a provider that may publish.
--
-- ADR-0004 and ADR-0011: only GitHub identities may publish, and that is a CHECK against
-- identity_provider.kind rather than a column an operator sets. This query reads the CHECKed
-- column rather than comparing the provider kind in Go, so the answer comes from the same place
-- the constraint does -- a second copy of "which providers may publish" in a Go switch is a copy
-- that can disagree with the database.
SELECT count(*) FROM identity i
JOIN identity_provider p ON p.kind = i.provider_kind
WHERE i.account_id = ? AND p.can_publish = 1;

-- name: GetReleaseByID :one
-- One release row, for rebuilding the answer to a replayed idempotency key.
SELECT
    id, plugin_id, version, state, source,
    artifact_url, artifact_sha256, artifact_bytes,
    sdk_specifier, minimum_app_version,
    submitted_by, submitted_at, verified_at,
    reviewed_by, reviewed_at, review_note, notes
FROM "release"
WHERE id = ?;

-- name: GetIdempotencyKey :one
-- A request this server has already answered. The request_hash comes back so the caller can tell a
-- replay of the SAME request from a key reused for a different one, which is a 409 rather than a
-- replay: answering with the old release's id would tell somebody their new version published
-- when it did not.
SELECT account_id, operation, idempotency_key, request_hash, release_id, created_at
FROM idempotency_key
WHERE account_id = ? AND operation = ? AND idempotency_key = ?;

-- name: InsertIdempotencyKey :exec
-- Written in the same transaction as the release it records. A key row without its release, or a
-- release without its key row, would each make a re-run do the wrong thing exactly once.
INSERT INTO idempotency_key (account_id, operation, idempotency_key, request_hash, release_id, created_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetLatestApprovedRelease :one
-- The release currently on the wire for a plugin, if there is one.
--
-- It is what a version bump is compared against, and the partial unique index
-- release_one_approved_per_plugin is what makes "the approved release" a single row rather than
-- whichever one this query reached first.
SELECT
    id, version, artifact_url, artifact_sha256, artifact_bytes, submitted_at, verified_at
FROM "release"
WHERE plugin_id = ? AND state = 'approved';

-- name: GetReleaseByVersion :one
-- Whether a version has been used for this plugin before, in ANY state.
--
-- A version is used once per plugin, ever -- release_plugin_version_key enforces it over a table
-- nothing deletes from. Reading it first turns "UNIQUE constraint failed" into an answer that
-- names the version and says which state the existing row is in.
SELECT id, version, state, submitted_at FROM "release"
WHERE plugin_id = ? AND version = ?;
