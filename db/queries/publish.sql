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

-- name: InsertPublishRelease :exec
-- The publish path's insert. Narrower than InsertRelease, which the seed importer uses: a
-- published release always has a submitter, never has a reviewer yet, and always carries
-- source = 'publish'. Columns a publish cannot set are absent rather than passed as NULL, so a
-- caller cannot set them by accident.
--
-- artifact_sha256 and verified_at are written TOGETHER or not at all. That pairing is what the
-- release_a_stored_hash_was_verified_or_imported CHECK reads: a hash with no record of when this
-- server computed it is a hash that came from somewhere else.
INSERT INTO "release" (
    id, plugin_id, version, state, source,
    artifact_url, artifact_sha256, artifact_bytes,
    sdk_specifier, minimum_app_version, notes,
    submitted_by, submitted_at, verified_at, review_note
) VALUES (?, ?, ?, ?, 'publish', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: GetAccountTrust :one
-- An account's trust tier. NO ROW MEANS 'new', which is the floor and the default: an account that
-- has never been assessed is one nothing should be automated for, and inventing a row at first
-- sign-in would make "never assessed" and "assessed and found ordinary" the same state.
SELECT account_id, level, set_at, set_by, note FROM account_trust WHERE account_id = ?;

-- name: SetAccountTrust :exec
-- Raise or lower an account's tier. An upsert, because a tier is a property of the account rather
-- than a history: the history is in audit_log, which is append-only and cannot be edited, and that
-- is the copy an incident review reads.
INSERT INTO account_trust (account_id, level, set_at, set_by, note)
VALUES (?, ?, ?, ?, ?)
ON CONFLICT (account_id) DO UPDATE SET
    level = excluded.level,
    set_at = excluded.set_at,
    set_by = excluded.set_by,
    note = excluded.note;

-- name: GetAccountHandle :one
-- The GitHub handle behind an account id, for a reviewer who is looking at a queue full of ULIDs.
-- Decoration, refreshed at each login, and never what anything matches on.
SELECT CAST(coalesce((
    SELECT i.handle FROM identity i
    WHERE i.account_id = a.id AND i.provider_kind = 'github'
    ORDER BY i.linked_at, i.id LIMIT 1
), '') AS TEXT) AS handle
FROM account a WHERE a.id = ?;
