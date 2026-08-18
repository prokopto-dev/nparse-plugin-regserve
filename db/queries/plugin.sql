-- Queries over the catalogue: the plugin rows, their single approved release, and the two writes
-- the boot-time seed import needs.
--
-- "release" is quoted throughout because RELEASE is a SQLite keyword (RELEASE SAVEPOINT). SQLite
-- accepts it bare in most positions; a position where it does not would fail at boot rather than
-- here, which is the wrong place to find out.

-- name: CountPlugins :one
-- Whether this database has a catalogue at all. The boot-time seed import reads exactly this, and
-- a non-zero answer means the import must not run: an existing catalogue is never overwritten by a
-- file on disk.
SELECT count(*) FROM plugin;

-- name: ListListings :many
SELECT
    p.id,
    p.name,
    p.description,
    p.author,
    p.homepage,
    r.version,
    r.artifact_url,
    r.artifact_sha256,
    r.sdk_specifier,
    r.minimum_app_version
FROM plugin p
JOIN "release" r ON r.plugin_id = p.id AND r.state = 'approved'
WHERE p.delisted_at IS NULL
ORDER BY p.id;

-- name: GetListing :one
SELECT
    p.id,
    p.name,
    p.description,
    p.author,
    p.homepage,
    r.version,
    r.artifact_url,
    r.artifact_sha256,
    r.sdk_specifier,
    r.minimum_app_version
FROM plugin p
JOIN "release" r ON r.plugin_id = p.id AND r.state = 'approved'
WHERE p.delisted_at IS NULL AND p.id = ?;

-- name: ListPluginsWithNoApprovedRelease :many
-- The rows ListListings drops. A listing that vanishes without explanation is indistinguishable
-- from a bug, so the catalogue counts and names them rather than letting them disappear between a
-- claimed id and a rendered index.
SELECT p.id
FROM plugin p
WHERE p.delisted_at IS NULL
  AND NOT EXISTS (
      SELECT 1 FROM "release" r WHERE r.plugin_id = p.id AND r.state = 'approved'
  )
ORDER BY p.id;

-- name: InsertPlugin :exec
INSERT INTO plugin (id, name, description, author, homepage, claimed_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: InsertRelease :exec
INSERT INTO "release" (
    id, plugin_id, version, state, source,
    artifact_url, artifact_sha256, artifact_bytes,
    sdk_specifier, minimum_app_version,
    submitted_by, submitted_at, verified_at,
    reviewed_by, reviewed_at, review_note
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: InsertAuditLog :exec
INSERT INTO audit_log (id, recorded_at, actor_kind, actor_account_id, action, subject_kind, subject_id, detail)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: CountCatalogueImports :one
-- Whether a seed has ever been imported into this database. The audit row written by the import is
-- the marker: it is durable, it is append-only, and it does not depend on inferring "we have never
-- imported" from a row count somebody could one day make deletable. Uses the
-- (subject_kind, subject_id) index.
SELECT count(*) FROM audit_log
WHERE subject_kind = 'catalogue' AND action = 'catalogue.import';
