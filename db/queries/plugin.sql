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
    r.minimum_app_version,
    r.notes
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
    r.minimum_app_version,
    r.notes
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
-- The seed importer's insert. It carries notes because the seed document is the index document:
-- a catalogue captured with curl and replayed into an empty database must come back the same, and
-- an import that silently dropped an author's patch notes would make the two disagree with nothing
-- anywhere saying so.
INSERT INTO "release" (
    id, plugin_id, version, state, source,
    artifact_url, artifact_sha256, artifact_bytes,
    sdk_specifier, minimum_app_version, notes,
    submitted_by, submitted_at, verified_at,
    reviewed_by, reviewed_at, review_note
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: CountCatalogueImports :one
-- Whether a seed has ever been imported into this database. The audit row written by the import is
-- the marker: it is durable, it is append-only, and it does not depend on inferring "we have never
-- imported" from a row count somebody could one day make deletable. Uses the
-- (subject_kind, subject_id) index.
SELECT count(*) FROM audit_log
WHERE subject_kind = 'catalogue' AND action = 'catalogue.import';

-- name: GetPlugin :one
-- Whether an id is claimed at all, and its listing state. Used by the ownership import, which must
-- NOT create a plugin row for an id owners.json names but this registry does not carry: a claim on
-- an id nobody can check is exactly the squatting the first-come rule exists to prevent.
SELECT id, name, delisted_at FROM plugin WHERE id = ?;

-- name: SearchListings :many
-- The public directory's query. It is a SEPARATE statement from ListListings on purpose: the
-- index's query must never grow a parameter a web page controls, because the index is the document
-- a released client parses and its rows are decided by the schema, not by a querystring.
--
-- Matching is instr() over lower(), not LIKE. Two reasons, and neither is style: instr's needle
-- is LITERAL, so there are no wildcards to escape and a visitor typing % or _ searches for those
-- characters rather than for everything; and sqlc v1.31.1's SQLite grammar does not parse LIKE's
-- ESCAPE clause, so the alternative was an unescaped LIKE, which is the bug.
--
-- SQLite's lower() folds ASCII ONLY. The Go side folds the query the same way, with A-Z and
-- nothing else, so the two agree by construction: a query with non-ASCII letters matches
-- case-sensitively, which is a stated limitation rather than a surprise. Plugin ids are ASCII by
-- construction (core.PluginID), so ids are unaffected.
--
-- instr(x, '') is 1, so an empty query matches every row. That is why there is no CASE and no
-- second parameter for "did they search at all": "show me everything" is the same statement as
-- "match anything", and one code path cannot disagree with itself.
--
-- There is NO FTS5 table here: the catalogue is tens of rows, and a virtual table plus a migration
-- plus the triggers to keep it in step is a lot of machinery for a scan that costs microseconds.
-- See issue #40 for the row count at which that stops being true.
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
    r.minimum_app_version,
    r.notes
FROM plugin p
JOIN "release" r ON r.plugin_id = p.id AND r.state = 'approved'
WHERE p.delisted_at IS NULL
  AND (instr(lower(p.id), sqlc.arg(needle)) > 0
       OR instr(lower(p.name), sqlc.arg(needle)) > 0
       OR instr(lower(p.description), sqlc.arg(needle)) > 0
       OR instr(lower(p.author), sqlc.arg(needle)) > 0)
ORDER BY p.id;

-- name: CountCatalogue :one
-- What the directory shows, and what it does not.
--
-- A listing that vanishes without explanation is indistinguishable from a bug, so the page counts
-- the rows it drops rather than quietly serving a shorter list: `listed` is what a visitor sees,
-- `awaiting` is claimed ids with nothing approved behind them yet, and `delisted` is ids that are
-- kept forever and never recycled. One statement rather than three round trips, and no ids in it:
-- a count is not an enumeration.
SELECT
    (SELECT count(*)
     FROM plugin p
     JOIN "release" r ON r.plugin_id = p.id AND r.state = 'approved'
     WHERE p.delisted_at IS NULL) AS listed,
    (SELECT count(*)
     FROM plugin p
     WHERE p.delisted_at IS NULL
       AND NOT EXISTS (
           SELECT 1 FROM "release" r WHERE r.plugin_id = p.id AND r.state = 'approved'
       )) AS awaiting,
    (SELECT count(*) FROM plugin WHERE delisted_at IS NOT NULL) AS delisted;
