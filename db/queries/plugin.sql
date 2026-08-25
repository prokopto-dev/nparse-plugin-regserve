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

-- name: ListPluginsForModeration :many
-- Every plugin this registry knows, whatever its state, for the reviewer's catalogue view.
--
-- NOT the directory's query, and the difference is the point of this one. SearchListings answers
-- "what is publicly visible" and drops a delisted or unpublished id on the floor, counting it so
-- the number is honest. A reviewer needs the rows themselves: the ids claimed and never published,
-- and the ids somebody delisted, are exactly the ones moderation is about, and a moderation
-- surface that could only see what the public sees would be blind to its own subject.
--
-- No WHERE at all, deliberately. A filter here would be a row a reviewer cannot see, and there is
-- no state of a plugin this page is not for.
SELECT
    p.id,
    p.name,
    p.description,
    p.author,
    p.homepage,
    p.claimed_at,
    p.delisted_at,
    p.delisted_reason,
    CAST(coalesce((SELECT r.version FROM "release" r
        WHERE r.plugin_id = p.id AND r.state = 'approved' LIMIT 1), '') AS TEXT) AS live_version,
    (SELECT count(*) FROM "release" r
        WHERE r.plugin_id = p.id AND r.state = 'pending') AS pending_releases,
    (SELECT count(*) FROM plugin_owner o WHERE o.plugin_id = p.id) AS owner_count
FROM plugin p
ORDER BY p.id;

-- name: GetPluginForModeration :one
-- One plugin for the reviewer's page. Same columns as the list, so the two surfaces cannot
-- disagree about what state a plugin is in.
SELECT
    p.id,
    p.name,
    p.description,
    p.author,
    p.homepage,
    p.claimed_at,
    p.delisted_at,
    p.delisted_reason,
    CAST(coalesce((SELECT r.version FROM "release" r
        WHERE r.plugin_id = p.id AND r.state = 'approved' LIMIT 1), '') AS TEXT) AS live_version,
    (SELECT count(*) FROM "release" r
        WHERE r.plugin_id = p.id AND r.state = 'pending') AS pending_releases,
    (SELECT count(*) FROM plugin_owner o WHERE o.plugin_id = p.id) AS owner_count
FROM plugin p
WHERE p.id = ?;

-- name: ListOwnersWithTrust :many
-- Every ownership grant in the registry, with the holder's handle and CURRENT trust tier.
--
-- ALL of them in one statement, grouped by the caller, rather than a query per plugin: the
-- reviewer's catalogue shows owners against every row, and a page that issued one read per plugin
-- would be a page whose cost grows with the registry while it holds the reader's connection open.
--
-- LEFT JOIN account_trust because NO ROW MEANS 'new'. An INNER JOIN would silently drop every
-- owner nobody has assessed -- which is most of them, and exactly the ones a reviewer is looking
-- for. The caller reads a NULL level as the floor, the same reading release.TrustOf gives it.
--
-- plugin_id is selected so one pass can bucket the rows; the caller filters in Go rather than
-- running this per plugin.
SELECT
    o.plugin_id,
    o.account_id,
    o.role,
    a.display_name,
    CAST(coalesce((SELECT i.handle FROM identity i WHERE i.account_id = a.id
        ORDER BY i.linked_at, i.id LIMIT 1), '') AS TEXT) AS handle,
    CAST(coalesce(t.level, '') AS TEXT) AS trust_level
FROM plugin_owner o
JOIN account a ON a.id = o.account_id
LEFT JOIN account_trust t ON t.account_id = o.account_id
ORDER BY o.plugin_id, o.granted_at, o.account_id;

-- name: DelistPlugin :execrows
-- Remove a plugin's listing and KEEP ITS CLAIM.
--
-- An UPDATE, never a DELETE. The plugin row IS the claim (a BEFORE DELETE trigger aborts a
-- removal), so delisting sets delisted_at and the id stays spoken for -- permanently, and for
-- nobody else. An id whose plugin is gone must never become available to somebody else, because
-- that is how you ship an update to another author's users.
--
-- delisted_reason is NOT NULL here because the table's CHECK requires the pair to agree: a
-- delisting with no stated reason is one nobody can review later, and a listing that vanishes
-- without explanation is indistinguishable from a bug.
--
-- The WHERE names the expected current state, like every state change in review.sql and for the
-- same reason: zero rows is how "it was already delisted" is reported, without a Go check above
-- the statement leaving a window between the read and the write.
UPDATE plugin
SET delisted_at = ?, delisted_reason = ?, updated_at = ?
WHERE id = ? AND delisted_at IS NULL;

-- name: RelistPlugin :execrows
-- Put a delisted plugin's listing back.
--
-- The inverse of the statement above, and it exists because the alternative to it is a maintainer
-- writing SQL against production. Delisting is reversible in the schema -- delisted_at is nullable
-- -- and a moderation action a reviewer cannot undo through the same surface they performed it in
-- is one that gets undone by hand, at 2am, with no audit row.
--
-- It clears delisted_reason with it, because the CHECK requires the pair to agree, and the reason
-- a listing WAS removed does not survive as a property of a listing that is back. It survives in
-- audit_log, which is the copy that cannot be edited.
--
-- Relisting does NOT restore anything else, because nothing else was taken away: the releases, the
-- owners and the claim were never touched. What comes back is the row's presence in the index, and
-- only if it still has an approved release -- a plugin delisted before it ever published relists
-- to exactly where it was, awaiting review.
UPDATE plugin
SET delisted_at = NULL, delisted_reason = NULL, updated_at = ?
WHERE id = ? AND delisted_at IS NOT NULL;
