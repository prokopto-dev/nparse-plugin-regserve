-- The review queue: reading what is waiting, and the three state changes a reviewer can make.
--
-- ASCII only: gate QRY001. sqlc slices queries out of this file by byte offset.
--
-- "release" is quoted throughout because RELEASE is a SQLite keyword (RELEASE SAVEPOINT).
--
-- EVERY STATE CHANGE BELOW NAMES THE EXPECTED CURRENT STATE IN ITS WHERE CLAUSE, and every one is
-- :execrows. That is not defensive style: it is how two reviewers acting at the same moment
-- produce one change and one honest "that release is no longer pending" rather than two approvals
-- racing over the same row. A Go check above the statement leaves a window; the WHERE does not.

-- name: ListPendingReleases :many
-- What is waiting for a human, oldest first.
--
-- Oldest first because a queue people work from the top of is a queue where the bottom is never
-- reached, and the bottom is where a submission that has been waiting a fortnight sits.
--
-- It carries verified_at and artifact_sha256 so the queue can SHOW which entries were never
-- verified. Those are the ones a reviewer must not simply wave through -- and the database will
-- refuse to approve them anyway (release_approved_has_a_hash), so a queue that did not show it
-- would be sending reviewers into an error.
SELECT
    r.id,
    r.plugin_id,
    p.name AS plugin_name,
    r.version,
    r.artifact_url,
    r.artifact_sha256,
    r.artifact_bytes,
    r.submitted_by,
    r.submitted_at,
    r.verified_at,
    r.review_note,
    (SELECT count(*) FROM "release" prior
        WHERE prior.plugin_id = r.plugin_id AND prior.state = 'approved') AS approved_releases
FROM "release" r
JOIN plugin p ON p.id = r.plugin_id
WHERE r.state = 'pending'
ORDER BY r.submitted_at, r.id;

-- name: CountPendingReleases :one
-- The queue depth. A number nobody looks at is a number that grows, so it is logged at boot and
-- reported on the account surface rather than being discoverable only by listing.
SELECT count(*) FROM "release" WHERE state = 'pending';

-- name: ApproveRelease :execrows
-- Make a release the plugin's live one.
--
-- The WHERE requires it to still be pending. Zero rows means somebody else got there first, or it
-- was rejected while this reviewer was reading it, and that is reported rather than retried.
UPDATE "release"
SET state = 'approved', reviewed_by = ?, reviewed_at = ?, review_note = ?
WHERE id = ? AND state = 'pending';

-- name: RejectRelease :execrows
-- Refuse a release. The row STAYS: it is the record of what was submitted and turned down, and the
-- version it used is never freed (a version is used once per plugin, ever).
UPDATE "release"
SET state = 'rejected', reviewed_by = ?, reviewed_at = ?, review_note = ?
WHERE id = ? AND state = 'pending';

-- name: SupersedeApprovedRelease :execrows
-- Retire whatever is currently live for a plugin, so a new approval can take its place.
--
-- Run in the SAME transaction as the approval that replaces it. The partial unique index
-- release_one_approved_per_plugin permits exactly one approved row per plugin, so doing this
-- second, or in another transaction, is a constraint violation rather than a race -- which is the
-- index doing its job, and is still a failed approval somebody has to understand.
--
-- Superseding is a STATE CHANGE and never a delete: ADR-0010 keeps every release row, because they
-- are the record of what was approved and by whom.
UPDATE "release"
SET state = 'superseded'
WHERE plugin_id = ? AND state = 'approved';

-- name: RecordReleaseVerification :execrows
-- Write the hash and size THIS SERVER computed onto a release it had not managed to verify.
--
-- The WHERE requires verified_at IS NULL, so this can only ever fill in a blank. It cannot change
-- a hash that is already recorded: a stored hash is what clients verify against, and a statement
-- that could rewrite one would be a way to swap the bytes behind an approved listing without
-- anybody reviewing the swap -- which is the exact property this whole service exists to keep.
UPDATE "release"
SET artifact_sha256 = ?, artifact_bytes = ?, verified_at = ?, review_note = ?
WHERE id = ? AND verified_at IS NULL;

-- name: ListHandlesForAccount :many
-- Every provider handle an account holds, for the reviewer check.
--
-- All of them rather than the first: an account with two linked identities holds both, and picking
-- one by linked_at would make whether somebody can review depend on the order they signed in.
SELECT provider_kind, handle FROM identity WHERE account_id = ? ORDER BY linked_at, id;
