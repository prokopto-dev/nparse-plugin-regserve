-- Personal access tokens: a deployment credential for one plugin's pipeline (ADR-0005).
--
-- Nothing here selects by id for the purpose of AUTHENTICATING. The lookup is by token_hash, which
-- is HMAC-SHA256(pepper, secret); the id and the 8-character prefix identify a row to a human, and
-- neither is a credential. The secret itself is not in this database at all.
--
-- ASCII only, like every file here: sqlc slices queries out of the file by byte offset and one
-- multi-byte character silently scrambles the SQL it generates. Gate QRY001.

-- name: InsertPAT :exec
INSERT INTO pat (id, account_id, prefix, token_hash, name, plugin_id, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);

-- name: InsertPATScope :exec
INSERT INTO pat_scope (pat_id, scope) VALUES (?, ?);

-- name: GetPATByTokenHash :one
-- The read on every publish. It joins the account so a disabled account's tokens stop working in
-- the same round trip: a token that outlives the account it belongs to is a credential nobody can
-- revoke by disabling the account.
SELECT
    p.id,
    p.account_id,
    p.prefix,
    p.plugin_id,
    p.created_at,
    p.expires_at,
    p.last_used_at,
    p.revoked_at,
    a.display_name,
    a.disabled_at
FROM pat p
JOIN account a ON a.id = p.account_id
WHERE p.token_hash = ?;

-- name: ListPATScopes :many
SELECT scope FROM pat_scope WHERE pat_id = ? ORDER BY scope;

-- name: ListPATsForAccount :many
-- What the account page shows. No hash and no secret: there is nothing here that could
-- authenticate anything.
SELECT id, prefix, name, plugin_id, created_at, expires_at, last_used_at, revoked_at
FROM pat
WHERE account_id = ?
ORDER BY created_at DESC;

-- name: TouchPAT :exec
-- Refreshed lazily, like a session's. A write in front of every publish would put token
-- bookkeeping in the single writer's queue ahead of the publish itself.
UPDATE pat SET last_used_at = ? WHERE id = ?;

-- name: RevokePAT :execrows
-- Scoped to the account on purpose: the id comes from a URL, and without this clause an owner
-- could revoke somebody else's token by guessing a ULID.
--
-- :execrows because the caller writes an audit row only when this changed something, and because
-- zero rows is how "not yours, or already revoked" is reported without a second query that would
-- tell the caller which.
UPDATE pat SET revoked_at = ?
WHERE id = ? AND account_id = ? AND revoked_at IS NULL;
