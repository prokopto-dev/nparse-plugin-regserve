-- Browser sessions and the in-flight OAuth handshakes that create them.
--
-- Nothing here selects a session by id. The lookup is always by token_hash, because the id is not
-- a credential and the secret is never stored — so "find the session this cookie belongs to" is a
-- keyed-hash lookup and cannot be anything else.

-- name: InsertSession :exec
INSERT INTO session (id, account_id, token_hash, created_at, last_seen_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetSessionByTokenHash :one
-- The read on every authenticated request. It joins the account so that a disabled account is
-- visible in the same round trip: a session that outlives the account it belongs to would be a
-- credential nobody can revoke by disabling the account.
SELECT
    s.id,
    s.account_id,
    s.created_at,
    s.last_seen_at,
    s.expires_at,
    s.revoked_at,
    a.display_name,
    a.disabled_at
FROM session s
JOIN account a ON a.id = s.account_id
WHERE s.token_hash = ?;

-- name: TouchSession :exec
-- Called at most once per session per touch interval, not once per request: this database has a
-- single writer, and a write in front of every authenticated read would put session bookkeeping
-- ahead of publishing in the write queue.
UPDATE session SET last_seen_at = ? WHERE id = ?;

-- name: RevokeSession :exec
-- Idempotent by the WHERE: logging out twice records the first time, not the second.
UPDATE session SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL;

-- name: ListSessionsForAccount :many
SELECT id, created_at, last_seen_at, expires_at, revoked_at
FROM session
WHERE account_id = ?
ORDER BY created_at DESC;

-- name: DeleteExpiredSessions :exec
-- Sessions carry no history worth keeping past their expiry — the audit log records the logins.
-- Deleting is allowed here precisely because of that, which is why this table has no no-delete
-- trigger and audit_log does.
DELETE FROM session WHERE expires_at < ?;

-- name: InsertOAuthFlow :exec
INSERT INTO oauth_flow (state_hash, provider_kind, code_verifier, redirect_to, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?);

-- name: GetOAuthFlow :one
SELECT state_hash, provider_kind, code_verifier, redirect_to, created_at, expires_at
FROM oauth_flow
WHERE state_hash = ?;

-- name: DeleteOAuthFlow :exec
-- SINGLE USE. The row is deleted the moment it is redeemed, which is the property a signed cookie
-- could not have given us: a replayed callback finds nothing and is refused.
DELETE FROM oauth_flow WHERE state_hash = ?;

-- name: DeleteExpiredOAuthFlows :exec
DELETE FROM oauth_flow WHERE expires_at < ?;
