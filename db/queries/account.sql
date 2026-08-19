-- Accounts and the provider identities that prove you are one (ADR-0003).
--
-- Every lookup here is by (provider_kind, subject) and NEVER by handle. The handle is decoration
-- refreshed at each login; matching on it is the property the account/identity split exists to
-- remove, because a GitHub rename would otherwise be indistinguishable from a different person.

-- name: GetAccountByIdentity :one
-- The login path's only read. It returns the account behind a (provider, subject) pair, plus the
-- identity row so the caller can refresh the cached handle without a second query.
SELECT
    a.id,
    a.display_name,
    a.created_at,
    a.disabled_at,
    i.id AS identity_id,
    i.handle
FROM identity i
JOIN account a ON a.id = i.account_id
WHERE i.provider_kind = ? AND i.subject = ?;

-- name: GetAccount :one
SELECT id, display_name, created_at, disabled_at FROM account WHERE id = ?;

-- name: GetIdentityForAccount :one
-- The identity to show a human on the account page. Ordered by linked_at so that an account with
-- several identities has a stable answer rather than whichever row the planner reached first.
SELECT provider_kind, subject, handle
FROM identity
WHERE account_id = ?
ORDER BY linked_at, id
LIMIT 1;

-- name: InsertAccount :exec
INSERT INTO account (id, display_name, created_at, updated_at) VALUES (?, ?, ?, ?);

-- name: InsertIdentity :exec
INSERT INTO identity (id, account_id, provider_kind, subject, handle, linked_at, refreshed_at)
VALUES (?, ?, ?, ?, ?, ?, ?);

-- name: RefreshIdentity :exec
-- The handle as it was at this login, and when we last looked. Never a matching key.
UPDATE identity SET handle = ?, refreshed_at = ? WHERE id = ?;

-- name: UpdateAccountDisplayName :exec
UPDATE account SET display_name = ?, updated_at = ? WHERE id = ?;
