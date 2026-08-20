-- Who may change a plugin's listing (ADR-0005).
--
-- Ownership is checked PER REQUEST rather than cascade-revoked, so removing an owner takes effect
-- on their next call rather than after a sweep. That is why these are reads on the hot path and
-- not a cached set.
--
-- ASCII only: gate QRY001. sqlc slices queries out of this file by byte offset.

-- name: ListPluginsForAccount :many
-- The account page's "your plugins". A delisted plugin is still listed here on purpose: the id is
-- still claimed, the owner still owns it, and a page that hid it would be a page that told
-- somebody their plugin was gone.
SELECT
    p.id,
    p.name,
    p.delisted_at,
    o.role,
    o.granted_at,
    (SELECT count(*) FROM "release" r WHERE r.plugin_id = p.id AND r.state = 'approved') AS approved_releases
FROM plugin_owner o
JOIN plugin p ON p.id = o.plugin_id
WHERE o.account_id = ?
ORDER BY p.id;

-- name: ListOwnersForPlugin :many
-- The settings page. It joins the identity so a human sees a GitHub handle rather than a ULID --
-- the handle is decoration, refreshed at each login, and never what anything matches on.
SELECT
    o.account_id,
    o.role,
    o.granted_at,
    a.display_name,
    CAST(coalesce((SELECT i.handle FROM identity i WHERE i.account_id = a.id ORDER BY i.linked_at, i.id LIMIT 1), '') AS TEXT) AS handle
FROM plugin_owner o
JOIN account a ON a.id = o.account_id
WHERE o.plugin_id = ?
ORDER BY o.granted_at, o.account_id;

-- name: GetPluginOwner :one
SELECT plugin_id, account_id, role, granted_at FROM plugin_owner
WHERE plugin_id = ? AND account_id = ?;

-- name: CountOwnersForPlugin :one
SELECT count(*) FROM plugin_owner WHERE plugin_id = ?;

-- name: InsertPluginOwner :exec
INSERT INTO plugin_owner (plugin_id, account_id, role, granted_at, granted_by)
VALUES (?, ?, ?, ?, ?);

-- name: DeletePluginOwner :execrows
-- Deleting a plugin_owner row is allowed, and is the only delete in this schema that is: it removes
-- a grant, not a claim. The plugin row IS the claim and a BEFORE DELETE trigger aborts any attempt
-- to remove one, so an id cannot be recycled by removing its last owner.
--
-- :execrows because zero rows is how "not an owner" is reported, and because the caller writes an
-- audit row only when something actually changed.
DELETE FROM plugin_owner WHERE plugin_id = ? AND account_id = ?;

-- name: GetAccountByHandle :one
-- Resolving a GitHub handle to the account behind it, for the "add an owner" form.
--
-- This is the ONE place a handle is matched on, and it is matched case-insensitively because that
-- is how GitHub compares them and how the static registry's owners.json did. It resolves to an
-- account that has ALREADY SIGNED IN: there is no way to grant ownership to somebody who has never
-- authenticated here, which is deliberate -- a grant to a handle nobody has proved they hold is a
-- grant to whoever registers it next.
SELECT a.id, a.display_name, a.disabled_at, i.handle
FROM identity i
JOIN account a ON a.id = i.account_id
WHERE i.provider_kind = ? AND lower(i.handle) = lower(sqlc.arg(handle))
ORDER BY i.linked_at, i.id
LIMIT 1;
