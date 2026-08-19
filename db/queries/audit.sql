-- The append-only record of who did what.
--
-- One INSERT and nothing else, deliberately: there is no UPDATE and no DELETE anywhere in this
-- file or in the generated bindings, and BEFORE UPDATE / BEFORE DELETE triggers abort either if
-- one ever arrives by another route. A correction is a new row.
--
-- `detail` is a JSON object and must NEVER carry a token secret, a session id, an OAuth access
-- token, a client secret or the pepper. This is the one table nobody can redact later.

-- name: InsertAuditLog :exec
INSERT INTO audit_log (id, recorded_at, actor_kind, actor_account_id, action, subject_kind, subject_id, detail)
VALUES (?, ?, ?, ?, ?, ?, ?, ?);
