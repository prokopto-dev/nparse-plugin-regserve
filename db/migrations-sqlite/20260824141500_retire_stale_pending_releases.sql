-- +goose Up
-- Leave each plugin with ONE release waiting for review: the one submitted most recently.
--
-- Hand-written rather than diffed from db/schema.hcl, because it changes rows and not shape. It
-- has to run BEFORE the migration that adds release_one_pending_per_plugin, which the live
-- database would otherwise refuse to have -- it already holds the duplicates this exists to clear,
-- which is how the defect was noticed: the same plugin id in front of a reviewer several times.
--
-- Newest by (submitted_at, id), which is the order the queue already sorts by. The id is a ULID
-- and so breaks a tie in submission order rather than arbitrarily -- two releases submitted in the
-- same MICROSECOND is not a case worth a different rule, but it is one worth being deterministic
-- about, because a migration that picks a different survivor on a re-run is a migration nobody can
-- reason about after the fact.
--
-- 'superseded' and never a delete: ADR-0010 keeps every release row, and a BEFORE DELETE trigger
-- would abort this statement if it tried. review_note is left ALONE. It carries the quarantine
-- reasons a reviewer reads, and this migration has nothing to add to them that the row's new state
-- does not already say.
UPDATE "release"
SET state = 'superseded'
WHERE state = 'pending'
  AND id <> (
    SELECT newest.id FROM "release" newest
    WHERE newest.plugin_id = "release".plugin_id AND newest.state = 'pending'
    ORDER BY newest.submitted_at DESC, newest.id DESC
    LIMIT 1
  );

-- +goose Down
-- FORWARD-ONLY (ADR-0006). There is no down migration.
--
-- Recovery from a bad migration is restoring the snapshot the deploy takes immediately before it
-- runs: /opt/regserve/backups/pre-<timestamp>.db on the droplet. See docs/operations/deployment.md.
-- Rolling the image back is not enough on its own, because an older binary refuses a newer schema.
--
-- RAISE() is only legal inside a trigger body, so this statement cannot succeed by any route: it
-- fails to parse, goose rolls the transaction back, and the schema is untouched. The message is
-- here for the person reading the file, which is where they will be looking.
-- +goose StatementBegin
SELECT RAISE(ABORT, 'migrations are forward-only: restore the pre-migration snapshot from /opt/regserve/backups');
-- +goose StatementEnd
