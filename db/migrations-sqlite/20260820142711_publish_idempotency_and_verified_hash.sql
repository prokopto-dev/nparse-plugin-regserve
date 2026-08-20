-- +goose Up
-- disable the enforcement of foreign-keys constraints
PRAGMA foreign_keys = off;
-- create "new_release" table
CREATE TABLE "new_release" (
  "id" text NOT NULL,
  "plugin_id" text NOT NULL,
  "version" text NOT NULL,
  "state" text NOT NULL,
  "source" text NOT NULL,
  "artifact_url" text NOT NULL,
  "artifact_sha256" text,
  "artifact_bytes" integer,
  "sdk_specifier" text NOT NULL,
  "minimum_app_version" text,
  "submitted_by" text,
  "submitted_at" integer NOT NULL,
  "verified_at" integer,
  "reviewed_by" text,
  "reviewed_at" integer,
  "review_note" text,
  "notes" text,
  PRIMARY KEY ("id"),
  CONSTRAINT "release_plugin_fk" FOREIGN KEY ("plugin_id") REFERENCES "plugin" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT,
  CONSTRAINT "release_submitted_by_fk" FOREIGN KEY ("submitted_by") REFERENCES "account" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT,
  CONSTRAINT "release_reviewed_by_fk" FOREIGN KEY ("reviewed_by") REFERENCES "account" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT,
  CONSTRAINT "release_state_enum" CHECK (state IN ('pending', 'approved', 'rejected', 'superseded')),
  CONSTRAINT "release_source_enum" CHECK (source IN ('publish', 'import')),
  CONSTRAINT "release_version_not_empty" CHECK (length(version) > 0),
  CONSTRAINT "release_artifact_url_https" CHECK (artifact_url LIKE 'https://%'),
  CONSTRAINT "release_artifact_sha256_shape" CHECK (artifact_sha256 IS NULL OR (length(artifact_sha256) = 64 AND NOT artifact_sha256 GLOB '*[^0-9a-f]*')),
  CONSTRAINT "release_artifact_bytes_non_negative" CHECK (artifact_bytes IS NULL OR artifact_bytes >= 0),
  CONSTRAINT "release_notes_within_the_index_budget" CHECK (notes IS NULL OR length(CAST(notes AS BLOB)) <= 2048),
  CONSTRAINT "release_approved_has_a_hash" CHECK (state <> 'approved' OR artifact_sha256 IS NOT NULL),
  CONSTRAINT "release_a_stored_hash_was_verified_or_imported" CHECK (artifact_sha256 IS NULL OR source = 'import' OR verified_at IS NOT NULL)
) STRICT;
-- copy rows from old table "release" to new temporary table "new_release"
INSERT INTO "new_release" ("id", "plugin_id", "version", "state", "source", "artifact_url", "artifact_sha256", "artifact_bytes", "sdk_specifier", "minimum_app_version", "submitted_by", "submitted_at", "verified_at", "reviewed_by", "reviewed_at", "review_note", "notes") SELECT "id", "plugin_id", "version", "state", "source", "artifact_url", "artifact_sha256", "artifact_bytes", "sdk_specifier", "minimum_app_version", "submitted_by", "submitted_at", "verified_at", "reviewed_by", "reviewed_at", "review_note", "notes" FROM "release";
-- drop "release" table after copying rows
DROP TABLE "release";
-- rename temporary table "new_release" to "release"
ALTER TABLE "new_release" RENAME TO "release";
-- create index "release_plugin_version_key" to table: "release"
CREATE UNIQUE INDEX "release_plugin_version_key" ON "release" ("plugin_id", "version");
-- create index "release_one_approved_per_plugin" to table: "release"
CREATE UNIQUE INDEX "release_one_approved_per_plugin" ON "release" ("plugin_id") WHERE state = 'approved';
-- create "idempotency_key" table
CREATE TABLE "idempotency_key" (
  "account_id" text NOT NULL,
  "operation" text NOT NULL,
  "idempotency_key" text NOT NULL,
  "request_hash" text NOT NULL,
  "release_id" text NOT NULL,
  "created_at" integer NOT NULL,
  PRIMARY KEY ("account_id", "operation", "idempotency_key"),
  CONSTRAINT "idempotency_key_account_fk" FOREIGN KEY ("account_id") REFERENCES "account" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT,
  CONSTRAINT "idempotency_key_release_fk" FOREIGN KEY ("release_id") REFERENCES "release" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT,
  CONSTRAINT "idempotency_key_not_empty" CHECK (length(idempotency_key) > 0),
  CONSTRAINT "idempotency_key_request_hash_shape" CHECK (length(request_hash) = 64 AND NOT request_hash GLOB '*[^0-9a-f]*')
) STRICT;
-- enable back the enforcement of foreign-keys constraints
PRAGMA foreign_keys = on;

-- --- HAND-AUTHORED BELOW THIS LINE ---------------------------------------------------------------
--
-- RECREATING A TRIGGER THE REBUILD ABOVE DESTROYED. This is the second time, and the reason is
-- unchanged from 20260820131854_release_notes.sql: adding a CHECK makes Atlas rebuild the table --
-- create new, copy, DROP TABLE, rename -- and SQLite drops a table's triggers with the table.
--
-- What is being protected is ADR-0010: the database keeps every release row even though only
-- "latest" ships on the wire, because those rows are the record of what was approved and by whom.
-- Without this trigger that history is deletable, and nothing anywhere would say so.
--
-- Gate MIG005 fails this migration without the block below, which is why it is here rather than
-- discovered by TestSchema_RefusedStatements after the fact -- as it was the first time.
-- +goose StatementBegin
CREATE TRIGGER "release_no_delete" BEFORE DELETE ON "release"
BEGIN
  SELECT RAISE(ABORT, 'release history is kept: supersede the row instead of deleting it');
END;
-- +goose StatementEnd

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
