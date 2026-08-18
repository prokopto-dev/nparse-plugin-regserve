-- +goose Up
-- create "account" table
CREATE TABLE "account" ("id" text NOT NULL, "display_name" text NOT NULL DEFAULT '', "created_at" integer NOT NULL, "updated_at" integer NOT NULL, "disabled_at" integer, PRIMARY KEY ("id")) STRICT;
-- create "identity_provider" table
CREATE TABLE "identity_provider" ("kind" text NOT NULL, "display_name" text NOT NULL, "can_publish" integer NOT NULL, "created_at" integer NOT NULL, PRIMARY KEY ("kind"), CONSTRAINT "identity_provider_kind_enum" CHECK (kind IN ('github')), CONSTRAINT "identity_provider_can_publish_boolean" CHECK (can_publish IN (0, 1)), CONSTRAINT "identity_provider_only_github_publishes" CHECK (can_publish = 0 OR kind = 'github')) STRICT;
-- create "identity" table
CREATE TABLE "identity" ("id" text NOT NULL, "account_id" text NOT NULL, "provider_kind" text NOT NULL, "subject" text NOT NULL, "handle" text NOT NULL DEFAULT '', "linked_at" integer NOT NULL, "refreshed_at" integer NOT NULL, PRIMARY KEY ("id"), CONSTRAINT "identity_account_fk" FOREIGN KEY ("account_id") REFERENCES "account" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "identity_provider_fk" FOREIGN KEY ("provider_kind") REFERENCES "identity_provider" ("kind") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "identity_subject_not_empty" CHECK (length(subject) > 0)) STRICT;
-- create index "identity_provider_subject_key" to table: "identity"
CREATE UNIQUE INDEX "identity_provider_subject_key" ON "identity" ("provider_kind", "subject");
-- create index "identity_account_idx" to table: "identity"
CREATE INDEX "identity_account_idx" ON "identity" ("account_id");
-- create "plugin" table
CREATE TABLE "plugin" ("id" text NOT NULL, "name" text NOT NULL, "description" text NOT NULL DEFAULT '', "author" text NOT NULL DEFAULT '', "homepage" text NOT NULL DEFAULT '', "claimed_at" integer NOT NULL, "updated_at" integer NOT NULL, "delisted_at" integer, "delisted_reason" text, PRIMARY KEY ("id"), CONSTRAINT "plugin_id_length" CHECK (length(id) BETWEEN 2 AND 40), CONSTRAINT "plugin_name_not_empty" CHECK (length(name) > 0), CONSTRAINT "plugin_delisting_states_its_reason" CHECK ((delisted_at IS NULL AND delisted_reason IS NULL) OR (delisted_at IS NOT NULL AND delisted_reason IS NOT NULL))) STRICT;
-- create "release" table
CREATE TABLE "release" ("id" text NOT NULL, "plugin_id" text NOT NULL, "version" text NOT NULL, "state" text NOT NULL, "source" text NOT NULL, "artifact_url" text NOT NULL, "artifact_sha256" text, "artifact_bytes" integer, "sdk_specifier" text NOT NULL, "minimum_app_version" text, "submitted_by" text, "submitted_at" integer NOT NULL, "verified_at" integer, "reviewed_by" text, "reviewed_at" integer, "review_note" text, PRIMARY KEY ("id"), CONSTRAINT "release_plugin_fk" FOREIGN KEY ("plugin_id") REFERENCES "plugin" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "release_submitted_by_fk" FOREIGN KEY ("submitted_by") REFERENCES "account" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "release_reviewed_by_fk" FOREIGN KEY ("reviewed_by") REFERENCES "account" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "release_state_enum" CHECK (state IN ('pending', 'approved', 'rejected', 'superseded')), CONSTRAINT "release_source_enum" CHECK (source IN ('publish', 'import')), CONSTRAINT "release_version_not_empty" CHECK (length(version) > 0), CONSTRAINT "release_artifact_url_https" CHECK (artifact_url LIKE 'https://%'), CONSTRAINT "release_artifact_sha256_shape" CHECK (artifact_sha256 IS NULL OR (length(artifact_sha256) = 64 AND NOT artifact_sha256 GLOB '*[^0-9a-f]*')), CONSTRAINT "release_artifact_bytes_non_negative" CHECK (artifact_bytes IS NULL OR artifact_bytes >= 0), CONSTRAINT "release_approved_has_a_hash" CHECK (state <> 'approved' OR artifact_sha256 IS NOT NULL)) STRICT;
-- create index "release_plugin_version_key" to table: "release"
CREATE UNIQUE INDEX "release_plugin_version_key" ON "release" ("plugin_id", "version");
-- create index "release_one_approved_per_plugin" to table: "release"
CREATE UNIQUE INDEX "release_one_approved_per_plugin" ON "release" ("plugin_id") WHERE state = 'approved';
-- create "plugin_owner" table
CREATE TABLE "plugin_owner" ("plugin_id" text NOT NULL, "account_id" text NOT NULL, "role" text NOT NULL, "granted_at" integer NOT NULL, "granted_by" text, PRIMARY KEY ("plugin_id", "account_id"), CONSTRAINT "plugin_owner_plugin_fk" FOREIGN KEY ("plugin_id") REFERENCES "plugin" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "plugin_owner_account_fk" FOREIGN KEY ("account_id") REFERENCES "account" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "plugin_owner_granted_by_fk" FOREIGN KEY ("granted_by") REFERENCES "account" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "plugin_owner_role_enum" CHECK (role IN ('owner', 'maintainer'))) STRICT;
-- create index "plugin_owner_account_idx" to table: "plugin_owner"
CREATE INDEX "plugin_owner_account_idx" ON "plugin_owner" ("account_id");
-- create "account_trust" table
CREATE TABLE "account_trust" ("account_id" text NOT NULL, "level" text NOT NULL, "set_at" integer NOT NULL, "set_by" text, "note" text, PRIMARY KEY ("account_id"), CONSTRAINT "account_trust_account_fk" FOREIGN KEY ("account_id") REFERENCES "account" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "account_trust_set_by_fk" FOREIGN KEY ("set_by") REFERENCES "account" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "account_trust_level_enum" CHECK (level IN ('blocked', 'new', 'trusted'))) STRICT;
-- create "audit_log" table
CREATE TABLE "audit_log" ("id" text NOT NULL, "recorded_at" integer NOT NULL, "actor_kind" text NOT NULL, "actor_account_id" text, "action" text NOT NULL, "subject_kind" text NOT NULL, "subject_id" text, "detail" text, PRIMARY KEY ("id"), CONSTRAINT "audit_log_actor_fk" FOREIGN KEY ("actor_account_id") REFERENCES "account" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "audit_log_actor_kind_enum" CHECK (actor_kind IN ('account', 'system')), CONSTRAINT "audit_log_actor_matches_kind" CHECK ((actor_kind = 'account' AND actor_account_id IS NOT NULL) OR (actor_kind = 'system' AND actor_account_id IS NULL)), CONSTRAINT "audit_log_action_not_empty" CHECK (length(action) > 0)) STRICT;
-- create index "audit_log_recorded_at_idx" to table: "audit_log"
CREATE INDEX "audit_log_recorded_at_idx" ON "audit_log" ("recorded_at");
-- create index "audit_log_subject_idx" to table: "audit_log"
CREATE INDEX "audit_log_subject_idx" ON "audit_log" ("subject_kind", "subject_id");


-- ------------------------------------------------------------------------------------------------
-- HAND-AUTHORED from here to the end of the Up block. Everything above was written by
-- "atlas migrate diff" from db/schema.hcl; everything below cannot be, and the boundary is marked
-- so that a later diff appending to this file does not leave a reader guessing which is which.
--
-- The community build of Atlas models neither triggers nor data. A "trigger" block in schema.hcl
-- is parsed and then silently ignored, which would be worse than absent -- a reader would believe
-- it was applied. Atlas replays this directory to compute its next diff, so it sees these objects
-- in the dev database and leaves them alone.
--
-- Each trigger below turns a rule that was previously a review rule into a mechanism. Tests in
-- internal/store write to a real database and require each one to fire; a trigger nobody has seen
-- abort is a trigger nobody knows works.
-- ------------------------------------------------------------------------------------------------

-- audit_log is APPEND-ONLY. It is the evidence the trust model rests on: "who approved these exact
-- bytes, and when" has to be answerable years later, including when the person answering is the
-- person under suspicion. A correction is a new row.
-- +goose StatementBegin
CREATE TRIGGER "audit_log_no_update" BEFORE UPDATE ON "audit_log"
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: record a correction as a new row');
END;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE TRIGGER "audit_log_no_delete" BEFORE DELETE ON "audit_log"
BEGIN
  SELECT RAISE(ABORT, 'audit_log is append-only: a row cannot be removed');
END;
-- +goose StatementEnd

-- A plugin id is permanent and never recycled. The row IS the claim, so deleting one would put an
-- id back on the market -- and shipping an update to somebody else's users is precisely what that
-- makes possible. Delisting sets delisted_at and keeps the row.
-- +goose StatementBegin
CREATE TRIGGER "plugin_no_delete" BEFORE DELETE ON "plugin"
BEGIN
  SELECT RAISE(ABORT, 'a plugin id is never recycled: delist it by setting delisted_at');
END;
-- +goose StatementEnd

-- Release history is kept even though only "latest" ships (ADR-0010). Superseding is a state
-- change; a deleted row is an approval nobody can audit and a version number that could be reused.
-- +goose StatementBegin
CREATE TRIGGER "release_no_delete" BEFORE DELETE ON "release"
BEGIN
  SELECT RAISE(ABORT, 'release history is kept: supersede the row instead of deleting it');
END;
-- +goose StatementEnd

-- GitHub is the only identity provider (ADR-0011), so it is the only row this table needs. It is
-- inserted by the migration rather than by application code because a service that writes its own
-- provider row at boot is a service where a bug in that code silently creates a second provider.
--
-- can_publish = 1 is permitted only because kind = 'github'; the CHECK on the table is what makes
-- a provider added later non-publishing until somebody argues otherwise in a pull request.
--
-- created_at is second-precision here: it records when the migration ran, and a migration has no
-- injected clock. Every other timestamp in this database comes from internal/clock.
INSERT INTO "identity_provider" ("kind", "display_name", "can_publish", "created_at")
VALUES ('github', 'GitHub', 1, CAST(strftime('%s', 'now') AS INTEGER) * 1000000);


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
