-- +goose Up
-- create "pat" table
CREATE TABLE "pat" ("id" text NOT NULL, "account_id" text NOT NULL, "prefix" text NOT NULL, "token_hash" text NOT NULL, "name" text NOT NULL DEFAULT '', "plugin_id" text, "created_at" integer NOT NULL, "expires_at" integer, "last_used_at" integer, "revoked_at" integer, PRIMARY KEY ("id"), CONSTRAINT "pat_account_fk" FOREIGN KEY ("account_id") REFERENCES "account" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "pat_plugin_fk" FOREIGN KEY ("plugin_id") REFERENCES "plugin" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "pat_token_hash_shape" CHECK (length(token_hash) = 64 AND NOT token_hash GLOB '*[^0-9a-f]*'), CONSTRAINT "pat_prefix_shape" CHECK (length(prefix) = 8 AND NOT prefix GLOB '*[^0-9a-f]*'), CONSTRAINT "pat_expires_after_it_starts" CHECK (expires_at IS NULL OR expires_at > created_at)) STRICT;
-- create index "pat_token_hash_key" to table: "pat"
CREATE UNIQUE INDEX "pat_token_hash_key" ON "pat" ("token_hash");
-- create index "pat_prefix_key" to table: "pat"
CREATE UNIQUE INDEX "pat_prefix_key" ON "pat" ("prefix");
-- create index "pat_account_idx" to table: "pat"
CREATE INDEX "pat_account_idx" ON "pat" ("account_id");
-- create "pat_scope" table
CREATE TABLE "pat_scope" ("pat_id" text NOT NULL, "scope" text NOT NULL, PRIMARY KEY ("pat_id", "scope"), CONSTRAINT "pat_scope_pat_fk" FOREIGN KEY ("pat_id") REFERENCES "pat" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "pat_scope_enum" CHECK (scope IN ('plugin:read', 'plugin:publish', 'plugin:manage'))) STRICT;

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
