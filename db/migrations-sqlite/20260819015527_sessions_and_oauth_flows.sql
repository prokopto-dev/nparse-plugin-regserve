-- +goose Up
-- create "session" table
CREATE TABLE "session" ("id" text NOT NULL, "account_id" text NOT NULL, "token_hash" text NOT NULL, "created_at" integer NOT NULL, "last_seen_at" integer NOT NULL, "expires_at" integer NOT NULL, "revoked_at" integer, PRIMARY KEY ("id"), CONSTRAINT "session_account_fk" FOREIGN KEY ("account_id") REFERENCES "account" ("id") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "session_token_hash_shape" CHECK (length(token_hash) = 64 AND NOT token_hash GLOB '*[^0-9a-f]*'), CONSTRAINT "session_expires_after_it_starts" CHECK (expires_at > created_at)) STRICT;
-- create index "session_token_hash_key" to table: "session"
CREATE UNIQUE INDEX "session_token_hash_key" ON "session" ("token_hash");
-- create index "session_account_idx" to table: "session"
CREATE INDEX "session_account_idx" ON "session" ("account_id");
-- create "oauth_flow" table
CREATE TABLE "oauth_flow" ("state_hash" text NOT NULL, "provider_kind" text NOT NULL, "code_verifier" text NOT NULL, "redirect_to" text NOT NULL DEFAULT '', "created_at" integer NOT NULL, "expires_at" integer NOT NULL, PRIMARY KEY ("state_hash"), CONSTRAINT "oauth_flow_provider_fk" FOREIGN KEY ("provider_kind") REFERENCES "identity_provider" ("kind") ON UPDATE NO ACTION ON DELETE RESTRICT, CONSTRAINT "oauth_flow_state_hash_shape" CHECK (length(state_hash) = 64 AND NOT state_hash GLOB '*[^0-9a-f]*'), CONSTRAINT "oauth_flow_code_verifier_length" CHECK (length(code_verifier) BETWEEN 43 AND 128), CONSTRAINT "oauth_flow_redirect_is_a_local_path" CHECK (redirect_to = '' OR (substr(redirect_to, 1, 1) = '/' AND substr(redirect_to, 2, 1) NOT IN ('/', char(92)))), CONSTRAINT "oauth_flow_expires_after_it_starts" CHECK (expires_at > created_at)) STRICT;
-- create index "oauth_flow_expires_at_idx" to table: "oauth_flow"
CREATE INDEX "oauth_flow_expires_at_idx" ON "oauth_flow" ("expires_at");

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
