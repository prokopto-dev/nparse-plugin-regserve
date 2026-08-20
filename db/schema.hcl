# db/schema.hcl — the single declarative truth for the database (ADR-0006, canonical §7).
#
# Atlas diffs this file and writes a numbered migration into db/migrations-sqlite/; goose, embedded
# in the binary, applies them at boot. Nothing else describes the schema: if a column is not here,
# it does not exist, and a migration that disagrees with this file is the bug.
#
# House rules, all of them mechanised or checked in review:
#
#   * Every table is STRICT. SQLite's default type affinity will happily store the string "banana"
#     in an INTEGER column, and the first place that shows up is a query that silently returns
#     nothing.
#   * Tables are singular, columns are snake_case, times end in `_at` and byte counts in `_bytes`.
#   * Times are INTEGER Unix MICROSECONDS UTC (core.Micros). Never a string, never seconds: two
#     releases submitted in the same second must still order.
#   * Booleans are INTEGER with a CHECK (x IN (0,1)). Enums are TEXT with a CHECK, lowercase
#     snake_case, spelled identically in the DB, the JSON and the OpenAPI document.
#   * Internal primary keys are ULIDs in TEXT (core.ULID). The plugin id is the exception and is
#     the plugin's own permanent identifier — see the `plugin` table.
#
# TWO THINGS THIS FILE CANNOT SAY, AND WHERE THEY LIVE INSTEAD
#
#   1. TRIGGERS. The community build of Atlas does not model them: a `trigger` block here is parsed
#      and then silently ignored, which is worse than absent because a reader would believe it. The
#      audit_log append-only triggers and the no-delete triggers on plugin and release are
#      therefore authored by hand in the initial migration, and asserted by tests in
#      internal/store that write to a real database and require the abort. They are named in
#      docs/concepts/invariants.md. Atlas replays the migration directory to compute a diff, so it
#      sees those triggers in the dev database and leaves them alone — verified, not assumed.
#
#   2. ENUM VALUES GENERATED FROM GO. Canonical §4 wants the CHECK lists written from the Go
#      constants by `make gen`, between GENERATED markers. That generator is the authz catalogue
#      and lands in Phase 2; until then the lists below are hand-written and are the source. When
#      the generator arrives, these CHECKs move between markers rather than growing a second home.
#
# WHY SOME COLUMNS ARE NOT NAMED AFTER THE WIRE FIELD THEY CARRY
#
# `sdk_specifier` and `minimum_app_version` hold what the index document calls something else.
# That is deliberate: gate SCHEMA002 keeps the wire-format field names inside internal/registry,
# and sqlc writes column names into Go string literals in internal/store/sqlitegen — so a column
# named after a wire field would smuggle the wire format into a second package and fail the gate.
# The database describes a release; internal/registry decides how a release is spelled to a client.

schema "main" {}

# --- account, identity ---------------------------------------------------------------------------

# An account is the thing that owns plugins and holds tokens (ADR-0003). It is deliberately NOT a
# GitHub user: identities are how you prove you are an account, and an account may hold several.
table "account" {
  schema = schema.main
  strict = true

  column "id" {
    null = false
    type = text
  }
  # Cached decoration refreshed on login, never an identifier. Handles change; subjects do not.
  column "display_name" {
    null    = false
    type    = text
    default = ""
  }
  column "created_at" {
    null = false
    type = integer
  }
  column "updated_at" {
    null = false
    type = integer
  }
  # A disabled account keeps every row it owns. Deleting one would orphan plugin ids, and an
  # orphaned id must never become claimable by somebody else.
  column "disabled_at" {
    null = true
    type = integer
  }

  primary_key {
    columns = [column.id]
  }
}

# One row per identity provider. GitHub is the only one (ADR-0011).
table "identity_provider" {
  schema = schema.main
  strict = true

  column "kind" {
    null = false
    type = text
  }
  column "display_name" {
    null = false
    type = text
  }
  # Whether an identity from this provider may publish. ADR-0004 hangs off this being a CHECK
  # against `kind` rather than a column an operator can set: an operator toggle is a row somebody
  # can UPDATE at 2am, and the whole point is that publishing requires a GitHub identity.
  column "can_publish" {
    null = false
    type = integer
  }
  column "created_at" {
    null = false
    type = integer
  }

  primary_key {
    columns = [column.kind]
  }

  # GitHub is the only provider that exists. Adding a second one is a migration plus a package
  # (ADR-0011's reversal cost), and this CHECK is what makes that a deliberate act.
  check "identity_provider_kind_enum" {
    expr = "kind IN ('github')"
  }
  check "identity_provider_can_publish_boolean" {
    expr = "can_publish IN (0, 1)"
  }
  # A provider added later is non-publishing until somebody argues otherwise in a pull request.
  check "identity_provider_only_github_publishes" {
    expr = "can_publish = 0 OR kind = 'github'"
  }
}

# A way to prove you are an account. `subject` is the provider's immutable numeric id — a GitHub
# node id — and NEVER the handle, which users change (ADR-0003).
table "identity" {
  schema = schema.main
  strict = true

  column "id" {
    null = false
    type = text
  }
  column "account_id" {
    null = false
    type = text
  }
  column "provider_kind" {
    null = false
    type = text
  }
  column "subject" {
    null = false
    type = text
  }
  # The handle as it was at the last login. Decoration for humans reading a log; never matched on.
  column "handle" {
    null    = false
    type    = text
    default = ""
  }
  column "linked_at" {
    null = false
    type = integer
  }
  column "refreshed_at" {
    null = false
    type = integer
  }

  primary_key {
    columns = [column.id]
  }
  foreign_key "identity_account_fk" {
    columns     = [column.account_id]
    ref_columns = [table.account.column.id]
    on_update   = NO_ACTION
    on_delete   = RESTRICT
  }
  foreign_key "identity_provider_fk" {
    columns     = [column.provider_kind]
    ref_columns = [table.identity_provider.column.kind]
    on_update   = NO_ACTION
    on_delete   = RESTRICT
  }
  # One account per (provider, subject). Without this, a second sign-in with the same GitHub
  # account could mint a second account and split ownership of the same person's plugins.
  index "identity_provider_subject_key" {
    unique  = true
    columns = [column.provider_kind, column.subject]
  }
  index "identity_account_idx" {
    columns = [column.account_id]
  }
  check "identity_subject_not_empty" {
    expr = "length(subject) > 0"
  }
}

# --- browser sessions and the OAuth handshake -----------------------------------------------------

# A browser session. It is the ONLY credential that satisfies a capability-floor operation
# (canonical §5): minting a token, changing owners and setting trust are session-only, because a
# token that could perform one would be equivalent to the account.
#
# The cookie carries a random secret; this table stores HMAC-SHA256(pepper, secret) and never the
# secret itself. A stolen database therefore does not hand over live sessions, which is the same
# argument the PAT storage makes and for the same reason: the pepper is in the environment, the
# rows are on the disk, and the two are not compromised together.
table "session" {
  schema = schema.main
  strict = true

  column "id" {
    null = false
    type = text
  }
  column "account_id" {
    null = false
    type = text
  }
  # HMAC-SHA256 of the cookie secret, lowercase hex. NEVER the secret, and never the session id
  # either -- the id is what a log line would carry, and canonical §10 forbids logging it.
  column "token_hash" {
    null = false
    type = text
  }
  column "created_at" {
    null = false
    type = integer
  }
  # Refreshed lazily rather than on every request: this database has one writer, and a write per
  # authenticated request would put session bookkeeping in front of every publish.
  column "last_seen_at" {
    null = false
    type = integer
  }
  # Absolute, not sliding. A session that renews itself forever is a credential with no expiry.
  column "expires_at" {
    null = false
    type = integer
  }
  # Set by logout and by a future "sign out everywhere". Rows are kept rather than deleted so that
  # "when did this session end, and was it ended or did it lapse" stays answerable.
  column "revoked_at" {
    null = true
    type = integer
  }

  primary_key {
    columns = [column.id]
  }
  foreign_key "session_account_fk" {
    columns     = [column.account_id]
    ref_columns = [table.account.column.id]
    on_update   = NO_ACTION
    on_delete   = RESTRICT
  }
  # The lookup on every authenticated request, and a uniqueness guarantee: two live sessions
  # cannot share a secret, so a collision is a constraint violation rather than a shared account.
  index "session_token_hash_key" {
    unique  = true
    columns = [column.token_hash]
  }
  index "session_account_idx" {
    columns = [column.account_id]
  }
  # 64 lowercase hex characters. The GLOB is negated because SQLite has no regex: "contains no
  # character outside 0-9a-f". A row that is not a hex digest is one nothing could have written.
  check "session_token_hash_shape" {
    expr = "length(token_hash) = 64 AND NOT token_hash GLOB '*[^0-9a-f]*'"
  }
  check "session_expires_after_it_starts" {
    expr = "expires_at > created_at"
  }
}

# One in-flight OAuth handshake: the `state` nonce and the PKCE verifier that go with it.
#
# The row is short-lived and single-use. It is a TABLE rather than a signed cookie because
# single-use is the property that matters: a cookie can be replayed, and a row that is deleted when
# it is redeemed cannot be. Deleting from this table is allowed -- it holds no history, and that is
# why it has no no-delete trigger.
table "oauth_flow" {
  schema = schema.main
  strict = true

  # HMAC-SHA256(pepper, state), lowercase hex. The browser holds the state itself, in a cookie and
  # in the URL GitHub redirects to; this side holds only a keyed hash, so a database dump cannot
  # complete somebody else's login.
  column "state_hash" {
    null = false
    type = text
  }
  column "provider_kind" {
    null = false
    type = text
  }
  # The PKCE verifier, which has to be sent to the provider verbatim and therefore cannot be
  # hashed. It is single-use and expires in minutes, and the row is deleted when it is redeemed.
  column "code_verifier" {
    null = false
    type = text
  }
  # Where to send the browser after a successful login. Validated as a same-site absolute PATH
  # before it is stored -- an open redirect on a login callback is a phishing primitive.
  column "redirect_to" {
    null    = false
    type    = text
    default = ""
  }
  column "created_at" {
    null = false
    type = integer
  }
  column "expires_at" {
    null = false
    type = integer
  }

  primary_key {
    columns = [column.state_hash]
  }
  foreign_key "oauth_flow_provider_fk" {
    columns     = [column.provider_kind]
    ref_columns = [table.identity_provider.column.kind]
    on_update   = NO_ACTION
    on_delete   = RESTRICT
  }
  # Swept whenever a flow starts, so an abandoned login does not accumulate.
  index "oauth_flow_expires_at_idx" {
    columns = [column.expires_at]
  }
  check "oauth_flow_state_hash_shape" {
    expr = "length(state_hash) = 64 AND NOT state_hash GLOB '*[^0-9a-f]*'"
  }
  # A verifier shorter than this is not PKCE, it is a guessable string. RFC 7636 puts the floor at
  # 43 characters and the ceiling at 128.
  check "oauth_flow_code_verifier_length" {
    expr = "length(code_verifier) BETWEEN 43 AND 128"
  }
  # Same-site paths only: one leading slash, and the second character is neither another slash nor
  # a backslash (char(92)). `//evil.example` is protocol-relative and `/\evil.example` is
  # normalised to it by several browsers, so both are absolute URLs wearing a path's clothes — and
  # an open redirect on a login callback is a phishing primitive, not a cosmetic bug.
  check "oauth_flow_redirect_is_a_local_path" {
    expr = "redirect_to = '' OR (substr(redirect_to, 1, 1) = '/' AND substr(redirect_to, 2, 1) NOT IN ('/', char(92)))"
  }
  check "oauth_flow_expires_after_it_starts" {
    expr = "expires_at > created_at"
  }
}

# --- the catalogue -------------------------------------------------------------------------------

# A plugin id is permanent, first-come, and NEVER recycled: it is the plugin's identity in every
# installed copy on every user's machine, and handing a used id to somebody else is how you ship an
# update to another author's users.
#
# So the row IS the claim. There is no separate claim table and no DELETE: delisting sets
# delisted_at, which removes the listing and keeps the id spoken for. A BEFORE DELETE trigger
# (authored in the initial migration) aborts any attempt to remove one.
table "plugin" {
  schema = schema.main
  strict = true

  # The plugin's own id, not a ULID — it is not ours to mint. The authoritative pattern is
  # core.PluginID, mirroring the SDK's; the CHECK below is a floor that stops an empty or absurd
  # value reaching the table, not a second copy of the regex.
  column "id" {
    null = false
    type = text
  }
  column "name" {
    null = false
    type = text
  }
  column "description" {
    null    = false
    type    = text
    default = ""
  }
  column "author" {
    null    = false
    type    = text
    default = ""
  }
  column "homepage" {
    null    = false
    type    = text
    default = ""
  }
  column "claimed_at" {
    null = false
    type = integer
  }
  column "updated_at" {
    null = false
    type = integer
  }
  # NULL means listed. A delisted plugin keeps its row, its releases and its owners.
  column "delisted_at" {
    null = true
    type = integer
  }
  # A listing that vanishes without a stated reason is indistinguishable from a bug, so the reason
  # is not optional — the CHECK below requires it.
  column "delisted_reason" {
    null = true
    type = text
  }

  primary_key {
    columns = [column.id]
  }
  check "plugin_id_length" {
    expr = "length(id) BETWEEN 2 AND 40"
  }
  check "plugin_name_not_empty" {
    expr = "length(name) > 0"
  }
  check "plugin_delisting_states_its_reason" {
    expr = "((delisted_at IS NULL AND delisted_reason IS NULL) OR (delisted_at IS NOT NULL AND delisted_reason IS NOT NULL))"
  }
}

# Every submitted release is a row here and stays (ADR-0010). The wire format carries only the
# current one; the database carries all of them, because what the server discards it cannot audit.
table "release" {
  schema = schema.main
  strict = true

  column "id" {
    null = false
    type = text
  }
  column "plugin_id" {
    null = false
    type = text
  }
  column "version" {
    null = false
    type = text
  }
  column "state" {
    null = false
    type = text
  }
  # How this row came to exist. An imported row carries a hash THIS SERVER DID NOT COMPUTE — it
  # came from the static registry, where a human reviewed it in a pull request. That distinction is
  # the difference between "we checked these bytes" and "somebody else did", and it must be
  # readable years later rather than inferred from a missing verified_at.
  column "source" {
    null = false
    type = text
  }
  # The URL is transport. The hash is the security boundary (ADR-0008).
  column "artifact_url" {
    null = false
    type = text
  }
  # NULL until the bytes have been fetched and hashed. A release cannot be approved without one —
  # see the CHECK. Never populated from a submitted value.
  column "artifact_sha256" {
    null = true
    type = text
  }
  column "artifact_bytes" {
    null = true
    type = integer
  }
  # A PEP 440 specifier the client evaluates; we only carry it. See the header on why it is not
  # named after the wire field.
  column "sdk_specifier" {
    null = false
    type = text
  }
  column "minimum_app_version" {
    null = true
    type = text
  }
  # NULL for a row that no account submitted: an imported one, and later a maintainer action taken
  # against a plugin whose owner has not yet registered.
  column "submitted_by" {
    null = true
    type = text
  }
  column "submitted_at" {
    null = false
    type = integer
  }
  # When THIS server fetched the artifact and computed the hash above.
  column "verified_at" {
    null = true
    type = integer
  }
  column "reviewed_by" {
    null = true
    type = text
  }
  column "reviewed_at" {
    null = true
    type = integer
  }
  # Why it was quarantined, rejected or approved. Read by a human during an incident.
  column "review_note" {
    null = true
    type = text
  }

  primary_key {
    columns = [column.id]
  }
  foreign_key "release_plugin_fk" {
    columns     = [column.plugin_id]
    ref_columns = [table.plugin.column.id]
    on_update   = NO_ACTION
    on_delete   = RESTRICT
  }
  foreign_key "release_submitted_by_fk" {
    columns     = [column.submitted_by]
    ref_columns = [table.account.column.id]
    on_update   = NO_ACTION
    on_delete   = RESTRICT
  }
  foreign_key "release_reviewed_by_fk" {
    columns     = [column.reviewed_by]
    ref_columns = [table.account.column.id]
    on_update   = NO_ACTION
    on_delete   = RESTRICT
  }

  # A version is used once per plugin, ever. Rows are never deleted, so a version cannot be quietly
  # reused after a delisting to ship different bytes under a number a client has already seen.
  index "release_plugin_version_key" {
    unique  = true
    columns = [column.plugin_id, column.version]
  }
  # AT MOST ONE APPROVED RELEASE PER PLUGIN. `latest` on the wire is derived from this row, and
  # ADR-0010 names the derivation as the risk it accepts: a bug there is a bug in what every user
  # downloads. This index makes the ambiguous case unrepresentable rather than unlikely.
  index "release_one_approved_per_plugin" {
    unique  = true
    columns = [column.plugin_id]
    where   = "state = 'approved'"
  }

  check "release_state_enum" {
    expr = "state IN ('pending', 'approved', 'rejected', 'superseded')"
  }
  check "release_source_enum" {
    expr = "source IN ('publish', 'import')"
  }
  check "release_version_not_empty" {
    expr = "length(version) > 0"
  }
  # The client refuses anything else, and so does the CI job this server replaces. An http:// URL
  # in this column could never be served, so it is not allowed to be stored.
  check "release_artifact_url_https" {
    expr = "artifact_url LIKE 'https://%'"
  }
  # 64 lowercase hex characters, mirroring what the client's parser accepts. The GLOB is negated
  # because SQLite has no regex: "contains no character outside 0-9a-f".
  check "release_artifact_sha256_shape" {
    expr = "artifact_sha256 IS NULL OR (length(artifact_sha256) = 64 AND NOT artifact_sha256 GLOB '*[^0-9a-f]*')"
  }
  check "release_artifact_bytes_non_negative" {
    expr = "artifact_bytes IS NULL OR artifact_bytes >= 0"
  }
  # An approved release without a hash is a release nobody can verify. The trust model is that the
  # hash is the security boundary; a NULL here would make it optional.
  check "release_approved_has_a_hash" {
    expr = "state <> 'approved' OR artifact_sha256 IS NOT NULL"
  }
}

# --- ownership and trust ---------------------------------------------------------------------------

# Who may change a plugin's listing. Checked per request at the moment of publish rather than
# cascade-revoked, so removing an owner takes effect on their next call (ADR-0005).
table "plugin_owner" {
  schema = schema.main
  strict = true

  column "plugin_id" {
    null = false
    type = text
  }
  column "account_id" {
    null = false
    type = text
  }
  column "role" {
    null = false
    type = text
  }
  column "granted_at" {
    null = false
    type = integer
  }
  # NULL when the grant was made by the system — the import of the static registry's owners.json,
  # for one, where no account performed the action.
  column "granted_by" {
    null = true
    type = text
  }

  primary_key {
    columns = [column.plugin_id, column.account_id]
  }
  foreign_key "plugin_owner_plugin_fk" {
    columns     = [column.plugin_id]
    ref_columns = [table.plugin.column.id]
    on_update   = NO_ACTION
    on_delete   = RESTRICT
  }
  foreign_key "plugin_owner_account_fk" {
    columns     = [column.account_id]
    ref_columns = [table.account.column.id]
    on_update   = NO_ACTION
    on_delete   = RESTRICT
  }
  foreign_key "plugin_owner_granted_by_fk" {
    columns     = [column.granted_by]
    ref_columns = [table.account.column.id]
    on_update   = NO_ACTION
    on_delete   = RESTRICT
  }
  index "plugin_owner_account_idx" {
    columns = [column.account_id]
  }
  check "plugin_owner_role_enum" {
    expr = "role IN ('owner', 'maintainer')"
  }
}

# The trust tier that decides whether a version bump of an ALREADY-APPROVED plugin publishes
# without a human (ADR-0007). It never applies to a new plugin id: the first appearance of an id is
# always reviewed, by anyone, at any tier.
#
# A row is a deliberate act by a maintainer. An account with no row is at the floor — trust is
# never raised automatically, because a counter of successful publishes is a counter an attacker
# can run up.
table "account_trust" {
  schema = schema.main
  strict = true

  column "account_id" {
    null = false
    type = text
  }
  column "level" {
    null = false
    type = text
  }
  column "set_at" {
    null = false
    type = integer
  }
  # NULL only for a level set by the system. Setting trust is in the capability floor (canonical
  # §5): it is session-only and no token can do it, so a row with a NULL here that was not written
  # by a migration is a bug worth noticing.
  column "set_by" {
    null = true
    type = text
  }
  # Why. A trust level with no stated reason is one nobody can review later.
  column "note" {
    null = true
    type = text
  }

  primary_key {
    columns = [column.account_id]
  }
  foreign_key "account_trust_account_fk" {
    columns     = [column.account_id]
    ref_columns = [table.account.column.id]
    on_update   = NO_ACTION
    on_delete   = RESTRICT
  }
  foreign_key "account_trust_set_by_fk" {
    columns     = [column.set_by]
    ref_columns = [table.account.column.id]
    on_update   = NO_ACTION
    on_delete   = RESTRICT
  }
  # `new` is the floor and the default for an account with no row at all. `blocked` is below it:
  # an explicit refusal, not an absence.
  check "account_trust_level_enum" {
    expr = "level IN ('blocked', 'new', 'trusted')"
  }
}

# --- the audit log ---------------------------------------------------------------------------------

# APPEND-ONLY. Corrections are new rows, never an UPDATE and never a DELETE — BEFORE UPDATE and
# BEFORE DELETE triggers in the initial migration abort either, and tests assert that they fire.
#
# This is the evidence the trust model is built on: "who approved these exact bytes, and when" has
# to be answerable years later, including in the case where the person answering is the person
# under suspicion.
table "audit_log" {
  schema = schema.main
  strict = true

  column "id" {
    null = false
    type = text
  }
  column "recorded_at" {
    null = false
    type = integer
  }
  column "actor_kind" {
    null = false
    type = text
  }
  # NULL exactly when actor_kind is 'system' — a migration, or the boot-time import of the static
  # catalogue. The CHECK below keeps those two facts from disagreeing.
  column "actor_account_id" {
    null = true
    type = text
  }
  # What happened. Free text until the authz catalogue generates the vocabulary in Phase 2; a CHECK
  # written by hand now would be a second source for a list that is about to have a generator.
  column "action" {
    null = false
    type = text
  }
  column "subject_kind" {
    null = false
    type = text
  }
  column "subject_id" {
    null = true
    type = text
  }
  # A JSON object with whatever the action needs. NEVER a token secret, a session id, an OAuth
  # access token, a client secret or the pepper: this table is the one nobody can redact later.
  column "detail" {
    null = true
    type = text
  }

  primary_key {
    columns = [column.id]
  }
  foreign_key "audit_log_actor_fk" {
    columns     = [column.actor_account_id]
    ref_columns = [table.account.column.id]
    on_update   = NO_ACTION
    on_delete   = RESTRICT
  }
  index "audit_log_recorded_at_idx" {
    columns = [column.recorded_at]
  }
  index "audit_log_subject_idx" {
    columns = [column.subject_kind, column.subject_id]
  }
  check "audit_log_actor_kind_enum" {
    expr = "actor_kind IN ('account', 'system')"
  }
  check "audit_log_actor_matches_kind" {
    expr = "((actor_kind = 'account' AND actor_account_id IS NOT NULL) OR (actor_kind = 'system' AND actor_account_id IS NULL))"
  }
  check "audit_log_action_not_empty" {
    expr = "length(action) > 0"
  }
}
