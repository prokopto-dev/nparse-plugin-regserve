package store_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// The schema is where most of this service's invariants actually live: the append-only triggers,
// the CHECK constraints, the partial unique index that makes "the approved release" singular.
//
// Every test below reaches the database with raw SQL rather than through the typed query set. That
// is the point. A guarantee that only holds for statements this repository happens to generate is
// not a guarantee — the next phase, a migration, or a hand-run UPDATE during an incident will not
// go through sqlc.

const (
	// A claimed, listed plugin, and an approved release of it. Times are arbitrary microseconds.
	seedPlugin = `INSERT INTO plugin (id, name, claimed_at, updated_at)
	              VALUES ('merchant-mode', 'Merchant Mode', 1700000000000000, 1700000000000000)`
	seedRelease = `INSERT INTO "release" (id, plugin_id, version, state, source, artifact_url,
	                   artifact_sha256, sdk_specifier, submitted_at)
	               VALUES ('01ARZ3NDEKTSV4RRFFQ69G5FAV', 'merchant-mode', '1.0.0', 'approved', 'import',
	                   'https://example.com/merchant-mode.zip',
	                   'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
	                   '>=1.0,<2', 1700000000000000)`
	seedAudit = `INSERT INTO audit_log (id, recorded_at, actor_kind, action, subject_kind, subject_id)
	             VALUES ('01ARZ3NDEKTSV4RRFFQ69G5FAW', 1700000000000000, 'system', 'catalogue.import',
	                 'catalogue', NULL)`
)

// TestSchema_RefusedStatements — one row per invariant the database itself enforces.
//
// A rule without a mechanism is a wish, and a mechanism nobody has watched fail is a rule nobody
// knows is enforced. Each case here is a statement that MUST be refused, and the assertion is on
// the message SQLite produces, so a constraint that gets renamed away is a red test rather than a
// quiet loss of coverage.
func TestSchema_RefusedStatements(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		why  string
		// setup runs first and must succeed.
		setup []string
		// stmt must fail.
		stmt    string
		wantErr string
	}{
		{
			name:    "audit_log cannot be updated",
			why:     "corrections are new rows; the log is the evidence the trust model rests on",
			setup:   []string{seedAudit},
			stmt:    `UPDATE audit_log SET action = 'something.else'`,
			wantErr: "append-only",
		},
		{
			name:    "audit_log cannot be deleted from",
			why:     "the row a compromise investigation needs is the one somebody would want gone",
			setup:   []string{seedAudit},
			stmt:    `DELETE FROM audit_log`,
			wantErr: "append-only",
		},
		{
			name:    "a plugin row cannot be deleted",
			why:     "the row is the id claim, and a recycled id ships an update to somebody else's users",
			setup:   []string{seedPlugin},
			stmt:    `DELETE FROM plugin WHERE id = 'merchant-mode'`,
			wantErr: "never recycled",
		},
		{
			name:    "a release row cannot be deleted",
			why:     "history is kept even though only latest ships (ADR-0010); superseding is a state change",
			setup:   []string{seedPlugin, seedRelease},
			stmt:    `DELETE FROM "release"`,
			wantErr: "history is kept",
		},
		{
			name:  "a second approved release of one plugin",
			why:   "latest on the wire is derived from exactly one row; two makes it arbitrary",
			setup: []string{seedPlugin, seedRelease},
			stmt: `INSERT INTO "release" (id, plugin_id, version, state, source, artifact_url,
			           artifact_sha256, sdk_specifier, submitted_at)
			       VALUES ('01ARZ3NDEKTSV4RRFFQ69G5FB0', 'merchant-mode', '2.0.0', 'approved', 'publish',
			           'https://example.com/merchant-mode-2.zip',
			           'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
			           '>=1.0,<2', 1700000000000001)`,
			wantErr: "UNIQUE constraint failed: release.plugin_id",
		},
		{
			name:  "a version number reused for one plugin",
			why:   "a version cannot be quietly reused after a delisting to ship different bytes",
			setup: []string{seedPlugin, seedRelease},
			stmt: `INSERT INTO "release" (id, plugin_id, version, state, source, artifact_url,
			           sdk_specifier, submitted_at)
			       VALUES ('01ARZ3NDEKTSV4RRFFQ69G5FB1', 'merchant-mode', '1.0.0', 'pending', 'publish',
			           'https://example.com/other.zip', '>=1.0,<2', 1700000000000001)`,
			wantErr: "UNIQUE constraint failed: release.plugin_id, release.version",
		},
		{
			name:  "an approved release with no hash",
			why:   "the hash is the security boundary; approving without one makes it optional",
			setup: []string{seedPlugin},
			stmt: `INSERT INTO "release" (id, plugin_id, version, state, source, artifact_url,
			           sdk_specifier, submitted_at)
			       VALUES ('01ARZ3NDEKTSV4RRFFQ69G5FB2', 'merchant-mode', '3.0.0', 'approved', 'publish',
			           'https://example.com/x.zip', '>=1.0,<2', 1700000000000001)`,
			wantErr: "release_approved_has_a_hash",
		},
		{
			name:  "an artifact URL that is not https",
			why:   "the client refuses it, so a row that could never be served is not allowed to exist",
			setup: []string{seedPlugin},
			stmt: `INSERT INTO "release" (id, plugin_id, version, state, source, artifact_url,
			           sdk_specifier, submitted_at)
			       VALUES ('01ARZ3NDEKTSV4RRFFQ69G5FB3', 'merchant-mode', '4.0.0', 'pending', 'publish',
			           'http://example.com/x.zip', '>=1.0,<2', 1700000000000001)`,
			wantErr: "release_artifact_url_https",
		},
		{
			name:  "a sha256 that is not 64 lowercase hex characters",
			why:   "the client lower-cases before matching; we store the strict form or nothing",
			setup: []string{seedPlugin},
			stmt: `INSERT INTO "release" (id, plugin_id, version, state, source, artifact_url,
			           artifact_sha256, sdk_specifier, submitted_at)
			       VALUES ('01ARZ3NDEKTSV4RRFFQ69G5FB4', 'merchant-mode', '5.0.0', 'pending', 'publish',
			           'https://example.com/x.zip',
			           'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
			           '>=1.0,<2', 1700000000000001)`,
			wantErr: "release_artifact_sha256_shape",
		},
		{
			name:  "a release of a plugin that was never claimed",
			why:   "foreign keys are OFF by default in SQLite, per connection, forever",
			setup: nil,
			stmt: `INSERT INTO "release" (id, plugin_id, version, state, source, artifact_url,
			           sdk_specifier, submitted_at)
			       VALUES ('01ARZ3NDEKTSV4RRFFQ69G5FB5', 'never-claimed', '1.0.0', 'pending', 'publish',
			           'https://example.com/x.zip', '>=1.0,<2', 1700000000000001)`,
			wantErr: "FOREIGN KEY constraint failed",
		},
		{
			name:    "a delisting with no stated reason",
			why:     "a listing that vanishes without explanation is indistinguishable from a bug",
			setup:   []string{seedPlugin},
			stmt:    `UPDATE plugin SET delisted_at = 1700000000000001 WHERE id = 'merchant-mode'`,
			wantErr: "plugin_delisting_states_its_reason",
		},
		{
			name: "a second identity provider",
			why:  "GitHub is the only provider (ADR-0011); adding one is a migration and a package",
			stmt: `INSERT INTO identity_provider (kind, display_name, can_publish, created_at)
			       VALUES ('discord', 'Discord', 0, 1700000000000000)`,
			wantErr: "identity_provider_kind_enum",
		},
		{
			name:    "a non-github provider that may publish",
			why:     "can_publish is a CHECK against kind, not a column an operator can set",
			stmt:    `UPDATE identity_provider SET kind = 'discord', can_publish = 1 WHERE kind = 'github'`,
			wantErr: "identity_provider_kind_enum",
		},
		{
			name: "a system audit row that names an actor account",
			why:  "actor_kind and actor_account_id must not be able to disagree about who acted",
			stmt: `INSERT INTO audit_log (id, recorded_at, actor_kind, actor_account_id, action, subject_kind)
			       VALUES ('01ARZ3NDEKTSV4RRFFQ69G5FB6', 1700000000000000, 'system', '01ARZ3NDEKTSV4RRFFQ69G5FB7',
			           'catalogue.import', 'catalogue')`,
			wantErr: "audit_log_actor_matches_kind",
		},
		{
			name:    "text in an integer column",
			why:     "every table is STRICT; without it SQLite stores the string and the query that reads it returns nothing",
			stmt:    `INSERT INTO plugin (id, name, claimed_at, updated_at) VALUES ('a-plugin', 'A', 'yesterday', 1)`,
			wantErr: "cannot store TEXT value in INTEGER column",
		},
		{
			name:    "a plugin id that is too short to be legal",
			why:     "a floor under core.PluginID, so a bug writing an empty id cannot reach the table",
			stmt:    `INSERT INTO plugin (id, name, claimed_at, updated_at) VALUES ('a', 'A', 1, 1)`,
			wantErr: "plugin_id_length",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw := openRaw(t, storetest.New(t).Path())
			for _, s := range tc.setup {
				_, err := raw.ExecContext(t.Context(), s)
				require.NoError(t, err, "setup failed, so the case below proves nothing")
			}

			_, err := raw.ExecContext(t.Context(), tc.stmt)
			require.Error(t, err, "the database accepted a statement it must refuse: %s", tc.why)
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// TestSchema_GitHubIsSeededAsTheOnlyProvider — the row is inserted by the migration rather than by
// application code, so this is what proves a fresh database can authenticate anybody at all.
func TestSchema_GitHubIsSeededAsTheOnlyProvider(t *testing.T) {
	t.Parallel()

	raw := openRaw(t, storetest.New(t).Path())

	var kind string
	var canPublish int
	var count int
	require.NoError(t, raw.QueryRowContext(t.Context(),
		`SELECT count(*) FROM identity_provider`).Scan(&count))
	require.Equal(t, 1, count, "exactly one provider ships (ADR-0011)")

	require.NoError(t, raw.QueryRowContext(t.Context(),
		`SELECT kind, can_publish FROM identity_provider`).Scan(&kind, &canPublish))
	require.Equal(t, "github", kind)
	require.Equal(t, 1, canPublish)
}

// TestSchema_AuditLogInsert_IsAllowed — the append-only triggers must refuse UPDATE and DELETE and
// nothing else. A trigger that also blocked INSERT would make the log unwritable, which is the
// failure that looks identical to "we forgot to log it".
func TestSchema_AuditLogInsert_IsAllowed(t *testing.T) {
	t.Parallel()

	raw := openRaw(t, storetest.New(t).Path())

	_, err := raw.ExecContext(t.Context(), seedAudit)
	require.NoError(t, err)

	var n int
	require.NoError(t, raw.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_log`).Scan(&n))
	require.Equal(t, 1, n)
}

// TestSchema_DelistingWithAReason_IsAllowed — the counterpart to the refusal above. Delisting has
// to remain possible, or the constraint has quietly turned "state your reason" into "you cannot
// delist", and nobody finds out until a plugin needs pulling.
func TestSchema_DelistingWithAReason_IsAllowed(t *testing.T) {
	t.Parallel()

	raw := openRaw(t, storetest.New(t).Path())
	_, err := raw.ExecContext(t.Context(), seedPlugin)
	require.NoError(t, err)

	_, err = raw.ExecContext(t.Context(),
		`UPDATE plugin SET delisted_at = 1700000000000001, delisted_reason = 'author request'
		 WHERE id = 'merchant-mode'`)
	require.NoError(t, err)
}
