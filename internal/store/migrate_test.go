package store_test

import (
	"database/sql"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/db"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

func embeddedMigrations(t *testing.T) []string {
	t.Helper()

	names, err := fs.Glob(db.MigrationsSQLite, filepath.Join(db.MigrationsSQLiteDir, "*.sql"))
	require.NoError(t, err)
	require.NotEmpty(t, names, "no migrations are embedded; the go:embed pattern matched nothing")
	return names
}

// TestMigrate_FreshDatabase_AppliesEveryEmbeddedMigration — the deployment story is that the
// shipped binary migrates itself with nothing installed alongside it (ADR-0006). If the embed
// pattern ever stops matching, this is the test that says so; the alternative is a container that
// starts, finds no tables, and reports an empty catalogue to every installed client.
func TestMigrate_FreshDatabase_AppliesEveryEmbeddedMigration(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "regserve.db")
	dbase, err := store.Open(t.Context(), store.Config{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, dbase.Close()) })

	out, err := dbase.Migrate(t.Context())
	require.NoError(t, err)
	require.Len(t, out.Applied, len(embeddedMigrations(t)))
	require.Positive(t, out.Version)

	// The schema is usable afterwards, not merely recorded as applied.
	n, err := dbase.Read().CountPlugins(t.Context())
	require.NoError(t, err)
	require.Zero(t, n)
}

// TestMigrate_AlreadyCurrent_AppliesNothing — every restart runs this. A migration that re-ran
// would fail on the second CREATE TABLE and crash-loop the container.
func TestMigrate_AlreadyCurrent_AppliesNothing(t *testing.T) {
	t.Parallel()

	dbase := storetest.New(t) // already migrated by the template

	out, err := dbase.Migrate(t.Context())
	require.NoError(t, err)
	require.Empty(t, out.Applied)
	require.Positive(t, out.Version)
}

// TestMigrate_SchemaFromTheFuture_RefusesToStart — the one database condition that is fatal at
// boot (canonical §11).
//
// It means an older binary met a newer database: a rollback where somebody restored the image and
// not the snapshot. Serving anyway would fail one request at a time, on the columns that moved,
// which is the hardest possible incident to read.
func TestMigrate_SchemaFromTheFuture_RefusesToStart(t *testing.T) {
	t.Parallel()

	dbase := storetest.New(t)
	raw := openRaw(t, dbase.Path())

	_, err := raw.ExecContext(t.Context(),
		`INSERT INTO goose_db_version (version_id, is_applied, tstamp)
		 VALUES (99999999999999, 1, CURRENT_TIMESTAMP)`)
	require.NoError(t, err)

	_, err = dbase.Migrate(t.Context())
	require.ErrorIs(t, err, store.ErrSchemaAhead)
	require.ErrorContains(t, err, "99999999999999",
		"the error must name the version, so an operator knows which release to restore")
}

// TestMigrate_DownBlock_CannotRun — migrations are forward-only, and this proves it against SQLite
// rather than against a grep.
//
// Gate MIG002 checks that each Down block CONTAINS RAISE(ABORT, ...). That is a shape check: it
// would pass a file where the abort sat behind a DROP TABLE. This runs the block and requires the
// database to refuse it.
func TestMigrate_DownBlock_CannotRun(t *testing.T) {
	t.Parallel()

	for _, name := range embeddedMigrations(t) {
		t.Run(filepath.Base(name), func(t *testing.T) {
			t.Parallel()

			raw, err := fs.ReadFile(db.MigrationsSQLite, name)
			require.NoError(t, err)

			_, down, found := strings.Cut(string(raw), "-- +goose Down")
			require.True(t, found, "%s has no Down block at all", name)

			var stmts []string
			for _, line := range strings.Split(down, "\n") {
				if trimmed := strings.TrimSpace(line); trimmed != "" && !strings.HasPrefix(trimmed, "--") {
					stmts = append(stmts, trimmed)
				}
			}
			require.NotEmpty(t, stmts, "%s has an empty Down block, which would silently succeed", name)

			conn := openRaw(t, storetest.New(t).Path())
			for _, stmt := range stmts {
				_, err := conn.ExecContext(t.Context(), stmt)
				require.Error(t, err, "a Down statement ran successfully: %s", stmt)
			}
		})
	}
}

// TestMigrate_DuplicateWaitingReleases_AreRetiredBeforeTheIndexIsAdded.
//
// release_one_pending_per_plugin cannot simply be added: the live database ALREADY holds the rows
// it forbids, which is how the defect was found -- the review queue showed one plugin id several
// times. So the migration before it retires the stale ones, and this drives goose to exactly the
// version before that pair and then forward, because that ordering is the whole reason there are
// two files and a fresh database can never exercise it.
func TestMigrate_DuplicateWaitingReleases_AreRetiredBeforeTheIndexIsAdded(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "regserve.db")
	raw := openRaw(t, path)

	fsys, err := fs.Sub(db.MigrationsSQLite, db.MigrationsSQLiteDir)
	require.NoError(t, err)
	provider, err := goose.NewProvider(goose.DialectSQLite3, raw, fsys,
		goose.WithDisableGlobalRegistry(true))
	require.NoError(t, err)

	// The last schema that permitted several waiting releases of one plugin.
	_, err = provider.UpTo(t.Context(), 20260820142711)
	require.NoError(t, err)

	_, err = raw.ExecContext(t.Context(),
		`INSERT INTO plugin (id, name, claimed_at, updated_at)
		 VALUES ('merchant-mode', 'Merchant Mode', 1700000000000000, 1700000000000000),
		        ('bag-sorter', 'Bag Sorter', 1700000000000000, 1700000000000000)`)
	require.NoError(t, err)

	// Three waiting releases of one plugin and one of another -- the queue as it was reported. The
	// review notes are set because the migration must not touch them: they are the only
	// explanation the author of a superseded submission ever gets.
	_, err = raw.ExecContext(t.Context(),
		`INSERT INTO "release" (id, plugin_id, version, state, source, artifact_url,
		     sdk_specifier, submitted_at, review_note)
		 VALUES ('01ARZ3NDEKTSV4RRFFQ69G5F01', 'merchant-mode', '1.0.0', 'pending', 'publish',
		         'https://example.com/a.zip', '>=1.0,<2', 1700000000000001, 'first release of this id'),
		        ('01ARZ3NDEKTSV4RRFFQ69G5F02', 'merchant-mode', '1.0.1', 'pending', 'publish',
		         'https://example.com/b.zip', '>=1.0,<2', 1700000000000002, 'first release of this id'),
		        ('01ARZ3NDEKTSV4RRFFQ69G5F03', 'merchant-mode', '1.0.2', 'pending', 'publish',
		         'https://example.com/c.zip', '>=1.0,<2', 1700000000000003, 'first release of this id'),
		        ('01ARZ3NDEKTSV4RRFFQ69G5F04', 'bag-sorter', '2.0.0', 'pending', 'publish',
		         'https://example.com/d.zip', '>=1.0,<2', 1700000000000001, 'first release of this id')`)
	require.NoError(t, err)

	_, err = provider.Up(t.Context())
	require.NoError(t, err, "the index was added over rows that violate it")

	require.Equal(t, map[string]string{
		"01ARZ3NDEKTSV4RRFFQ69G5F01": "superseded",
		"01ARZ3NDEKTSV4RRFFQ69G5F02": "superseded",
		// The NEWEST submission of the plugin that had three, and the only one of its plugin left.
		"01ARZ3NDEKTSV4RRFFQ69G5F03": "pending",
		// Untouched: one waiting release was never the problem.
		"01ARZ3NDEKTSV4RRFFQ69G5F04": "pending",
	}, releaseStates(t, raw))

	// Retiring a row is a state change and never a delete (ADR-0010), and the reason each one was
	// waiting survives -- the migration has nothing to add to it that the new state does not say.
	notes := scan(t, raw, `SELECT review_note FROM "release" ORDER BY id`)
	require.Equal(t, []string{
		"first release of this id", "first release of this id",
		"first release of this id", "first release of this id",
	}, notes)
}

// releaseStates maps every release id to its state.
func releaseStates(t *testing.T, raw *sql.DB) map[string]string {
	t.Helper()

	rows, err := raw.QueryContext(t.Context(), `SELECT id, state FROM "release"`)
	require.NoError(t, err)
	defer func() { require.NoError(t, rows.Close()) }()

	out := map[string]string{}
	for rows.Next() {
		var id, state string
		require.NoError(t, rows.Scan(&id, &state))
		out[id] = state
	}
	require.NoError(t, rows.Err())
	return out
}

// scan reads a single-column query into a slice.
func scan(t *testing.T, raw *sql.DB, query string) []string {
	t.Helper()

	rows, err := raw.QueryContext(t.Context(), query)
	require.NoError(t, err)
	defer func() { require.NoError(t, rows.Close()) }()

	var out []string
	for rows.Next() {
		var v string
		require.NoError(t, rows.Scan(&v))
		out = append(out, v)
	}
	require.NoError(t, rows.Err())
	return out
}
