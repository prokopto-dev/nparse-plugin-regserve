package store_test

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"

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
