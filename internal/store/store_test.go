package store_test

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// openRaw opens the database file directly, outside the store's pools.
//
// The tests about triggers and CHECK constraints need statements the typed query set deliberately
// does not offer — an UPDATE of audit_log, a DELETE of a plugin. Reaching past the store is the
// point: the guarantee under test is the database's, and it has to hold against SQL that did not
// come through this package.
func openRaw(t *testing.T, path string) *sql.DB {
	t.Helper()

	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	return raw
}

// insertPlugin adds a claimed, listed plugin. Tests that are not about claiming a plugin should
// not have to spell one out.
func insertPlugin(t *testing.T, db *store.DB, id string) {
	t.Helper()

	require.NoError(t, db.Tx(t.Context(), func(q *store.Queries) error {
		return q.InsertPlugin(t.Context(), sqlitegen.InsertPluginParams{
			ID:        id,
			Name:      "Test " + id,
			ClaimedAt: 1_700_000_000_000_000,
			UpdatedAt: 1_700_000_000_000_000,
		})
	}))
}

// TestOpen_NoPath_IsItsOwnError — "the operator did not configure a database" and "the database is
// broken" get the same 503 from /readyz, so they have to be distinguishable in the code that logs
// them. Otherwise the first deploy of this release reads as a corrupted volume.
func TestOpen_NoPath_IsItsOwnError(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"", "   "} {
		_, err := store.Open(t.Context(), store.Config{Path: path})
		require.ErrorIs(t, err, store.ErrNoPath)
	}
}

// TestOpen_FreshPath_CreatesTheFileAt0600 — the file is the entire credential corpus (ADR-0001).
//
// Left to SQLite it would be created at 0666 minus the umask, which on a default umask is
// world-readable: every PAT hash and every OAuth subject readable by any process on the host.
func TestOpen_FreshPath_CreatesTheFileAt0600(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "regserve.db")
	db, err := store.Open(t.Context(), store.Config{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, store.FileMode, info.Mode().Perm())
	require.Equal(t, path, db.Path())
}

// TestOpen_LooseExistingFile_IsTightened — a database restored from a backup, or copied by hand
// during an incident, arrives with whatever permissions the copy gave it. Opening it is where that
// gets noticed, because nothing else in the lifecycle looks.
func TestOpen_LooseExistingFile_IsTightened(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "regserve.db")
	require.NoError(t, os.WriteFile(path, nil, 0o644))

	db, err := store.Open(t.Context(), store.Config{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, store.FileMode, info.Mode().Perm(),
		"an existing database with loose permissions must be tightened, not accepted")
}

// TestOpen_MissingDirectory_Fails — /data not being mounted is the deployment failure this catches.
// Creating the directory instead would put the only copy of the ownership records on the
// container's ephemeral layer, where the next deploy silently discards it.
func TestOpen_MissingDirectory_Fails(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "absent", "regserve.db")
	_, err := store.Open(t.Context(), store.Config{Path: path})
	require.Error(t, err)
	require.ErrorContains(t, err, path, "the error must name the file an operator has to go and fix")
}

// TestTx_CallbackFails_NothingIsCommitted — every mutation here is a set of rows that are only
// correct together: a release and the audit row naming who put it there. A partial commit is a
// database that says something happened and cannot say who did it.
func TestTx_CallbackFails_NothingIsCommitted(t *testing.T) {
	t.Parallel()

	db := storetest.New(t)
	sentinel := errors.New("deliberate failure")

	err := db.Tx(t.Context(), func(q *store.Queries) error {
		if err := q.InsertPlugin(t.Context(), sqlitegen.InsertPluginParams{
			ID: "merchant-mode", Name: "Merchant Mode", ClaimedAt: 1, UpdatedAt: 1,
		}); err != nil {
			return err
		}
		return sentinel
	})
	require.ErrorIs(t, err, sentinel)

	n, err := db.Read().CountPlugins(t.Context())
	require.NoError(t, err)
	require.Zero(t, n, "the row written before the callback failed was committed anyway")
}

// TestTx_Commit_IsVisibleToTheReaderPool — the two pools are two sets of connections onto one file,
// and WAL gives each reader its own snapshot. A commit that a subsequent read cannot see would
// make every publish look like it silently failed.
func TestTx_Commit_IsVisibleToTheReaderPool(t *testing.T) {
	t.Parallel()

	db := storetest.New(t)
	insertPlugin(t, db, "merchant-mode")

	n, err := db.Read().CountPlugins(t.Context())
	require.NoError(t, err)
	require.Equal(t, int64(1), n)
}

// TestRead_IsQueryOnly_AWriteThroughItFails — the reader pool cannot write.
//
// *Queries carries the write methods either way, so nothing in the type system stops a future
// caller from reaching for one on the read path. PRAGMA query_only turns that into an error at the
// first statement instead of a second writer contending with the one the design allows.
func TestRead_IsQueryOnly_AWriteThroughItFails(t *testing.T) {
	t.Parallel()

	db := storetest.New(t)

	err := db.Read().InsertPlugin(t.Context(), sqlitegen.InsertPluginParams{
		ID: "merchant-mode", Name: "Merchant Mode", ClaimedAt: 1, UpdatedAt: 1,
	})
	require.Error(t, err, "the reader pool accepted a write")
	require.ErrorContains(t, err, "readonly")
}

// TestPing_OpenDatabase_AnswersOnBothPools — /readyz is what the deploy asks after it swaps the
// container. A readiness check that only pinged the reader would report a service ready that
// cannot accept a publish.
func TestPing_OpenDatabase_AnswersOnBothPools(t *testing.T) {
	t.Parallel()

	db := storetest.New(t)
	require.NoError(t, db.Ping(t.Context()))
}

// TestPing_ClosedDatabase_Fails — the failure /readyz exists to report.
func TestPing_ClosedDatabase_Fails(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "regserve.db")
	db, err := store.Open(t.Context(), store.Config{Path: path})
	require.NoError(t, err)
	require.NoError(t, db.Close())

	require.Error(t, db.Ping(t.Context()))
}
