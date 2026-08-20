// Package storetest builds real databases for tests.
//
// There are no mocks of the database anywhere in this repository, and that is deliberate: every
// invariant worth testing here — the append-only triggers, the CHECK constraints, the partial
// unique index that makes "the approved release" singular — lives in SQLite and not in Go. A mock
// would assert that our Go code calls the methods our Go code calls.
//
// The cost of that is migrating a database per test, so this migrates ONE and copies the file. A
// clone is a file copy of a few tens of kilobytes; a migration is every statement in every
// migration ever written, and that bill grows with the project.
package storetest

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
)

// The template is process-wide state, which this repository otherwise bans. It is the one shape
// that cannot be avoided: a memoised fixture has to live somewhere, and threading it through every
// test signature would be worse. It is written exactly once, under sync.Once, and read-only after.
var (
	templateOnce sync.Once
	templateDir  string
	templatePath string
	templateErr  error
)

// Main is the whole body of TestMain in a package that uses this helper:
//
//	func TestMain(m *testing.M) { storetest.Main(m) }
//
// It removes the template database after the tests and then runs the goroutine-leak check. goleak
// runs last on purpose: a database connection that outlives its test shows up here as a leaked
// goroutine, and finding it in CI is the point.
func Main(m *testing.M) {
	code := m.Run()

	if templateDir != "" {
		if err := os.RemoveAll(templateDir); err != nil {
			fmt.Fprintf(os.Stderr, "storetest: remove the template database: %v\n", err) //nolint:forbidigo // TestMain has no *testing.T to report through
			code = 1
		}
	}

	if code == 0 {
		if err := goleak.Find(); err != nil {
			fmt.Fprintf(os.Stderr, "goleak: %v\n", err) //nolint:forbidigo // as above
			code = 1
		}
	}
	os.Exit(code)
}

// New returns an open, migrated, empty database in the test's own directory.
//
// It is closed when the test ends. Each test gets its own file, so tests that write can still run
// in parallel — which matters more than it sounds with a single-writer database: sharing one would
// serialise the suite and let one test's rows become another's mystery.
func New(t *testing.T) *store.DB {
	t.Helper()

	path := filepath.Join(t.TempDir(), "regserve.db")
	clone(t, path)

	db, err := store.Open(t.Context(), store.Config{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })
	return db
}

// Path returns the path of a fresh, migrated database file that is NOT open, for tests that need
// to open it themselves — the ones about opening.
func Path(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "regserve.db")
	clone(t, path)
	return path
}

func clone(t *testing.T, dest string) {
	t.Helper()

	src := templateFile(t)
	// A closed SQLite database in WAL mode has checkpointed and removed its -wal and -shm files,
	// so the single file is the whole database. Copying an OPEN one would not be.
	raw, err := os.ReadFile(src) //nolint:gosec // a path this package created
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(dest, raw, store.FileMode)) //nolint:gosec // dest is built from t.TempDir()
}

func templateFile(t *testing.T) string {
	t.Helper()

	templateOnce.Do(func() {
		templateDir, templateErr = os.MkdirTemp("", "regserve-storetest-")
		if templateErr != nil {
			return
		}
		templatePath = filepath.Join(templateDir, "template.db")

		// context.Background rather than a test's context: the template outlives the test that
		// happened to build it, and a cancelled context would leave every later test looking at a
		// half-migrated file.
		ctx := context.Background()
		db, err := store.Open(ctx, store.Config{Path: templatePath})
		if err != nil {
			templateErr = fmt.Errorf("open the template database: %w", err)
			return
		}
		if _, err := db.Migrate(ctx); err != nil {
			_ = db.Close()
			templateErr = fmt.Errorf("migrate the template database: %w", err)
			return
		}
		// Closing is what checkpoints the WAL into the file being copied.
		if err := db.Close(); err != nil {
			templateErr = fmt.Errorf("close the template database: %w", err)
		}
	})

	require.NoError(t, templateErr)
	return templatePath
}

// Column runs query and returns the first column of every row, as a string.
//
// It exists so that a test in another package can assert what a service WROTE rather than what it
// returned. A helper that read the row back through the same query set could not tell a correct
// row from a consistent misunderstanding — and the values worth checking that way are exactly the
// ones no query selects, because nothing in production has a reason to read them: a stored
// credential hash, for one.
//
// It stays here rather than in the calling package because internal/store is the only tree allowed
// to hold a *sql.DB (gate SQL001), and a test helper that handed one out would be that rule with a
// door in it.
func Column(t *testing.T, db *store.DB, query string, args ...any) []string {
	t.Helper()

	rows, err := raw(t, db).QueryContext(t.Context(), query, args...)
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

// Exec runs a statement that the generated query set deliberately has no method for.
//
// Every use is a test arranging a state the service cannot itself produce — a disabled account, a
// row aged past an expiry. A test that needs this to arrange something the service SHOULD be able
// to do is a test pointing at a missing method.
func Exec(t *testing.T, db *store.DB, stmt string, args ...any) {
	t.Helper()

	_, err := raw(t, db).ExecContext(t.Context(), stmt, args...)
	require.NoError(t, err)
}

// raw opens a second connection to the same file. WAL mode is what makes that safe alongside the
// pools db already holds, and the busy timeout is what makes it wait rather than fail if it meets
// the writer.
func raw(t *testing.T, db *store.DB) *sql.DB {
	t.Helper()

	conn, err := sql.Open("sqlite", "file:"+db.Path()+"?_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, conn.Close()) })
	return conn
}
