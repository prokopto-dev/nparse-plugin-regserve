package store_test

import (
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// GATE BACKUP001 (the half that is about SQLite): copying the main database file out from under a
// running server loses every commit still in the WAL, and `VACUUM INTO` does not.
//
// THIS IS NOT A TEST OF SQLITE FOR ITS OWN SAKE. The pre-deploy snapshot in
// `.github/workflows/deploy.yml` is, by that step's own comment, "the only undo that exists":
// migrations are forward-only (ADR-0006), so a bad release is recovered by restoring that file or
// not at all. It used to be taken with `cp /data/regserve.db` against the RUNNING container, and
// Open sets `journal_mode(WAL)` with `synchronous(NORMAL)` — so a release published minutes before
// a deploy, an id just claimed, a token just minted, all sat in `regserve.db-wal` and were silently
// absent from the backup.
//
// THE PART THAT MAKES IT DANGEROUS RATHER THAN MERELY WRONG is asserted below too: the truncated
// copy is a perfectly VALID SQLite database. It opens, it passes `PRAGMA integrity_check`, it
// answers queries. Nothing about it says it is stale, so it is discovered only by restoring it
// during an incident and finding the last day's writes gone.
//
// The other half of BACKUP001 — that the workflow actually uses this method, and that a failure
// stops the deploy rather than printing a reassuring line — is in test/repo/backup_test.go.
func TestBACKUP001_CopyingTheFileUnderALiveWriter_LosesTheWAL(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "regserve.db")

	// A first open that MIGRATES AND CLOSES. Closing checkpoints, so the schema is in the main file
	// and everything the second open writes is unambiguously WAL-only — which is what makes the
	// row counts below mean "the WAL was lost" rather than "the database was empty anyway".
	db, err := store.Open(t.Context(), store.Config{Path: path})
	require.NoError(t, err)
	_, err = db.Migrate(t.Context())
	require.NoError(t, err)
	require.NoError(t, db.Close())

	// The second open is the droplet: a live server, committing, never closing.
	db, err = store.Open(t.Context(), store.Config{Path: path})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	const committed = 25
	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	for i := range committed {
		require.NoError(t, db.Tx(t.Context(), func(q *store.Queries) error {
			return q.InsertPlugin(t.Context(), sqlitegen.InsertPluginParams{
				ID:        "committed-after-the-checkpoint-" + string(rune('a'+i)),
				Name:      "Committed, not checkpointed",
				ClaimedAt: core.MicrosFromTime(now).Int64(),
				UpdatedAt: core.MicrosFromTime(now).Int64(),
			})
		}))
	}

	// The precondition, asserted rather than assumed. If a future driver or PRAGMA change made
	// these commits land in the main file, every assertion below would pass for the wrong reason
	// and this gate would be reporting green while checking nothing.
	wal, err := os.Stat(path + "-wal")
	require.NoError(t, err, "WAL mode must produce a -wal file, or this gate is inspecting nothing")
	require.NotZero(t, wal.Size(), "the commits above must still be in the WAL, not checkpointed")

	t.Run("cp of the main file loses every uncheckpointed commit", func(t *testing.T) {
		copied := filepath.Join(dir, "by-cp.db")
		copyFile(t, path, copied)

		require.Equal(t, 0, pluginRows(t, copied),
			"a plain copy took the schema and none of the writes; this is what the deploy shipped")

		// And it is VALID. This is the whole reason the defect survived: a stale backup is
		// indistinguishable from a good one by every check short of counting the rows.
		require.Equal(t, "ok", integrityCheck(t, copied),
			"the truncated copy passes integrity_check, which is why nothing caught this")
	})

	t.Run("VACUUM INTO takes the WAL with it", func(t *testing.T) {
		// The statement the deploy runs, against the same live database, through the same SQLite
		// the server is using. It reads one consistent snapshot inside a read transaction, so the
		// writer above is free to carry on.
		snapshot := filepath.Join(dir, "by-vacuum.db")
		require.NoError(t, db.Tx(t.Context(), func(*store.Queries) error { return nil }),
			"sanity: the writer is still live while the snapshot is taken")
		vacuumInto(t, path, snapshot)

		require.Equal(t, committed, pluginRows(t, snapshot),
			"the snapshot must carry the commits that are still in the WAL")
		require.Equal(t, "ok", integrityCheck(t, snapshot))
	})
}

// vacuumInto runs the deploy's statement over a SEPARATE connection to the live database, which is
// how the deploy runs it: a different process entirely, with the server still holding the file.
func vacuumInto(t *testing.T, source, target string) {
	t.Helper()

	raw, err := sql.Open("sqlite", "file:"+source+"?_pragma=busy_timeout(5000)")
	require.NoError(t, err)
	defer func() { require.NoError(t, raw.Close()) }()

	// The path is a bound parameter here and a literal in the workflow, for the same reason each
	// is right where it is: this one comes from t.TempDir, and that one is a constant so the shell
	// quoting in a YAML heredoc has nothing to get wrong.
	_, err = raw.ExecContext(t.Context(), "VACUUM INTO ?", target)
	require.NoError(t, err)
}

// pluginRows opens a snapshot ALONE — no -wal, no -shm beside it — and counts what survived.
//
// Opening it alone is the point: a restore copies one file into place, so what that file holds by
// itself is the entire question.
func pluginRows(t *testing.T, path string) int {
	t.Helper()

	raw, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	require.NoError(t, err)
	defer func() { require.NoError(t, raw.Close()) }()

	var n int
	require.NoError(t, raw.QueryRowContext(t.Context(), `SELECT count(*) FROM plugin`).Scan(&n))
	return n
}

func integrityCheck(t *testing.T, path string) string {
	t.Helper()

	raw, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	require.NoError(t, err)
	defer func() { require.NoError(t, raw.Close()) }()

	var result string
	require.NoError(t, raw.QueryRowContext(t.Context(), `PRAGMA integrity_check`).Scan(&result))
	return result
}

// copyFile is the `cp` the workflow used to run, reproduced exactly: the main file and nothing else.
func copyFile(t *testing.T, source, target string) {
	t.Helper()

	in, err := os.Open(source)
	require.NoError(t, err)
	defer func() { require.NoError(t, in.Close()) }()

	out, err := os.Create(target)
	require.NoError(t, err)
	defer func() { require.NoError(t, out.Close()) }()

	_, err = io.Copy(out, in)
	require.NoError(t, err)
}
