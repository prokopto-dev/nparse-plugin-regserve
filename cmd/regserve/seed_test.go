package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// writeOwners puts an owners.json next to the test.
func writeOwners(t *testing.T, owners map[string][]string) string {
	t.Helper()

	body, err := json.Marshal(map[string]any{
		"_readme": []string{"documentation, ignored by the importer"},
		"owners":  owners,
	})
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "owners.json")
	require.NoError(t, os.WriteFile(path, body, 0o600))
	return path
}

// TestSeedOwners_AFreshDatabase_IsMigratedRatherThanFailing — what `make seed` actually does.
//
// store.Open CREATES the file and applies nothing, so the documented `DB=./regserve.db` on a
// machine that has never run the server is a database with no tables. Without a migration the
// first query fails with "no such table: plugin" — a confusing message from a command whose job
// is to write rows, and one that reads as a bug in the importer rather than a missing step.
//
// It stops before reaching GitHub: the empty catalogue means every id is unknown, which is the
// warning this asserts. That is deliberate — the test must not make a network call, and the path
// it covers is everything up to the point where one would happen.
func TestSeedOwners_AFreshDatabase_IsMigratedRatherThanFailing(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "regserve.db")
	owners := writeOwners(t, map[string][]string{"merchant-mode": {"prokopto-dev"}})

	out, err := runOut(t, "seed-owners", "--owners", owners, "--db", dbPath)

	// A partial import exits non-zero: it did what it could and something is left for a human.
	require.ErrorIs(t, err, errPartialImport,
		"the id is unknown because the catalogue is empty, which is a person's problem, not a crash")
	require.NotContains(t, err.Error(), "no such table",
		"the database must have been migrated before anything queried it")
	require.Contains(t, out, "granted 0")

	// The schema is really there afterwards, not merely un-queried.
	db, err := store.Open(t.Context(), store.Config{Path: dbPath})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, db.Close()) })

	count, err := db.Read().CountPlugins(t.Context())
	require.NoError(t, err, "the plugin table must exist")
	require.Zero(t, count)
}

// TestSeedOwners_AnAlreadyMigratedDatabase_IsLeftAlone — migrating is idempotent.
func TestSeedOwners_AnAlreadyMigratedDatabase_IsLeftAlone(t *testing.T) {
	dbPath := storetest.Path(t)
	owners := writeOwners(t, map[string][]string{"merchant-mode": {"prokopto-dev"}})

	_, err := runOut(t, "seed-owners", "--owners", owners, "--db", dbPath)
	require.ErrorIs(t, err, errPartialImport)
}

func TestSeedOwners_RefusesToStartWithoutItsInputs(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "regserve.db")

	t.Run("no owners file", func(t *testing.T) {
		_, err := runOut(t, "seed-owners", "--db", dbPath)
		require.ErrorIs(t, err, errNoOwnersPath)
	})

	t.Run("no database", func(t *testing.T) {
		t.Setenv(envDBPath, "")
		_, err := runOut(t, "seed-owners", "--owners", writeOwners(t, map[string][]string{"x": {"y"}}))
		require.ErrorIs(t, err, store.ErrNoPath)
	})

	t.Run("an owners file that does not parse", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "owners.json")
		require.NoError(t, os.WriteFile(path, []byte("{"), 0o600))

		_, err := runOut(t, "seed-owners", "--owners", path, "--db", dbPath)
		require.Error(t, err)
		// The file is read BEFORE anything is opened or asked of GitHub: a malformed file found
		// after fifty API calls is fifty calls against a rate limit spent on a run that was never
		// going to finish.
		require.NoFileExists(t, dbPath, "nothing should have been created")
	})
}
