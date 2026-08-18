package plugin_test

import (
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	_ "modernc.org/sqlite"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/plugin"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

func TestMain(m *testing.M) { storetest.Main(m) }

func fixedClock() clock.Clock {
	return clock.Fixed{T: time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)}
}

// seedFile writes a schema-v1 document and returns its path. It renders through the registry types
// rather than a JSON literal, so this file never restates the wire format registry owns.
func seedFile(t *testing.T, plugins ...registry.Plugin) string {
	t.Helper()

	raw, err := json.Marshal(registry.Index{SchemaVersion: registry.SchemaVersion, Plugins: plugins})
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "seed.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

func listing(id string) registry.Plugin {
	return registry.Plugin{
		ID:          id,
		Name:        "Test " + id,
		Description: "a plugin called " + id,
		Author:      "someone",
		Homepage:    "https://example.com/" + id,
		Latest: registry.Release{
			Version:     "1.0.0",
			URL:         "https://example.com/" + id + ".zip",
			SHA256:      strings.Repeat("c", 64),
			RequiresSDK: registry.DefaultRequiresSDK,
		},
	}
}

// importInto seeds a database from plugins and returns the catalogue over it.
func importInto(t *testing.T, db *store.DB, plugins ...registry.Plugin) *plugin.Catalogue {
	t.Helper()

	seed, err := plugin.LoadSeed(seedFile(t, plugins...))
	require.NoError(t, err)

	out, err := plugin.ImportSeed(t.Context(), db, fixedClock(), seed)
	require.NoError(t, err)
	require.Empty(t, out.Skip)
	require.Equal(t, len(plugins), out.Plugins)
	return plugin.NewCatalogue(db)
}

func openRaw(t *testing.T, path string) *sql.DB {
	t.Helper()

	raw, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(ON)")
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, raw.Close()) })
	return raw
}

// TestImportSeed_ThenServe_RendersTheSameDocument — the transition test.
//
// A live registry is serving this exact document to installed clients right now. If importing it
// and rendering it back changes so much as a null into an empty string, every one of those clients
// sees a listing change on the day this ships. Whole-value comparison, not field-by-field: the
// field somebody forgets to compare is the field that breaks.
func TestImportSeed_ThenServe_RendersTheSameDocument(t *testing.T) {
	t.Parallel()

	floor := "1.4.0"
	withFloor := listing("merchant-mode")
	withFloor.Latest.MinAppVersion = &floor

	original := []registry.Plugin{withFloor, listing("alpha"), listing("zeta")}
	want, err := registry.NewIndex(original)
	require.NoError(t, err)

	cat := importInto(t, storetest.New(t), original...)

	served, err := cat.Listings(t.Context())
	require.NoError(t, err)
	got, err := registry.NewIndex(served)
	require.NoError(t, err)

	require.Empty(t, cmp.Diff(want, got), "the imported catalogue does not render what was imported")
}

// TestImportSeed_NonEmptyDatabase_ChangesNothing — the property the production transition rests on.
//
// The seed file stays mounted on the droplet after this release. If a later boot re-imported it,
// every publish made since would be silently reverted to whatever the file says — and the file is
// a snapshot of the catalogue as it was on the day of the cutover.
func TestImportSeed_NonEmptyDatabase_ChangesNothing(t *testing.T) {
	t.Parallel()

	db := storetest.New(t)
	importInto(t, db, listing("alpha"))

	// A second, DIFFERENT seed: the shape of somebody updating the file and restarting.
	other, err := plugin.LoadSeed(seedFile(t, listing("beta"), listing("gamma")))
	require.NoError(t, err)

	out, err := plugin.ImportSeed(t.Context(), db, fixedClock(), other)
	require.NoError(t, err, "an ignored seed is not an error; it is every boot after the first")
	require.Zero(t, out.Plugins)
	require.Equal(t, plugin.SkipCatalogueExists, out.Skip)
	require.Equal(t, int64(1), out.Existing)

	served, err := plugin.NewCatalogue(db).Listings(t.Context())
	require.NoError(t, err)
	require.Len(t, served, 1)
	require.Equal(t, "alpha", served[0].ID)
}

// TestImportSeed_RecordsProvenance — an imported release carries a hash THIS SERVER DID NOT
// COMPUTE, and the row has to say so.
//
// The trust model's whole claim is that a stored hash was computed here from bytes fetched here
// (ADR-0008). For imported rows that is not true, and a row that looked identical to a published
// one would make the claim false without anyone being able to tell which rows it applied to.
func TestImportSeed_RecordsProvenance(t *testing.T) {
	t.Parallel()

	db := storetest.New(t)
	importInto(t, db, listing("alpha"))
	raw := openRaw(t, db.Path())

	var source, state string
	var verifiedAt, reviewedBy *string
	require.NoError(t, raw.QueryRowContext(t.Context(),
		`SELECT source, state, verified_at, reviewed_by FROM "release"`).
		Scan(&source, &state, &verifiedAt, &reviewedBy))

	require.Equal(t, "import", source)
	require.Equal(t, "approved", state, "the imported catalogue is what the live registry serves today")
	require.Nil(t, verifiedAt, "this server did not fetch or hash those bytes")
	require.Nil(t, reviewedBy, "no account here reviewed it; the review happened in the static registry")

	var action, actorKind string
	var detail string
	require.NoError(t, raw.QueryRowContext(t.Context(),
		`SELECT action, actor_kind, detail FROM audit_log`).Scan(&action, &actorKind, &detail))
	require.Equal(t, "catalogue.import", action)
	require.Equal(t, "system", actorKind, "no account performed the import")
	require.Contains(t, detail, `"plugins":1`)
}

// TestCatalogue_Listings_OrderedById — the client renders plugins in array order, so a document
// whose order depends on the database's row order produces a browse list that reshuffles.
func TestCatalogue_Listings_OrderedById(t *testing.T) {
	t.Parallel()

	cat := importInto(t, storetest.New(t), listing("zeta"), listing("alpha"), listing("merchant-mode"))

	got, err := cat.Listings(t.Context())
	require.NoError(t, err)

	ids := make([]string, 0, len(got))
	for _, p := range got {
		ids = append(ids, p.ID)
	}
	require.Equal(t, []string{"alpha", "merchant-mode", "zeta"}, ids)
}

// TestCatalogue_DelistedPlugin_IsGoneFromBothEndpoints — delisting removes the listing and keeps
// the id claim. A delisted plugin is indistinguishable from one that never existed, to a client
// and to somebody enumerating ids.
func TestCatalogue_DelistedPlugin_IsGoneFromBothEndpoints(t *testing.T) {
	t.Parallel()

	db := storetest.New(t)
	cat := importInto(t, db, listing("alpha"), listing("beta"))

	raw := openRaw(t, db.Path())
	_, err := raw.ExecContext(t.Context(),
		`UPDATE plugin SET delisted_at = 1, delisted_reason = 'author request' WHERE id = 'alpha'`)
	require.NoError(t, err)

	got, err := cat.Listings(t.Context())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "beta", got[0].ID)

	_, err = cat.Listing(t.Context(), core.PluginID("alpha"))
	require.ErrorIs(t, err, api.ErrListingNotFound)

	// The claim survives: the id is still spoken for and cannot be handed to anybody else.
	var n int
	require.NoError(t, raw.QueryRowContext(t.Context(),
		`SELECT count(*) FROM plugin WHERE id = 'alpha'`).Scan(&n))
	require.Equal(t, 1, n)
}

// TestCatalogue_ClaimedButUnapproved_IsNotServed — a plugin awaiting human review is claimed and
// not listed. Serving it would publish an artifact nobody has approved.
func TestCatalogue_ClaimedButUnapproved_IsNotServed(t *testing.T) {
	t.Parallel()

	db := storetest.New(t)
	cat := importInto(t, db, listing("alpha"))

	raw := openRaw(t, db.Path())
	_, err := raw.ExecContext(t.Context(),
		`INSERT INTO plugin (id, name, claimed_at, updated_at) VALUES ('pending-one', 'Pending', 1, 1)`)
	require.NoError(t, err)
	_, err = raw.ExecContext(t.Context(),
		`INSERT INTO "release" (id, plugin_id, version, state, source, artifact_url, sdk_specifier, submitted_at)
		 VALUES ('01ARZ3NDEKTSV4RRFFQ69G5FAV', 'pending-one', '1.0.0', 'pending', 'publish',
		         'https://example.com/p.zip', '>=1.0,<2', 1)`)
	require.NoError(t, err)

	got, err := cat.Listings(t.Context())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "alpha", got[0].ID)

	_, err = cat.Listing(t.Context(), core.PluginID("pending-one"))
	require.ErrorIs(t, err, api.ErrListingNotFound)
}

// TestCatalogue_Listing_UnknownId_IsNotFound — the 404 path the index endpoint maps onto.
func TestCatalogue_Listing_UnknownId_IsNotFound(t *testing.T) {
	t.Parallel()

	cat := importInto(t, storetest.New(t), listing("alpha"))

	_, err := cat.Listing(t.Context(), core.PluginID("never-claimed"))
	require.ErrorIs(t, err, api.ErrListingNotFound)
}

// TestCatalogue_Listing_KnownId_ReturnsTheWholeListing — the per-plugin endpoint is what
// PluginMeta.update_url points at in every published plugin, so it must carry the same fields as
// the full index and not a reduced version of them.
func TestCatalogue_Listing_KnownId_ReturnsTheWholeListing(t *testing.T) {
	t.Parallel()

	floor := "1.4.0"
	want := listing("merchant-mode")
	want.Latest.MinAppVersion = &floor

	cat := importInto(t, storetest.New(t), want, listing("alpha"))

	got, err := cat.Listing(t.Context(), core.PluginID("merchant-mode"))
	require.NoError(t, err)
	require.Empty(t, cmp.Diff(want, got))
}

// TestCatalogue_Ready_EmptyCatalogue_IsReady — an index with no plugins is a valid document, not a
// broken one. Reporting it unready would make a fresh instance look like a failed deploy.
func TestCatalogue_Ready_EmptyCatalogue_IsReady(t *testing.T) {
	t.Parallel()

	require.NoError(t, plugin.NewCatalogue(storetest.New(t)).Ready(t.Context()))
}

// TestCatalogue_Ready_LoadedCatalogue_IsReady — the answer the deploy waits for.
func TestCatalogue_Ready_LoadedCatalogue_IsReady(t *testing.T) {
	t.Parallel()

	cat := importInto(t, storetest.New(t), listing("alpha"), listing("beta"))
	require.NoError(t, cat.Ready(t.Context()))
}

// TestCatalogue_Ready_ClosedDatabase_SaysSoWithoutPublishingAPath — /readyz returns this string to
// an unauthenticated caller. It has to explain enough for an operator and nothing an attacker can
// use to map the container.
func TestCatalogue_Ready_ClosedDatabase_SaysSoWithoutPublishingAPath(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "regserve.db")
	db, err := store.Open(t.Context(), store.Config{Path: path})
	require.NoError(t, err)
	require.NoError(t, db.Close())

	err = plugin.NewCatalogue(db).Ready(t.Context())
	require.Error(t, err)
	require.NotContains(t, err.Error(), path, "the readiness detail must not publish a filesystem layout")
	require.NotContains(t, err.Error(), t.TempDir())
}

// TestLoadSeed_UnusableFile_NamesTheFile — the server refuses to start on these, and the operator
// has to be told which file to go and fix.
func TestLoadSeed_UnusableFile_NamesTheFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		path    func(t *testing.T) string
		wantErr string
	}{
		{
			name:    "the file does not exist",
			path:    func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.json") },
			wantErr: "read seed file",
		},
		{
			// What a missing bind-mount source actually looks like: Docker creates a directory.
			name:    "the path is a directory",
			path:    func(t *testing.T) string { return t.TempDir() },
			wantErr: "read seed file",
		},
		{
			name: "a listing would not satisfy the client's parser",
			path: func(t *testing.T) string {
				bad := listing("alpha")
				bad.Latest.SHA256 = "not-a-hash"
				return seedFile(t, bad)
			},
			wantErr: "parse seed file",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := tc.path(t)
			_, err := plugin.LoadSeed(path)
			require.ErrorContains(t, err, tc.wantErr)
			require.ErrorContains(t, err, path)
		})
	}
}

// TestImportSeed_EmptySeed_WritesNothingAtAll — an index with no plugins is a VALID document, so a
// truncated upstream fetch or a hand-edited file produces one, and the server has to survive
// restarting against it.
//
// The bug this pins: using "the catalogue is empty" as the one-time condition means an empty seed
// never satisfies it, so every restart re-runs the import and appends another audit row to a table
// that can never be pruned. Nothing happened, so nothing is written — including the marker.
func TestImportSeed_EmptySeed_WritesNothingAtAll(t *testing.T) {
	t.Parallel()

	db := storetest.New(t)
	empty, err := plugin.LoadSeed(seedFile(t))
	require.NoError(t, err)

	for i := range 3 {
		out, err := plugin.ImportSeed(t.Context(), db, fixedClock(), empty)
		require.NoError(t, err, "boot %d", i)
		require.Zero(t, out.Plugins)
		require.Equal(t, plugin.SkipSeedEmpty, out.Skip)
	}

	raw := openRaw(t, db.Path())
	var audits int
	require.NoError(t, raw.QueryRowContext(t.Context(), `SELECT count(*) FROM audit_log`).Scan(&audits))
	require.Zero(t, audits, "three restarts against an empty seed wrote %d audit rows", audits)
}

// TestImportSeed_EmptySeedThenARealOne_StillImports — the reason an empty seed must NOT claim the
// import marker.
//
// An operator who notices the catalogue is empty fixes the file and restarts. If the empty boot had
// recorded "a seed was imported", that fix would silently do nothing and the registry would stay
// empty with every log line reporting success.
func TestImportSeed_EmptySeedThenARealOne_StillImports(t *testing.T) {
	t.Parallel()

	db := storetest.New(t)

	empty, err := plugin.LoadSeed(seedFile(t))
	require.NoError(t, err)
	out, err := plugin.ImportSeed(t.Context(), db, fixedClock(), empty)
	require.NoError(t, err)
	require.Equal(t, plugin.SkipSeedEmpty, out.Skip)

	fixed, err := plugin.LoadSeed(seedFile(t, listing("alpha")))
	require.NoError(t, err)
	out, err = plugin.ImportSeed(t.Context(), db, fixedClock(), fixed)
	require.NoError(t, err)
	require.Empty(t, out.Skip, "the corrected seed must still be imported")
	require.Equal(t, 1, out.Plugins)

	served, err := plugin.NewCatalogue(db).Listings(t.Context())
	require.NoError(t, err)
	require.Len(t, served, 1)
}

// TestImportSeed_MarkerAlone_StopsASecondImport — the audit record is the one-time condition, not
// the plugin count.
//
// The state is built by hand because the schema forbids reaching it any other way: a plugin row
// cannot be deleted. That is exactly why the marker is checked separately — the rule must not
// depend on a trigger in another file staying where it is, and its failure mode is a restart
// reverting every publish made since the cutover.
func TestImportSeed_MarkerAlone_StopsASecondImport(t *testing.T) {
	t.Parallel()

	db := storetest.New(t)
	raw := openRaw(t, db.Path())
	_, err := raw.ExecContext(t.Context(),
		`INSERT INTO audit_log (id, recorded_at, actor_kind, action, subject_kind)
		 VALUES ('01ARZ3NDEKTSV4RRFFQ69G5FAV', 1700000000000000, 'system', 'catalogue.import', 'catalogue')`)
	require.NoError(t, err)

	seed, err := plugin.LoadSeed(seedFile(t, listing("alpha")))
	require.NoError(t, err)

	out, err := plugin.ImportSeed(t.Context(), db, fixedClock(), seed)
	require.NoError(t, err)
	require.Zero(t, out.Plugins)
	require.Equal(t, plugin.SkipAlreadyImported, out.Skip)

	var plugins int
	require.NoError(t, raw.QueryRowContext(t.Context(), `SELECT count(*) FROM plugin`).Scan(&plugins))
	require.Zero(t, plugins)
}
