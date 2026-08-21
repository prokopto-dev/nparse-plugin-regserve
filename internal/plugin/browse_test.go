package plugin_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/plugin"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// The public directory's search, against a real database.
//
// These are not page tests: what is being checked is the QUERY — that it matches the four fields
// it claims to, that a visitor's punctuation is data rather than syntax, and that the counts the
// page prints are true. A fake would answer whatever the fake's author expected, and the
// interesting failures here are SQLite's.

// named returns a listing with the four searchable fields set explicitly, so a test can say which
// one it expects to match on.
func named(id, name, description, author string) registry.Plugin {
	p := listing(id)
	p.Name = name
	p.Description = description
	p.Author = author
	return p
}

func catalogue(t *testing.T, plugins ...registry.Plugin) (*store.DB, *plugin.Catalogue) {
	t.Helper()

	db := storetest.New(t)
	return db, importInto(t, db, plugins...)
}

func TestBrowse_EmptyQuery_ReturnsEveryListing(t *testing.T) {
	t.Parallel()

	_, cat := catalogue(t, listing("alpha"), listing("beta"), listing("gamma"))

	got, err := cat.Browse(t.Context(), "")
	require.NoError(t, err)
	require.Equal(t, []string{"alpha", "beta", "gamma"}, ids(got.Plugins),
		"an empty search is show everything, in the index's own order")
	require.Equal(t, 3, got.Listed)
	require.Zero(t, got.Awaiting)
	require.Zero(t, got.Delisted)
}

// TestBrowse_MatchesEveryFieldItClaimsTo — the four fields, one at a time.
//
// Each fixture is the ONLY row carrying the term, so a match proves the field is searched rather
// than that something else happened to contain it.
func TestBrowse_MatchesEveryFieldItClaimsTo(t *testing.T) {
	t.Parallel()

	_, cat := catalogue(t,
		named("merchant-mode", "Merchant Mode", "linkable auction macros", "prokopto-dev"),
		named("timers", "Spell Timers", "casting bars that follow your log", "someone-else"),
	)

	tests := []struct {
		name, query, want string
	}{
		{name: "id", query: "merchant-mo", want: "merchant-mode"},
		{name: "name", query: "spell", want: "timers"},
		{name: "description", query: "auction", want: "merchant-mode"},
		{name: "author", query: "someone-else", want: "timers"},
		{name: "case is folded for ascii", query: "MERCHANT MODE", want: "merchant-mode"},
		{name: "a substring anywhere matches", query: "ing bars", want: "timers"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := cat.Browse(t.Context(), tt.query)
			require.NoError(t, err)
			require.Equal(t, []string{tt.want}, ids(got.Plugins))
			require.Equal(t, 2, got.Listed, "the total is what is listed, not what matched")
		})
	}
}

// TestBrowse_PunctuationIsData_NotSyntax.
//
// The reason this query uses instr() rather than LIKE is that LIKE's `%` and `_` are wildcards: a
// visitor typing `%` into a search box would match every row, and a visitor typing `_` would match
// every row with at least one character — both of which look like a broken search and are the
// classic un-escaped-LIKE bug. instr's needle is literal, so these find only real occurrences.
func TestBrowse_PunctuationIsData_NotSyntax(t *testing.T) {
	t.Parallel()

	_, cat := catalogue(t,
		named("alpha", "Alpha", "no punctuation here", "someone"),
		named("beta", "100% Coverage", "a literal percent in the name", "someone"),
	)

	percent, err := cat.Browse(t.Context(), "%")
	require.NoError(t, err)
	require.Equal(t, []string{"beta"}, ids(percent.Plugins),
		"a percent sign matches the row that contains one, not every row")

	underscore, err := cat.Browse(t.Context(), "_")
	require.NoError(t, err)
	require.Empty(t, underscore.Plugins,
		"an underscore is a character to find, not a wildcard for any character")
}

// TestBrowse_ASQLShapedQuery_FindsNothingAndBreaksNothing.
//
// The query is parameterised through sqlc, so this cannot work — which is exactly why it is worth
// asserting: the test that proves it is the one that fails the day somebody builds the statement
// with fmt.Sprintf instead.
func TestBrowse_ASQLShapedQuery_FindsNothingAndBreaksNothing(t *testing.T) {
	t.Parallel()

	_, cat := catalogue(t, listing("alpha"), listing("beta"))

	for _, hostile := range []string{
		`'; DROP TABLE plugin; --`,
		`' OR 1=1 --`,
		`" UNION SELECT id, name FROM plugin --`,
	} {
		got, err := cat.Browse(t.Context(), hostile)
		require.NoError(t, err, "a hostile query is ordinary text, not an error")
		require.Empty(t, got.Plugins, "%q matched something", hostile)
	}

	// The catalogue is still there, and still serves. A dropped table would fail here rather than
	// in whatever ran next.
	after, err := cat.Listings(t.Context())
	require.NoError(t, err)
	require.Len(t, after, 2)
}

// TestBrowse_DelistedAndUnapproved_AreExcludedAndCounted — never hide a row silently.
//
// Both kinds of absence are legitimate and neither is visible in the list itself, so the page gets
// a number for each. A directory shorter than the catalogue with nothing saying why is
// indistinguishable from a registry that lost a plugin.
func TestBrowse_DelistedAndUnapproved_AreExcludedAndCounted(t *testing.T) {
	t.Parallel()

	db, cat := catalogue(t, listing("alpha"), listing("beta"))

	raw := openRaw(t, db.Path())
	_, err := raw.ExecContext(t.Context(),
		`UPDATE plugin SET delisted_at = 1, delisted_reason = 'author request' WHERE id = 'beta'`)
	require.NoError(t, err)
	_, err = raw.ExecContext(t.Context(),
		`INSERT INTO plugin (id, name, claimed_at, updated_at) VALUES ('pending-one', 'Pending', 1, 1)`)
	require.NoError(t, err)

	got, err := cat.Browse(t.Context(), "")
	require.NoError(t, err)
	require.Equal(t, []string{"alpha"}, ids(got.Plugins))
	require.Equal(t, 1, got.Listed)
	require.Equal(t, 1, got.Awaiting, "a claimed id with nothing approved is counted, not hidden")
	require.Equal(t, 1, got.Delisted, "a delisted id is counted, and stays claimed forever")

	// A delisted plugin is not reachable by searching for it either: the directory and the index
	// agree about what is public.
	byName, err := cat.Browse(t.Context(), "beta")
	require.NoError(t, err)
	require.Empty(t, byName.Plugins)
}

// TestBrowse_NonASCII_FoldsNothing — the stated limitation, pinned.
//
// SQLite's lower() folds ASCII only, and the Go side folds the same alphabet on purpose so the two
// agree. The cost is that a non-ASCII query matches case-sensitively. That is written down in
// internal/plugin and in the query, and this is what makes it a decision rather than a surprise
// somebody discovers: if it ever changes, this test says so.
func TestBrowse_NonASCII_FoldsNothing(t *testing.T) {
	t.Parallel()

	_, cat := catalogue(t, named("umlaut", "Ärger Tracker", "keeps score", "someone"))

	exact, err := cat.Browse(t.Context(), "Ärger")
	require.NoError(t, err)
	require.Equal(t, []string{"umlaut"}, ids(exact.Plugins))

	folded, err := cat.Browse(t.Context(), "ärger")
	require.NoError(t, err)
	require.Empty(t, folded.Plugins,
		"a non-ASCII query is case-sensitive; adding ICU would change this and should update the "+
			"comment in db/queries/plugin.sql that promises it")
}

func ids(plugins []registry.Plugin) []string {
	out := make([]string, 0, len(plugins))
	for _, p := range plugins {
		out = append(out, p.ID)
	}
	return out
}
