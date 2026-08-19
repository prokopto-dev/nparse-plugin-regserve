package authz_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
)

// The catalogue is the one source for permissions and scopes (canonical §5). These are the
// properties a reader of it is entitled to assume, asserted over whatever it currently holds
// rather than against a copy of the list — a test that restates the catalogue is a second
// catalogue, which is the thing §5 forbids.

func TestCatalogue_EveryEntry_IsSpelledAndSummarised(t *testing.T) {
	t.Parallel()

	entries := authz.Catalogue()
	require.NotEmpty(t, entries, "an empty catalogue is not a catalogue")

	seen := map[authz.Permission]bool{}
	for _, e := range entries {
		t.Run(e.Permission.String(), func(t *testing.T) {
			t.Parallel()

			require.True(t, e.Permission.Valid(),
				"%q is not spelled <resource>.<action> (canonical §12)", e.Permission)
			require.NotEmpty(t, strings.TrimSpace(e.Summary),
				"%q has no summary; the generated docs page renders it to plugin authors",
				e.Permission)
			for _, s := range e.Scopes {
				require.True(t, s.Valid(),
					"%q names scope %q, which is not spelled <family>:<verb>", e.Permission, s)
			}
		})

		require.False(t, seen[e.Permission], "%q appears twice in the catalogue", e.Permission)
		seen[e.Permission] = true
	}
}

// TestCatalogue_FloorEntries_CarryNoScope — the capability floor, asserted rather than described.
//
// Canonical §5: minting, listing and revoking PATs, changing owners, setting trust and reviewing
// releases carry NO scope at all, because a token that could perform one would be equivalent to
// the account. A scope on a floor entry would be an `admin:*` by another name.
func TestCatalogue_FloorEntries_CarryNoScope(t *testing.T) {
	t.Parallel()

	for _, e := range authz.Catalogue() {
		if !e.Floor {
			continue
		}
		require.Empty(t, e.Scopes,
			"%q is a capability-floor permission and names scopes; there is no scope that reaches "+
				"the floor and no admin:*", e.Permission)
		require.False(t, authz.Satisfies(e.Permission, authz.Scopes()),
			"%q is satisfied by holding every scope in the catalogue; the floor is meant to be "+
				"unreachable by any token", e.Permission)
	}
}

// TestCatalogue_TheFloorHolds_ForTheOperationsCanonicalNames — the members, by name.
//
// This is the one place the list IS restated, and deliberately: canonical §5 names these
// operations in prose, and a catalogue that quietly dropped `token.mint` from the floor would
// otherwise pass every other test in this file.
func TestCatalogue_TheFloorHolds_ForTheOperationsCanonicalNames(t *testing.T) {
	t.Parallel()

	for _, name := range []authz.Permission{
		"token.mint", "token.read", "token.revoke", "owner.manage", "trust.set", "release.review",
	} {
		e, ok := authz.Lookup(name)
		require.True(t, ok, "canonical §5 names %q as a capability-floor operation; it is not in "+
			"the catalogue at all", name)
		require.True(t, e.Floor, "%q must be in the capability floor (canonical §5)", name)
	}
}

func TestScopes_AreDerivedFromTheEntriesThatGrantThem(t *testing.T) {
	t.Parallel()

	scopes := authz.Scopes()
	require.NotEmpty(t, scopes)

	for _, s := range scopes {
		var grants int
		for _, e := range authz.Catalogue() {
			for _, es := range e.Scopes {
				if es == s {
					grants++
				}
			}
		}
		require.NotZero(t, grants,
			"scope %q grants no permission; a token carrying it would look narrow and be exactly "+
				"as powerless", s)
		require.True(t, authz.KnownScope(s))
	}

	require.False(t, authz.KnownScope("admin:everything"),
		"an unknown scope must not be mintable; there is no admin:*")
}

func TestSatisfies_IsTheIntersectionOfPermissionAndHeldScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		perm authz.Permission
		held []authz.Scope
		want bool
	}{
		{name: "the granting scope", perm: "plugin.publish", held: []authz.Scope{"plugin:publish"}, want: true},
		{name: "one of several held", perm: "plugin.publish", held: []authz.Scope{"plugin:read", "plugin:publish"}, want: true},
		{name: "a different scope", perm: "plugin.publish", held: []authz.Scope{"plugin:read"}, want: false},
		{name: "no scopes at all", perm: "plugin.publish", want: false},
		{name: "a capability-floor permission", perm: "token.mint", held: []authz.Scope{"plugin:publish"}, want: false},
		{name: "a permission not in the catalogue", perm: "nothing.here", held: []authz.Scope{"plugin:publish"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, authz.Satisfies(tt.perm, tt.held))
		})
	}
}

// TestRenderDocs_ListsEveryPermissionAndScope — the generated page cannot silently omit an entry.
//
// GEN001 checks that the checked-in page matches the generator. Nothing else checks that the
// GENERATOR is complete, and a page that renders nine of ten permissions would pass that gate
// forever.
func TestRenderDocs_ListsEveryPermissionAndScope(t *testing.T) {
	t.Parallel()

	page, err := authz.RenderDocs(authz.Usage{
		"plugin.publish": {"POST /api/v1/plugins/{id}/releases"},
		"":               {"GET /index.json"},
	})
	require.NoError(t, err)

	rendered := string(page)
	for _, e := range authz.Catalogue() {
		require.Contains(t, rendered, "`"+e.Permission.String()+"`",
			"the permissions page omits %q", e.Permission)
		require.Contains(t, rendered, e.Summary,
			"the permissions page omits the summary of %q", e.Permission)
	}
	for _, s := range authz.Scopes() {
		require.Contains(t, rendered, "`"+s.String()+"`", "the permissions page omits scope %q", s)
	}

	require.Contains(t, rendered, "POST /api/v1/plugins/{id}/releases",
		"the page must say which operations declare a permission")
	require.Contains(t, rendered, "GET /index.json",
		"the page must list the operations that declare none")
}

func TestRenderDocs_IsDeterministic(t *testing.T) {
	t.Parallel()

	// Two operations arriving in the opposite order must render identically. They come from a map
	// walk in the generator, so without sorting, GEN001 would report drift on alternate runs and
	// everybody would learn to re-run it until it agreed with itself.
	first, err := authz.RenderDocs(authz.Usage{"plugin.publish": {"POST /b", "POST /a"}})
	require.NoError(t, err)
	second, err := authz.RenderDocs(authz.Usage{"plugin.publish": {"POST /a", "POST /b", "POST /a"}})
	require.NoError(t, err)

	require.Equal(t, string(first), string(second))
}
