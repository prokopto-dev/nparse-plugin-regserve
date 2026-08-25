package repo_test

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
)

// DOC004 — the normative capability-floor list and the catalogue say the same thing.
//
// Canonical §5 is NORMATIVE and names the floor members in prose. `internal/authz/catalogue.go` is
// the one source, and `Floor: true` is what actually decides. Those are two artefacts describing
// one rule, which is a drift shape, and it had already drifted twice before anybody noticed:
// `plugin.claim` and `session.end` were floor members for two phases and appeared nowhere in §5,
// and `plugin.moderate` was added on top of both omissions.
//
// The failure mode is quiet and it is the expensive kind. Nothing breaks when the document is short
// — the catalogue still refuses the token, the middleware still enforces it — so the only symptom
// is that the page somebody reads to learn what the floor IS covers fewer cases than the code, and
// the argument for why an operation belongs there stops being made for the operations added since.
// A reader deciding whether a NEW operation is capability-floor reads §5, not the catalogue.
//
// BOTH DIRECTIONS ARE CHECKED. A floor permission missing from §5 is the drift above. A key named
// in §5 that the catalogue does not hold at the floor is the opposite and is worse: a document
// promising a token cannot do something it can.
//
// The catalogue stays the one source. This does not make the document authoritative — it makes it
// impossible for the document to be silently wrong.

// floorSectionPattern finds the capability-floor list in canonical §5.
//
// It is bounded at both ends rather than reading to the end of the section: the paragraphs after
// the list mention `plugin.manage` and `plugin:manage` while explaining what moderation is NOT, and
// a scan that ran past the bullets would read those as claims about the floor and fail on the one
// permission the passage exists to say is not in it.
var floorSectionPattern = regexp.MustCompile(
	`(?s)### The capability floor\n(.*?)\n\*\*This list is the complete set`)

// floorBulletPattern matches ONE LIST ENTRY, and only a list entry.
//
// The keys have to come from the bullets rather than from everything inside the bounded span,
// because the span also holds the sentence introducing the list. A key mentioned in that prose
// would otherwise satisfy the requirement to have a bullet for it — so a permission could be
// "documented" by being named in a paragraph that does not put it in the floor at all, which is
// the reverse of what this gate is for.
var floorBulletPattern = regexp.MustCompile(`(?m)^[-*][ \t]+(.*)$`)

// backtickedPattern matches any backticked token in a bullet. Which of them are PERMISSIONS is
// decided by internal/authz and not here — see floorKeysIn.
var backtickedPattern = regexp.MustCompile("`([^`]+)`")

// floorKeysIn returns the permission keys named in the floor list's bullets.
//
// WHAT COUNTS AS A PERMISSION IS `authz.Permission.Valid`, not a second grammar written here. That
// matters in both directions and the first version of this gate got it wrong: it matched `[a-z]+`
// on either side of the dot, while canonical §12's spelling — the one `internal/authz` enforces —
// is `[a-z][a-z0-9_]*`. A key like `oauth2.rotate_key` is perfectly legal and would have been
// invisible to it, so documenting a floor member the catalogue does not hold would have passed the
// dangerous direction of this gate, and naming it correctly in both places would have failed the
// safe one. A gate with its own idea of the vocabulary is a gate that disagrees with the code it
// checks.
func floorKeysIn(section string) map[string]bool {
	out := map[string]bool{}
	for _, bullet := range floorBulletPattern.FindAllStringSubmatch(section, -1) {
		for _, token := range backtickedPattern.FindAllStringSubmatch(bullet[1], -1) {
			if key := token[1]; authz.Permission(key).Valid() {
				out[key] = true
			}
		}
	}
	return out
}

// catalogueFloorKeys returns every permission the catalogue holds at the floor.
func catalogueFloorKeys() map[string]bool {
	out := map[string]bool{}
	for _, e := range authz.Catalogue() {
		if e.Floor {
			out[e.Permission.String()] = true
		}
	}
	return out
}

func TestDOC004_TheCanonicalFloorList_MatchesTheCatalogue(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../../docs/design/00-canonical-conventions.md")
	require.NoError(t, err, "canonical §5 is normative; this gate cannot run without it")

	section := floorSectionPattern.FindStringSubmatch(string(raw))
	require.Len(t, section, 2,
		"DOC004 could not find the capability-floor list in canonical §5. It is anchored on the "+
			"'### The capability floor' heading and the sentence that closes the list; if either "+
			"was reworded, re-anchor this gate rather than deleting it — a gate that cannot find "+
			"its subject reports success over a document it never read")

	documented := floorKeysIn(section[1])
	require.NotEmpty(t, documented,
		"DOC004 read the floor list and found no permission keys in its bullets; the gate is "+
			"vacant, not passing")

	catalogued := catalogueFloorKeys()
	require.NotEmpty(t, catalogued, "the catalogue holds no floor permissions; that cannot be right")

	require.Empty(t, sortedMissing(catalogued, documented),
		"these permissions are `Floor: true` in internal/authz/catalogue.go and are not named in "+
			"a BULLET of canonical §5's capability-floor list. §5 is the normative statement of "+
			"what the floor IS, and a reader deciding whether a new operation belongs there reads "+
			"it rather than the catalogue: add the entry, with the reason a token that could "+
			"perform it would be equivalent to the account")

	require.Empty(t, sortedMissing(documented, catalogued),
		"canonical §5 names these as capability-floor and internal/authz does not hold them at "+
			"that level. This is the dangerous direction: the normative document is promising that "+
			"no token can perform an operation that a scoped token may be able to")
}

// sortedMissing returns the keys of want that are absent from have, in a stable order so a failure
// message reads the same on every run.
func sortedMissing(want, have map[string]bool) []string {
	var out []string
	for k := range want {
		if !have[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// TestDOC004_FiresOnADocumentThatDisagrees — the gate has been seen to fail, in every way it must.
//
// A gate nobody has watched fail is a gate nobody knows works, and this one is easy to get wrong in
// the direction that reports success: an extractor that stops matching finds no keys and, without
// the vacancy check above, would pass over a document it never read.
//
// THESE RUN THE REAL EXTRACTOR. An earlier version of this test re-implemented the parsing inline,
// which meant the fixtures proved something about the test rather than about the gate — the
// grammar bug the review caught was in the extractor and would have been invisible here.
func TestDOC004_FiresOnADocumentThatDisagrees(t *testing.T) {
	t.Parallel()

	floor := sortedMissing(catalogueFloorKeys(), map[string]bool{})
	require.NotEmpty(t, floor)

	// section renders a floor list shaped like the real one, from the entries given.
	section := func(entries ...string) string {
		var b strings.Builder
		b.WriteString("### The capability floor\n\nSome operations carry no scope at all:\n\n")
		for _, e := range entries {
			b.WriteString(e + "\n")
		}
		b.WriteString("\n**This list is the complete set")
		return b.String()
	}
	bullet := func(key string) string { return "- something — `" + key + "`" }

	bullets := func(keys ...string) []string {
		out := make([]string, 0, len(keys))
		for _, k := range keys {
			out = append(out, bullet(k))
		}
		return out
	}

	tests := []struct {
		name    string
		entries []string
		want    string
	}{
		{
			name:    "a floor permission the document does not name",
			entries: bullets(floor[1:]...),
			want:    floor[0],
		},
		{
			name:    "a permission the document invents",
			entries: append(bullets(floor...), bullet("plugin.manage")),
			want:    "plugin.manage",
		},
		{
			// THE PROSE CASE. The key is inside the bounded span and is not a list entry, so it
			// must not count as documenting anything. Otherwise a permission could be "in the
			// floor" by being mentioned in a sentence that says it is not.
			name: "a key mentioned in prose rather than in a bullet",
			entries: append(bullets(floor[1:]...),
				"Nothing here puts `"+floor[0]+"` in the floor; it is merely named."),
			want: floor[0],
		},
		{
			// THE GRAMMAR CASE, and the one the first version of this gate got wrong. Digits and
			// underscores are legal in a permission (`[a-z][a-z0-9_]*`), so a documented-only key
			// carrying them must be SEEN and reported, not skipped.
			name:    "a documented-only key carrying digits and an underscore",
			entries: append(bullets(floor...), bullet("oauth2.rotate_key")),
			want:    "oauth2.rotate_key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			matched := floorSectionPattern.FindStringSubmatch(section(tc.entries...))
			require.Len(t, matched, 2, "the fixture must be shaped like the real section")

			documented := floorKeysIn(matched[1])
			catalogued := catalogueFloorKeys()

			findings := append(sortedMissing(catalogued, documented),
				sortedMissing(documented, catalogued)...)
			require.Contains(t, findings, tc.want,
				"DOC004 must reject this shape, and reject it for the reason it was written for")
		})
	}
}

// TestDOC004_AcceptsAKeyThatIsSpelledLegally — the other side of the grammar case.
//
// The fixture above proves a `[a-z0-9_]` key is not skipped when it is wrong. This proves the same
// key is not FALSELY reported when it is right, which is the failure a stricter-than-the-code
// extractor produces: correct in both places and red anyway. A gate that fails on correct input
// gets switched off, and takes the real findings with it.
func TestDOC004_AcceptsAKeyThatIsSpelledLegally(t *testing.T) {
	t.Parallel()

	documented := floorKeysIn("- rotating a key — `oauth2.rotate_key`\n- a scope, not a permission — `plugin:manage`")

	require.True(t, documented["oauth2.rotate_key"],
		"the extractor must recognise every spelling internal/authz calls a permission")
	require.False(t, documented["plugin:manage"],
		"a scope is not a permission and must not be read as one")
	require.Len(t, documented, 1)
}
