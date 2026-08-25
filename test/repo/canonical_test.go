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
// `plugin.claim` and `session.end` were floor members for two phases and appear nowhere in §5, and
// `plugin.moderate` was added on top of both omissions.
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

// permissionKeyPattern matches a backticked `<resource>.<action>` key.
var permissionKeyPattern = regexp.MustCompile("`([a-z]+\\.[a-z]+)`")

func TestDOC004_TheCanonicalFloorList_MatchesTheCatalogue(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile("../../docs/design/00-canonical-conventions.md")
	require.NoError(t, err, "canonical §5 is normative; this gate cannot run without it")

	section := floorSectionPattern.FindSubmatch(raw)
	require.Len(t, section, 2,
		"DOC004 could not find the capability-floor list in canonical §5. It is anchored on the "+
			"'### The capability floor' heading and the sentence that closes the list; if either "+
			"was reworded, re-anchor this gate rather than deleting it — a gate that cannot find "+
			"its subject reports success over a document it never read")

	documented := map[string]bool{}
	for _, m := range permissionKeyPattern.FindAllSubmatch(section[1], -1) {
		documented[string(m[1])] = true
	}
	require.NotEmpty(t, documented,
		"DOC004 read the floor list and found no permission keys in it; the gate is vacant, not "+
			"passing")

	catalogued := map[string]bool{}
	for _, e := range authz.Catalogue() {
		if e.Floor {
			catalogued[e.Permission.String()] = true
		}
	}
	require.NotEmpty(t, catalogued, "the catalogue holds no floor permissions; that cannot be right")

	require.Empty(t, sortedMissing(catalogued, documented),
		"these permissions are `Floor: true` in internal/authz/catalogue.go and are not named in "+
			"canonical §5's capability-floor list. §5 is the normative statement of what the floor "+
			"IS, and a reader deciding whether a new operation belongs there reads it rather than "+
			"the catalogue: add the bullet, with the reason a token that could perform it would be "+
			"equivalent to the account")

	require.Empty(t, sortedMissing(documented, catalogued),
		"canonical §5 names these as capability-floor and internal/authz does not hold them at "+
			"that level. This is the dangerous direction: the normative document is promising that "+
			"no token can perform an operation that a scoped token may be able to")
}

// sortedMissing returns the keys of want that have are absent from have, in a stable order so a
// failure message reads the same on every run.
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

// TestDOC004_FiresOnADocumentThatDisagrees — the gate has been seen to fail, in both directions.
//
// A gate nobody has watched fail is a gate nobody knows works, and this one is easy to get wrong in
// the direction that reports success: a regexp that stops matching finds no keys and, without the
// vacancy check above, would pass over a document it never read. Each case below is a section that
// MUST produce a finding.
func TestDOC004_FiresOnADocumentThatDisagrees(t *testing.T) {
	t.Parallel()

	// Every floor permission the catalogue holds, so a fixture can drop one deliberately.
	var floor []string
	for _, e := range authz.Catalogue() {
		if e.Floor {
			floor = append(floor, e.Permission.String())
		}
	}
	sort.Strings(floor)
	require.NotEmpty(t, floor)

	bullets := func(keys []string) string {
		var b strings.Builder
		b.WriteString("### The capability floor\n")
		for _, k := range keys {
			b.WriteString("- something — `" + k + "`\n")
		}
		b.WriteString("\n**This list is the complete set")
		return b.String()
	}

	tests := []struct {
		name    string
		section string
		want    string
	}{
		{
			name:    "a floor permission the document does not name",
			section: bullets(floor[1:]),
			want:    floor[0],
		},
		{
			name:    "a permission the document invents",
			section: bullets(append(append([]string{}, floor...), "plugin.manage")),
			want:    "plugin.manage",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			section := floorSectionPattern.FindStringSubmatch(tc.section)
			require.Len(t, section, 2, "the fixture must be shaped like the real section")

			documented := map[string]bool{}
			for _, m := range permissionKeyPattern.FindAllStringSubmatch(section[1], -1) {
				documented[m[1]] = true
			}
			catalogued := map[string]bool{}
			for _, k := range floor {
				catalogued[k] = true
			}

			findings := append(sortedMissing(catalogued, documented),
				sortedMissing(documented, catalogued)...)
			require.Contains(t, findings, tc.want,
				"DOC004 must reject this shape, and reject it for the reason it was written for")
		})
	}
}
