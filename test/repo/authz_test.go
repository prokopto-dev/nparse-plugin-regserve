package repo_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
)

// cataloguePath is the one source canonical §5 names. The gate below reads it as TEXT, on purpose.
const cataloguePath = "../../internal/authz/catalogue.go"

// --- AUTHZ001 ---------------------------------------------------------------------------------

// TestAUTHZ001_EveryKey_IsAWholeQuotedLiteral — a permission is greppable or it is not a catalogue.
//
// Canonical §5: "Every key is written as a whole quoted literal. The spec gate reads the file as
// text and asserts the exact quoted string appears. A composed key (`resource + "." + action`)
// produces the right runtime value and fails the gate. Do not 'tidy' the catalogue into fields."
//
// The reason is not aesthetic. The catalogue's whole job is to be the place somebody lands when
// they grep for `owner.manage` at 2am, having found it in a 403 body or an OpenAPI extension. A
// value assembled from parts is correct at runtime and answers no question anybody asks — and the
// tidying that produces one always looks like an improvement in review.
func TestAUTHZ001_EveryKey_IsAWholeQuotedLiteral(t *testing.T) {
	t.Parallel()

	src, err := os.ReadFile(cataloguePath)
	require.NoError(t, err, "AUTHZ001 cannot read the catalogue")

	perms := make([]string, 0)
	for _, e := range authz.Catalogue() {
		perms = append(perms, e.Permission.String())
	}
	scopes := make([]string, 0)
	for _, s := range authz.Scopes() {
		scopes = append(scopes, s.String())
	}
	require.NotEmpty(t, perms, "AUTHZ001 inspected no permissions; the gate is vacant, not passing")
	require.NotEmpty(t, scopes, "AUTHZ001 inspected no scopes; the gate is vacant, not passing")

	require.Empty(t, catalogueFindings(string(src), perms, scopes),
		"AUTHZ001: a catalogue key is not written as a whole quoted literal in %s", cataloguePath)
}

// TestAUTHZ001_FiresOnAComposedKey — the gate has been seen to fail.
//
// A gate nobody has watched fail is a gate nobody knows works, and this one is trivially easy to
// write in the direction that always passes: `strings.Contains` over a file that also contains the
// prose describing the rule would match the rule's own documentation.
func TestAUTHZ001_FiresOnAComposedKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		src    string
		perms  []string
		scopes []string
	}{
		{
			name:  "a permission built from parts",
			src:   `{Permission: Permission(resource + "." + action)}`,
			perms: []string{"plugin.publish"},
		},
		{
			name:  "a permission that is not in the file at all",
			src:   `{Permission: "plugin.read"}`,
			perms: []string{"plugin.publish"},
		},
		{
			name:  "the key present only inside a comment sentence",
			src:   `// the plugin.publish permission is declared elsewhere`,
			perms: []string{"plugin.publish"},
		},
		{
			name:   "a scope built from parts",
			src:    `{Permission: "plugin.publish", Scopes: []Scope{Scope(family + ":" + verb)}}`,
			perms:  []string{"plugin.publish"},
			scopes: []string{"plugin:publish"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.NotEmpty(t, catalogueFindings(tt.src, tt.perms, tt.scopes),
				"AUTHZ001 must reject this source; it accepted it, so the gate is not checking "+
					"what it claims to")
		})
	}
}

// catalogueFindings returns every key that is not present in src as a whole quoted literal.
//
// It looks for the QUOTED form — `"plugin.publish"` with the quotes — which is what makes the
// prose in this repository, including the comment above that names the very key being checked,
// not a match.
func catalogueFindings(src string, perms, scopes []string) []string {
	var found []string
	for _, key := range perms {
		if !containsLiteral(src, key) {
			found = append(found, fmt.Sprintf("permission %q is not a whole quoted literal", key))
		}
	}
	for _, key := range scopes {
		if !containsLiteral(src, key) {
			found = append(found, fmt.Sprintf("scope %q is not a whole quoted literal", key))
		}
	}
	return found
}

func containsLiteral(src, key string) bool {
	quoted := `"` + key + `"`
	for i := 0; i+len(quoted) <= len(src); i++ {
		if src[i:i+len(quoted)] == quoted {
			return true
		}
	}
	return false
}
