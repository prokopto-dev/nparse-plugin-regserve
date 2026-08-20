package authz_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
)

// The generator that writes the scope enum into db/schema.hcl.
//
// Canonical §4: the Go constants are the source, and `make gen` writes the CHECK between GENERATED
// markers. GEN001 catches drift in the checked-in file; these cover the generator itself, which
// GEN001 cannot — a generator that emitted an empty list would agree with a schema containing an
// empty list forever.

func TestWriteScopeCheck_WritesEveryCatalogueScope(t *testing.T) {
	t.Parallel()

	in := []byte("  check \"x\" {\n" +
		"    # GENERATED: authz scopes\n" +
		"    expr = \"scope IN ('stale:value')\"\n" +
		"    # END GENERATED\n" +
		"  }\n")

	out, err := authz.WriteScopeCheck(in)
	require.NoError(t, err)

	rendered := string(out)
	require.NotContains(t, rendered, "stale:value", "the old expression is replaced, not appended")
	for _, s := range authz.Scopes() {
		require.Contains(t, rendered, "'"+s.String()+"'", "the CHECK omits scope %q", s)
	}
	require.Contains(t, rendered, "# GENERATED: authz scopes")
	require.Contains(t, rendered, "# END GENERATED")
	require.Contains(t, rendered, "    expr =", "the rewrite keeps the surrounding indentation")
}

func TestWriteScopeCheck_IsIdempotent(t *testing.T) {
	t.Parallel()

	in := []byte("  # GENERATED: authz scopes\n  expr = \"scope IN ('nothing')\"\n  # END GENERATED\n")

	once, err := authz.WriteScopeCheck(in)
	require.NoError(t, err)
	twice, err := authz.WriteScopeCheck(once)
	require.NoError(t, err)

	// `make migration` diffs the schema with Atlas. A generator whose output moved on every run
	// would make every diff look like it might have changed something.
	require.Equal(t, string(once), string(twice))
}

// TestWriteScopeCheck_WithNoMarkers_IsAnError — it does not invent somewhere to write.
//
// A generator that appends when it cannot find its markers produces a schema with two CHECKs, and
// the second is the one nobody notices.
func TestWriteScopeCheck_WithNoMarkers_IsAnError(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
	}{
		{name: "no markers at all", in: "table \"pat_scope\" {}\n"},
		{name: "only the opening marker", in: "# GENERATED: authz scopes\nexpr = \"\"\n"},
		{name: "empty file", in: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			out, err := authz.WriteScopeCheck([]byte(tt.in))
			require.ErrorIs(t, err, authz.ErrNoScopeMarkers)
			require.Nil(t, out)
		})
	}
}

// TestSchemaHCL_ScopeCheck_MatchesTheCatalogue — the checked-in file, against the source.
//
// GEN001 asserts the same thing by regenerating, and needs Atlas and sqlc on PATH to do it. This
// runs under plain `make test`, so the drift is caught on a laptop with no generator toolchain as
// well as in the CI job that has one.
func TestSchemaHCL_ScopeCheck_MatchesTheCatalogue(t *testing.T) {
	t.Parallel()

	const path = "../../db/schema.hcl"

	current, err := os.ReadFile(path)
	require.NoError(t, err, "the schema file is the single declarative truth; it must be readable")

	updated, err := authz.WriteScopeCheck(current)
	require.NoError(t, err)
	require.Equal(t, string(current), string(updated),
		"db/schema.hcl's generated scope CHECK is stale: run `make gen-authz`")

	// Vacancy: if the markers ever moved somewhere that holds no scopes, everything above would
	// still pass over a file that says nothing.
	require.Contains(t, string(current), "'"+authz.Scopes()[0].String()+"'")
	require.NotEmpty(t, authz.Scopes())
}

// TestSchemaHCL_ScopeCheck_IsTheOnlyPlaceScopesAreListedInSQL — one source, mechanised.
//
// Canonical §5 forbids a hand-written scope list anywhere. The generated CHECK is the exception
// that proves it, and this asserts nothing in db/queries has grown a second one.
func TestSchemaHCL_ScopeCheck_IsTheOnlyPlaceScopesAreListedInSQL(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("../../db/queries")
	require.NoError(t, err)
	require.NotEmpty(t, entries)

	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		src, err := os.ReadFile("../../db/queries/" + e.Name())
		require.NoError(t, err)

		for _, s := range authz.Scopes() {
			require.NotContains(t, string(src), "'"+s.String()+"'",
				"db/queries/%s hard-codes scope %q; the catalogue is the one source", e.Name(), s)
		}
	}
}
