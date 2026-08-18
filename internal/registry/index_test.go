package registry_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

const schemaPath = "testdata/index-v1.schema.json"

// schemaURI is the $id the vendored document declares. The compiler resolves references by URI, so
// this has to match what is in the file rather than being a path.
const schemaURI = "https://prokopto-dev.github.io/nparseplus-plugins/schema/index-v1.schema.json"

func compiledSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()

	f, err := os.Open(schemaPath)
	require.NoError(t, err, "open the vendored upstream schema")
	defer func() { _ = f.Close() }()

	doc, err := jsonschema.UnmarshalJSON(f)
	require.NoError(t, err, "parse the vendored upstream schema")

	c := jsonschema.NewCompiler()
	require.NoError(t, c.AddResource(schemaURI, doc), "register the schema resource")

	s, err := c.Compile(schemaURI)
	require.NoError(t, err, "compile the vendored upstream schema")
	return s
}

// validateAgainstSchema round-trips through encoding/json so the schema sees exactly the bytes a
// client would, not the Go values. A field that marshals differently than it looks is the whole
// class of bug this is here to catch.
func validateAgainstSchema(t *testing.T, s *jsonschema.Schema, idx registry.Index) error {
	t.Helper()

	raw, err := json.Marshal(idx)
	require.NoError(t, err, "marshal the index")

	var generic any
	require.NoError(t, json.Unmarshal(raw, &generic), "re-parse the marshalled index")

	return s.Validate(generic)
}

func sampleRelease() registry.Release {
	min := "2.1.0"
	return registry.Release{
		Version:       "0.5.0",
		URL:           "https://github.com/prokopto-dev/nparseplus-merchantmode/releases/download/v0.5.0/merchant_mode.zip",
		SHA256:        "87478a4fa3463cd831e5157a5b3f6e3c8fe6e6ff321f777162f6ab06cfccc742",
		RequiresSDK:   registry.DefaultRequiresSDK,
		MinAppVersion: &min,
	}
}

func samplePlugin() registry.Plugin {
	return registry.Plugin{
		ID:          "merchant-mode",
		Name:        "Merchant Mode",
		Description: "Turn your inventory into linkable WTS auction macros.",
		Author:      "prokopto-dev",
		Homepage:    "https://github.com/prokopto-dev/nparseplus-merchantmode",
		Latest:      sampleRelease(),
	}
}

// --- SCHEMA001 --------------------------------------------------------------------------------

// TestSchema001_RenderedIndex_ValidatesAgainstUpstreamSchema is gate SCHEMA001.
//
// The schema in testdata is generated upstream from the pydantic models a released client parses
// with. If this fails, the renderer drifted from the client — do not edit the schema to agree.
func TestSchema001_RenderedIndex_ValidatesAgainstUpstreamSchema(t *testing.T) {
	t.Parallel()

	s := compiledSchema(t)
	idx, err := registry.NewIndex([]registry.Plugin{samplePlugin()})
	require.NoError(t, err)

	require.NoError(t, validateAgainstSchema(t, s, idx),
		"the rendered index must satisfy the schema the client parses with")
}

// TestSchema001_MinimalPlugin_ValidatesAgainstUpstreamSchema covers the other end: only the fields
// the schema marks required, with the nullable one actually null. Optional fields defaulting to ""
// is the documented behaviour, so a listing that omits them must still be renderable.
func TestSchema001_MinimalPlugin_ValidatesAgainstUpstreamSchema(t *testing.T) {
	t.Parallel()

	s := compiledSchema(t)
	idx, err := registry.NewIndex([]registry.Plugin{{
		ID:   "minimal",
		Name: "Minimal",
		Latest: registry.Release{
			Version:     "1.0.0",
			URL:         "https://example.com/minimal.zip",
			SHA256:      strings.Repeat("a", 64),
			RequiresSDK: registry.DefaultRequiresSDK,
		},
	}})
	require.NoError(t, err)

	require.NoError(t, validateAgainstSchema(t, s, idx))
}

// TestSchema001_SchemaVersion_IsOne pins the constant.
//
// This test exists to be annoying. Changing SchemaVersion is a breaking change for every nParse+
// release in the field — they refuse the whole index and tell the user to update — so it should
// take a deliberate act and a conversation, not a one-character edit that CI waves through.
func TestSchema001_SchemaVersion_IsOne(t *testing.T) {
	t.Parallel()
	require.Equal(t, 1, registry.SchemaVersion,
		"bumping schema_version strands every released client; see ADR-0009")
}

// TestSchema001_EmptyCatalogue_IsValid — an index with no plugins is a legitimate document, not an
// error. A fresh instance serves one, and the client must render an empty browse list rather than
// report the registry as malformed.
func TestSchema001_EmptyCatalogue_IsValid(t *testing.T) {
	t.Parallel()

	s := compiledSchema(t)
	idx, err := registry.NewIndex(nil)
	require.NoError(t, err)

	require.NoError(t, validateAgainstSchema(t, s, idx))

	raw, err := json.Marshal(idx)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"plugins":[]`,
		"an empty catalogue must marshal as [], never null — pydantic rejects null for a list")
}

// --- Wire-shape expectations ------------------------------------------------------------------

func TestNewIndex_Plugins_AreSortedByID(t *testing.T) {
	t.Parallel()

	mk := func(id string) registry.Plugin {
		p := samplePlugin()
		p.ID = id
		return p
	}
	idx, err := registry.NewIndex([]registry.Plugin{mk("zeta"), mk("alpha"), mk("mid-plugin")})
	require.NoError(t, err)

	got := []string{idx.Plugins[0].ID, idx.Plugins[1].ID, idx.Plugins[2].ID}
	require.Equal(t, []string{"alpha", "mid-plugin", "zeta"}, got,
		"the client renders in array order; unstable order reshuffles the browse list on refresh")
}

func TestNewIndex_NilMinAppVersion_MarshalsAsNull(t *testing.T) {
	t.Parallel()

	p := samplePlugin()
	p.Latest.MinAppVersion = nil
	idx, err := registry.NewIndex([]registry.Plugin{p})
	require.NoError(t, err)

	raw, err := json.Marshal(idx)
	require.NoError(t, err)
	require.Contains(t, string(raw), `"min_app_version":null`)
}

func TestValidate_RejectsBadListings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*registry.Plugin)
		wantErr error
	}{
		{
			name:    "http url",
			mutate:  func(p *registry.Plugin) { p.Latest.URL = "http://example.com/x.zip" },
			wantErr: registry.ErrNotHTTPS,
		},
		{
			name:    "uppercase sha256",
			mutate:  func(p *registry.Plugin) { p.Latest.SHA256 = strings.ToUpper(p.Latest.SHA256) },
			wantErr: registry.ErrBadSHA256,
		},
		{
			name:    "short sha256",
			mutate:  func(p *registry.Plugin) { p.Latest.SHA256 = "abc123" },
			wantErr: registry.ErrBadSHA256,
		},
		{
			name:    "empty name",
			mutate:  func(p *registry.Plugin) { p.Name = "  " },
			wantErr: registry.ErrNoName,
		},
		{
			name:    "empty version",
			mutate:  func(p *registry.Plugin) { p.Latest.Version = "" },
			wantErr: registry.ErrNoVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := samplePlugin()
			tt.mutate(&p)
			_, err := registry.NewIndex([]registry.Plugin{p})
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestValidate_RejectsInvalidAndDuplicateIDs(t *testing.T) {
	t.Parallel()

	t.Run("invalid id", func(t *testing.T) {
		t.Parallel()
		p := samplePlugin()
		p.ID = "Not-Valid"
		_, err := registry.NewIndex([]registry.Plugin{p})
		require.Error(t, err)
	})

	t.Run("duplicate id", func(t *testing.T) {
		t.Parallel()
		_, err := registry.NewIndex([]registry.Plugin{samplePlugin(), samplePlugin()})
		require.ErrorIs(t, err, registry.ErrDuplicatePlugin)
	})
}

// --- SIZE001 ----------------------------------------------------------------------------------

// TestSize001_RenderedIndex_StaysUnderTheClientCap is gate SIZE001.
//
// MaxIndexBytes is the client's limit, not ours: past it the client aborts the read and every user
// sees "could not reach the registry" at once. This fails at 80% so the alarm arrives while there
// is still room to do something about it, rather than at the moment it breaks.
func TestSize001_RenderedIndex_StaysUnderTheClientCap(t *testing.T) {
	t.Parallel()

	const budget = registry.MaxIndexBytes * 8 / 10

	plugins := make([]registry.Plugin, 0, 500)
	for i := range 500 {
		p := samplePlugin()
		p.ID = fmt.Sprintf("plugin-%04d", i)
		p.Description = strings.Repeat("a plausibly long plugin description. ", 10)
		plugins = append(plugins, p)
	}

	idx, err := registry.NewIndex(plugins)
	require.NoError(t, err)

	raw, err := json.Marshal(idx)
	require.NoError(t, err)

	require.Less(t, len(raw), budget,
		"500 listings must fit well inside the client's %d-byte cap; at %d bytes the catalogue is "+
			"approaching a hard failure for every installed client at once",
		registry.MaxIndexBytes, len(raw))
}
