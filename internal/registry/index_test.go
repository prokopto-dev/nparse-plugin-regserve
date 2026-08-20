package registry_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

// Gate SCHEMA001 does NOT live here any more. It validates the bytes of a real HTTP response
// against the vendored upstream schema, in internal/api/schema001_test.go, because validating the
// renderer's return value cannot see anything the HTTP layer does to it afterwards — a negotiated
// format, an injected member, a re-marshalling — and the HTTP layer now has a framework in it
// (ADR-0012). What is left in this file is the renderer's own behaviour: ordering, nullability,
// the validation rules, and SIZE001.

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
//
// EVERY LISTING CARRIES NOTES AT THE 2048-BYTE CAP, which is the arithmetic ADR-0013 rests on
// rather than a pessimistic flourish: notes are the first field whose length an author controls,
// so the catalogue this gate has to survive is the one where every author used all of it. Before
// the field shipped this test measured a document that could not happen any more, which is the
// quiet way a size gate stops being one. The cap's own constant lives in internal/release next to
// the validator and the column's CHECK; the number is written out here rather than imported
// because internal/registry must not gain a second copy of it (SCHEMA002's neighbouring rule: one
// package owns one fact).
func TestSize001_RenderedIndex_StaysUnderTheClientCap(t *testing.T) {
	t.Parallel()

	const budget = registry.MaxIndexBytes * 8 / 10

	plugins := make([]registry.Plugin, 0, 500)
	for i := range 500 {
		p := samplePlugin()
		p.ID = fmt.Sprintf("plugin-%04d", i)
		p.Description = strings.Repeat("a plausibly long plugin description. ", 10)
		p.Latest.ReleaseNotes = strings.Repeat("n", 2048)
		plugins = append(plugins, p)
	}

	idx, err := registry.NewIndex(plugins)
	require.NoError(t, err)

	// Marshal, not json.Marshal: the budget is about the bytes that leave the server, and those
	// are the ones the HTTP layer writes verbatim.
	raw, err := idx.Marshal()
	require.NoError(t, err)

	// Logged rather than only asserted. The number this gate is really about is the HEADROOM, and
	// a gate that reports nothing until the day it fails gives whoever added the field that used
	// it up no warning at all.
	t.Logf("500 listings with notes at the cap render to %d bytes: %d%% of the %d-byte gate "+
		"threshold, %d%% of the client's %d-byte limit",
		len(raw), len(raw)*100/budget, budget,
		len(raw)*100/registry.MaxIndexBytes, registry.MaxIndexBytes)

	require.Less(t, len(raw), budget,
		"500 listings must fit well inside the client's %d-byte cap; at %d bytes the catalogue is "+
			"approaching a hard failure for every installed client at once",
		registry.MaxIndexBytes, len(raw))
}
