package core_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
)

func TestParsePluginID_ValidIDs_Accepted(t *testing.T) {
	t.Parallel()

	valid := []string{
		"ab",            // the shortest legal id: 1 + minimum 1 more
		"merchant-mode", // the one in production
		"a_b-c9",        // every permitted character class
		"a" + string(make([]byte, 0)) + "bcdefghij", // ordinary
		"a123456789012345678901234567890123456789",  // exactly 40 characters, the ceiling
	}
	for _, s := range valid {
		t.Run(s, func(t *testing.T) {
			t.Parallel()
			got, err := core.ParsePluginID(s)
			require.NoError(t, err)
			require.Equal(t, s, got.String())
		})
	}
}

func TestParsePluginID_InvalidIDs_Rejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"single character", "a"},
		{"leading digit", "9lives"},
		{"leading hyphen", "-nope"},
		{"leading underscore", "_nope"},
		{"uppercase", "Merchant-Mode"},
		{"dot", "merchant.mode"},
		{"space", "merchant mode"},
		{"slash", "owner/plugin"},
		{"41 characters", "a1234567890123456789012345678901234567890"},
		{"trailing newline", "merchant-mode\n"},
		{"leading newline", "\nmerchant-mode"},
		{"non-ascii", "merchant-modé"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := core.ParsePluginID(tt.in)
			require.ErrorIs(t, err, core.ErrInvalidPluginID,
				"an id the SDK would reject must not become a claim here")
		})
	}
}

// TestParsePluginID_Pattern_MatchesTheSDK pins the published pattern.
//
// The same string appears in nparseplus_sdk.plugin.PLUGIN_ID_RE, in the client's pydantic model and
// in the vendored JSON Schema. A divergence does not fail loudly — it produces listings some
// clients accept and others drop.
func TestParsePluginID_Pattern_MatchesTheSDK(t *testing.T) {
	t.Parallel()
	require.Equal(t, `^[a-z][a-z0-9_-]{1,39}$`, core.PluginIDPattern())
}
