package plugin

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// A white-box test, deliberately.
//
// The row it feeds in — an approved release with a NULL hash — cannot be created through the
// database: release_approved_has_a_hash refuses it. That is exactly why the mapping needs a test
// here. The branch exists for the row that arrives by a route nobody has thought of, and a branch
// that has never run once is a branch that does not work.

func TestListingFrom_CompleteRow_MapsEveryField(t *testing.T) {
	t.Parallel()

	floor := "1.4.0"
	sha := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	got, err := listingFrom(sqlitegen.ListListingsRow{
		ID:                "merchant-mode",
		Name:              "Merchant Mode",
		Description:       "a description",
		Author:            "someone",
		Homepage:          "https://example.com",
		Version:           "1.2.3",
		ArtifactUrl:       "https://example.com/merchant-mode.zip",
		ArtifactSha256:    &sha,
		SdkSpecifier:      registry.DefaultRequiresSDK,
		MinimumAppVersion: &floor,
	})
	require.NoError(t, err)

	want := registry.Plugin{
		ID:          "merchant-mode",
		Name:        "Merchant Mode",
		Description: "a description",
		Author:      "someone",
		Homepage:    "https://example.com",
		Latest: registry.Release{
			Version:       "1.2.3",
			URL:           "https://example.com/merchant-mode.zip",
			SHA256:        sha,
			RequiresSDK:   registry.DefaultRequiresSDK,
			MinAppVersion: &floor,
		},
	}
	require.Empty(t, cmp.Diff(want, got))
}

// TestListingFrom_AbsentAppVersionFloor_StaysAbsent — the field is string-or-null on the wire, and
// an absent constraint is not the same statement as an empty one. Turning NULL into "" would make
// every client evaluate "" as a version floor.
func TestListingFrom_AbsentAppVersionFloor_StaysAbsent(t *testing.T) {
	t.Parallel()

	sha := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	got, err := listingFrom(sqlitegen.ListListingsRow{
		ID: "alpha", Name: "Alpha", Version: "1.0.0",
		ArtifactUrl: "https://example.com/a.zip", ArtifactSha256: &sha,
		SdkSpecifier: registry.DefaultRequiresSDK,
	})
	require.NoError(t, err)
	require.Nil(t, got.Latest.MinAppVersion)
}

// TestListingFrom_NoHash_IsAnError — never a listing with an empty hash, and never a quietly
// shorter index. The client refuses an artifact whose bytes do not match, so an empty hash is a
// plugin that cannot install; a dropped row is a plugin that looks delisted.
func TestListingFrom_NoHash_IsAnError(t *testing.T) {
	t.Parallel()

	empty := ""
	for _, sha := range []*string{nil, &empty} {
		_, err := listingFrom(sqlitegen.ListListingsRow{
			ID: "alpha", Name: "Alpha", Version: "1.0.0",
			ArtifactUrl: "https://example.com/a.zip", ArtifactSha256: sha,
			SdkSpecifier: registry.DefaultRequiresSDK,
		})
		require.ErrorIs(t, err, ErrUnservableListing)
		require.ErrorContains(t, err, "alpha", "the error must name the plugin that stopped the render")
	}
}
