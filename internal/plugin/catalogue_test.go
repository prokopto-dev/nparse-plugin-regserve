package plugin_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/plugin"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

func seedFile(t *testing.T, plugins ...registry.Plugin) string {
	t.Helper()

	raw, err := json.Marshal(registry.Index{SchemaVersion: registry.SchemaVersion, Plugins: plugins})
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "seed.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

func listing(id string) registry.Plugin {
	return registry.Plugin{
		ID:   id,
		Name: "Test " + id,
		Latest: registry.Release{
			Version:     "1.0.0",
			URL:         "https://example.com/" + id + ".zip",
			SHA256:      strings.Repeat("c", 64),
			RequiresSDK: registry.DefaultRequiresSDK,
		},
	}
}

// TestStatic_Ready_LoadedCatalogue_IsReady — /readyz is what the deploy and Traefik ask, so a
// catalogue that loaded and renders must answer 200. A readiness check that is 503 on a healthy
// instance gets ignored, and then it is 503 on a broken one too and nobody notices.
func TestStatic_Ready_LoadedCatalogue_IsReady(t *testing.T) {
	t.Parallel()

	cat, err := plugin.LoadStatic(seedFile(t, listing("alpha"), listing("beta")))
	require.NoError(t, err)
	require.NoError(t, cat.Ready(t.Context()))

	got, err := cat.Listings(t.Context())
	require.NoError(t, err)
	require.Len(t, got, 2)
}

// TestLoadStatic_EmptyCatalogue_IsReady — an index with no plugins is a valid document, not a
// broken one. Reporting it unready would make a fresh instance look like a failed deploy.
func TestLoadStatic_EmptyCatalogue_IsReady(t *testing.T) {
	t.Parallel()

	cat, err := plugin.LoadStatic(seedFile(t))
	require.NoError(t, err)
	require.NoError(t, cat.Ready(t.Context()))
}
