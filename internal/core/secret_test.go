package core_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
)

const canary = "super-secret-oauth-client-secret"

// TestSecret_EveryRenderingPath_Redacts covers the verbs somebody reaches for while debugging,
// which is exactly when a secret is most likely to be printed and least likely to be noticed.
func TestSecret_EveryRenderingPath_Redacts(t *testing.T) {
	t.Parallel()

	s := core.NewSecret(canary)

	renderings := map[string]string{
		"String": s.String(),
		"%v":     fmt.Sprintf("%v", s),
		// staticcheck S1025 says to call String() directly, which would test nothing: the point is
		// that the %s VERB redacts, because %s is what somebody reaches for in a debug line.
		"%s":      fmt.Sprintf("%s", s), //nolint:staticcheck // exercising the verb is the test
		"%q":      fmt.Sprintf("%q", s),
		"%#v":     fmt.Sprintf("%#v", s),
		"%+v":     fmt.Sprintf("%+v", s),
		"in slog": fmt.Sprintf("client_secret=%v", s),
	}
	for name, got := range renderings {
		require.NotContains(t, got, canary, "%s leaked the secret", name)
	}
}

func TestSecret_MarshalJSON_Redacts(t *testing.T) {
	t.Parallel()

	type config struct {
		ClientSecret core.Secret `json:"client_secret"`
	}
	raw, err := json.Marshal(config{ClientSecret: core.NewSecret(canary)})
	require.NoError(t, err)
	require.NotContains(t, string(raw), canary,
		"a config struct must be safe to marshal into a log line or an error body")
	require.Contains(t, string(raw), "REDACTED")
}

func TestSecret_Reveal_ReturnsTheValue(t *testing.T) {
	t.Parallel()
	require.Equal(t, canary, core.NewSecret(canary).Reveal())
}

func TestSecret_IsZero_ReportsUnset(t *testing.T) {
	t.Parallel()
	require.True(t, core.NewSecret("").IsZero())
	require.False(t, core.NewSecret(canary).IsZero())
}
