package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

// run executes the real command tree, so what is under test is what a container runs — including
// the flag wiring and the environment fallbacks, which is exactly where the deploy was broken.
func run(t *testing.T, args ...string) error {
	t.Helper()

	cmd := newRootCmd()
	cmd.SetArgs(args)
	// Cobra prints the error itself; the assertions read the returned one, and a test log full of
	// deliberately-provoked errors makes a real failure harder to find.
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	return cmd.ExecuteContext(t.Context())
}

// writeSeed writes raw to a file in a fresh temp dir and returns its path.
func writeSeed(t *testing.T, raw []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "seed.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

// marshalSeed renders a seed document from the registry types rather than a JSON literal, so this
// file never restates the wire format that internal/registry owns.
func marshalSeed(t *testing.T, schema int, plugins ...registry.Plugin) []byte {
	t.Helper()

	raw, err := json.Marshal(registry.Index{SchemaVersion: schema, Plugins: plugins})
	require.NoError(t, err)
	return raw
}

func validPlugin() registry.Plugin {
	return registry.Plugin{
		ID:   "merchant-mode",
		Name: "Merchant Mode",
		Latest: registry.Release{
			Version:     "1.0.0",
			URL:         "https://example.com/merchant-mode.zip",
			SHA256:      strings.Repeat("a", 64),
			RequiresSDK: registry.DefaultRequiresSDK,
		},
	}
}

// TestServe_UnusableSeed_FailsBeforeListening — a seed the server cannot use must kill the process,
// not be shrugged off.
//
// The container is started with --seed and the file is bind-mounted from the host, so every one of
// these is a real deployment failure: the mount is missing (Docker then creates a DIRECTORY where
// the file should be), the file was truncated mid-copy, or somebody hand-edited it. Booting anyway
// would serve 404 or a malformed index to every installed client while /healthz reported "ok" —
// the failure nobody sees. Crashing is what makes the deploy's own verification catch it.
//
// Every case must also name the path: an operator reading `docker compose logs` needs to know
// which file, not just that "a" file was wrong.
func TestServe_UnusableSeed_FailsBeforeListening(t *testing.T) {
	t.Parallel()

	badSHA := validPlugin()
	badSHA.Latest.SHA256 = "not-a-hash"

	tests := []struct {
		name    string
		seed    func(t *testing.T) string
		wantErr string
	}{
		{
			name:    "the file does not exist",
			seed:    func(t *testing.T) string { return filepath.Join(t.TempDir(), "absent.json") },
			wantErr: "read seed file",
		},
		{
			// What a missing bind-mount source actually looks like: Docker creates a directory.
			name:    "the path is a directory",
			seed:    func(t *testing.T) string { return t.TempDir() },
			wantErr: "read seed file",
		},
		{
			name:    "the file is empty",
			seed:    func(t *testing.T) string { return writeSeed(t, nil) },
			wantErr: "parse seed file",
		},
		{
			name:    "the json is truncated",
			seed:    func(t *testing.T) string { return writeSeed(t, []byte(`{"plugins":[`)) },
			wantErr: "parse seed file",
		},
		{
			name: "a listing would not satisfy the client's parser",
			seed: func(t *testing.T) string {
				return writeSeed(t, marshalSeed(t, registry.SchemaVersion, badSHA))
			},
			wantErr: "parse seed file",
		},
		{
			name: "the document is from a newer schema than this build understands",
			seed: func(t *testing.T) string {
				return writeSeed(t, marshalSeed(t, registry.SchemaVersion+1, validPlugin()))
			},
			wantErr: "parse seed file",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := tc.seed(t)
			err := run(t, "serve", "--addr", "127.0.0.1:0", "--seed", path)

			require.Error(t, err, "a server with an unusable seed must not start")
			require.ErrorContains(t, err, tc.wantErr)
			require.ErrorContains(t, err, path,
				"the error must name the file an operator has to go and fix")
		})
	}
}

// TestServe_SeedPath_FlagBeatsEnvironment — deploy/compose.yaml sets REGSERVE_* variables, and
// until this existed the binary read none of them.
//
// Not parallel: t.Setenv forbids it, and the alternative — testing the resolution helper alone —
// would leave the wiring between the flag and the variable untested, which is the half that was
// actually broken.
func TestServe_SeedPath_FlagBeatsEnvironment(t *testing.T) {
	fromEnv := filepath.Join(t.TempDir(), "from-env.json")
	fromFlag := filepath.Join(t.TempDir(), "from-flag.json")

	t.Run("the variable is used when the flag is absent", func(t *testing.T) {
		t.Setenv(envSeedPath, fromEnv)

		err := run(t, "serve", "--addr", "127.0.0.1:0")
		require.ErrorContains(t, err, fromEnv)
	})

	t.Run("the flag wins when both are set", func(t *testing.T) {
		t.Setenv(envSeedPath, fromEnv)

		err := run(t, "serve", "--addr", "127.0.0.1:0", "--seed", fromFlag)
		require.ErrorContains(t, err, fromFlag)
		require.NotContains(t, err.Error(), fromEnv)
	})
}

// TestCatalogueReadiness_NoCatalogue_ExplainsItself — an instance started without a seed answers
// /readyz with a reason rather than 404. The reason matters: 404 on a documented endpoint reads as
// "the old image is still deployed", which sends an operator looking in the wrong place.
func TestCatalogueReadiness_NoCatalogue_ExplainsItself(t *testing.T) {
	t.Parallel()

	err := catalogueReadiness{}.Ready(t.Context())
	require.ErrorIs(t, err, errNoCatalogue)
	require.NotContains(t, err.Error(), "/etc/",
		"the detail is served to unauthenticated callers; it must not publish a filesystem layout")
}

// TestEnvDefault_EmptyVariable_CountsAsUnset — `REGSERVE_LOG_LEVEL=` in a compose file is how a
// value is cleared. Reading it as a request for "" would fail slog's level parser at boot, so an
// empty .env line would crash-loop the container.
func TestEnvDefault_EmptyVariable_CountsAsUnset(t *testing.T) {
	t.Setenv(envLogLevel, "")
	require.Equal(t, "info", envDefault(false, "info", envLogLevel))

	t.Setenv(envLogLevel, "debug")
	require.Equal(t, "debug", envDefault(false, "info", envLogLevel))
	require.Equal(t, "warn", envDefault(true, "warn", envLogLevel),
		"an operator who typed the flag is working around the environment, not asking for it")
}
