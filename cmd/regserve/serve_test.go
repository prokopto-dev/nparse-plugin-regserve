package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/plugin"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// TestMain runs the goroutine-leak check after the suite; these tests open real databases.
func TestMain(m *testing.M) { storetest.Main(m) }

// runOut executes the command tree and returns what it wrote to stdout.
func runOut(t *testing.T, args ...string) (string, error) {
	t.Helper()

	var out bytes.Buffer
	cmd := newRootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)

	// Executed on its own line: in `return out.String(), cmd.Execute(...)` Go evaluates the buffer
	// before the command has written to it, and the test then asserts against "".
	err := cmd.ExecuteContext(t.Context())
	return out.String(), err
}

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

// TestReadiness_NoCatalogue_ExplainsItself — an instance started without a database answers
// /readyz with a reason rather than 404. The reason matters: 404 on a documented endpoint reads as
// "the old image is still deployed", which sends an operator looking in the wrong place.
//
// Neither reason may name a path. The detail is served verbatim to unauthenticated callers.
func TestReadiness_NoCatalogue_ExplainsItself(t *testing.T) {
	t.Parallel()

	for _, reason := range []error{errNoDatabase, errDatabaseUnavailable} {
		err := readiness{reason: reason}.Ready(t.Context())
		require.ErrorIs(t, err, reason)
		require.NotContains(t, err.Error(), "/etc/",
			"the detail is served to unauthenticated callers; it must not publish a filesystem layout")
		require.NotContains(t, err.Error(), "/data")
	}
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

// TestOpenDatabase_NoPath_ServesAnyway — canonical §11: a missing or unopenable database is logged
// and the server still serves, so /healthz stays green and /readyz explains. Only a failed
// migration or a schema downgrade is fatal at boot.
func TestOpenDatabase_NoPath_ServesAnyway(t *testing.T) {
	t.Parallel()

	db, reason := openDatabase(t.Context(), "")
	require.Nil(t, db)
	require.ErrorIs(t, reason, errNoDatabase)
}

// TestOpenDatabase_UnopenablePath_ServesAnyway — /data not mounted. The container answering
// "not ready, and here is why" is what the deploy's own verification catches; crashing here would
// restart-loop a container whose volume may be a minute from being remounted.
func TestOpenDatabase_UnopenablePath_ServesAnyway(t *testing.T) {
	t.Parallel()

	db, reason := openDatabase(t.Context(), filepath.Join(t.TempDir(), "absent", "regserve.db"))
	require.Nil(t, db)
	require.ErrorIs(t, reason, errDatabaseUnavailable)
}

// TestPrepareCatalogue_EmptyDatabaseWithASeed_ImportsIt — the boot path that carries the live
// catalogue into the database on the first container running this release.
//
// Without it the store-backed catalogue replaces a file-backed one that had the plugins in it, and
// the first thing every installed client sees is an index with none.
func TestPrepareCatalogue_EmptyDatabaseWithASeed_ImportsIt(t *testing.T) {
	t.Parallel()

	db := storetest.New(t)
	seed, err := plugin.LoadSeed(writeSeed(t, marshalSeed(t, registry.SchemaVersion, validPlugin())))
	require.NoError(t, err)

	cat, err := prepareCatalogue(t.Context(), db, clock.System{}, &seed)
	require.NoError(t, err)

	got, err := cat.Listings(t.Context())
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, validPlugin().ID, got[0].ID)
}

// TestPrepareCatalogue_NoSeed_LeavesTheDatabaseAlone — the shape of every boot after the transition,
// once the seed mount is removed from the droplet.
func TestPrepareCatalogue_NoSeed_LeavesTheDatabaseAlone(t *testing.T) {
	t.Parallel()

	db := storetest.New(t)
	cat, err := prepareCatalogue(t.Context(), db, clock.System{}, nil)
	require.NoError(t, err)

	got, err := cat.Listings(t.Context())
	require.NoError(t, err)
	require.Empty(t, got)
}

// TestMigrateCommand_FreshDatabase_AppliesAndReports — `make migrate` runs this, and so does an
// operator asking what schema a file is at. Reporting through stdout as JSON means a script can
// read the answer without parsing a log.
func TestMigrateCommand_FreshDatabase_AppliesAndReports(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "regserve.db")

	out, err := runOut(t, "migrate", "--db", path)
	require.NoError(t, err)
	require.Contains(t, out, `"schema"`)
	require.Contains(t, out, "initial_schema")

	// Idempotent: a second run applies nothing and still succeeds, which is what makes it safe to
	// put in a Makefile people run without thinking.
	again, err := runOut(t, "migrate", "--db", path)
	require.NoError(t, err)
	require.Contains(t, again, `"applied": []`)
}

// TestMigrateCommand_NoDatabase_IsFatal — unlike serve, doing nothing here while exiting 0 is how a
// deploy reports success against a database it never touched.
func TestMigrateCommand_NoDatabase_IsFatal(t *testing.T) {
	t.Parallel()

	err := run(t, "migrate")
	require.ErrorIs(t, err, store.ErrNoPath)
}

// TestServe_DatabasePath_FlagBeatsEnvironment — deploy/compose.yaml sets REGSERVE_DB_PATH and the
// Dockerfile declares it; until this release the binary ignored both.
//
// Not parallel: t.Setenv forbids it.
func TestServe_DatabasePath_FlagBeatsEnvironment(t *testing.T) {
	fromEnv := filepath.Join(t.TempDir(), "from-env", "regserve.db")
	fromFlag := filepath.Join(t.TempDir(), "from-flag", "regserve.db")

	t.Run("the variable is used when the flag is absent", func(t *testing.T) {
		t.Setenv(envDBPath, fromEnv)

		_, err := runOut(t, "migrate")
		require.ErrorContains(t, err, fromEnv)
	})

	t.Run("the flag wins when both are set", func(t *testing.T) {
		t.Setenv(envDBPath, fromEnv)

		_, err := runOut(t, "migrate", "--db", fromFlag)
		require.ErrorContains(t, err, fromFlag)
		require.NotContains(t, err.Error(), fromEnv)
	})
}

// --- first boot ------------------------------------------------------------------------------

// dialAttemptWindow bounds the wait for the listener. Generous because it only elapses when the
// server never comes up at all, and short enough that a wedged boot fails the suite rather than
// hanging CI until the job timeout.
const dialAttemptWindow = 15 * time.Second

// reservePort asks the kernel for a free port and closes it again.
//
// runServe opens its own listener; the point is to know the address BEFORE it does, because the
// assertion below has to be racing the boot rather than following it.
func reservePort(ctx context.Context, t *testing.T) string {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// waitForAccept returns at the first instant a TCP connection to addr succeeds.
//
// No sleep between attempts, deliberately. Sleeping would hand the server time to finish booting
// and the test would then assert against a settled process — which is the one state nobody needed
// a test for. The whole value here is arriving as early as a client possibly can.
func waitForAccept(ctx context.Context, t *testing.T, addr string) {
	t.Helper()

	ctx, cancel := context.WithTimeout(ctx, dialAttemptWindow)
	defer cancel()

	var d net.Dialer
	for ctx.Err() == nil {
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			continue
		}
		require.NoError(t, conn.Close())
		return
	}
	t.Fatalf("the server never accepted a connection on %s", addr)
}

// statusOf performs one GET and returns the status code.
func statusOf(ctx context.Context, t *testing.T, addr, path string) int {
	t.Helper()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+path, nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	_, err = io.Copy(io.Discard, resp.Body)
	require.NoError(t, err)
	return resp.StatusCode
}

// TestServe_FirstBoot_EveryRouteAnswersTheInstantThePortAccepts — the first-boot ordering, pinned.
//
// The Phase 1 deploy (run 32193784028, attempt 1) failed verification with a 404 roughly one second
// after the container started, and the first explanation offered was that this window exists: the
// listener accepting while the catalogue is still being built, so `cfg.Catalogue` is nil, so
// registerIndex was never called and /index.json 404s.
//
// That window does not exist. runServe migrates, imports the seed and builds the catalogue before
// it constructs the handler, and constructs the handler before ListenAndServe — so by the time
// anything can connect, every route is registered. But that ordering is a property of one
// function, invisible at every call site, and reordering it would break no other test in this
// suite. It is asserted here at the earliest moment it is observable: the instant the port accepts
// a connection, every route the deploy checks must already answer.
//
// The database file is a path that does not exist yet, which is what a fresh volume is.
func TestServe_FirstBoot_EveryRouteAnswersTheInstantThePortAccepts(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	addr := reservePort(ctx, t)
	dbPath := filepath.Join(t.TempDir(), "regserve.db")
	seedPath := writeSeed(t, marshalSeed(t, registry.SchemaVersion, validPlugin()))

	done := make(chan error, 1)
	go func() { done <- runServe(ctx, addr, dbPath, seedPath) }()

	waitForAccept(ctx, t, addr)

	// Exactly the three the deploy's verify step fetches, in the order it fetches them.
	for _, path := range []string{"/healthz", "/readyz", "/index.json"} {
		require.Equal(t, http.StatusOK, statusOf(ctx, t, addr, path),
			"%s must answer the instant the listener accepts: the deploy checks it one second "+
				"after the container starts, and a 404 there is what sent Phase 1 red", path)
	}

	cancel()
	require.NoError(t, <-done)
}

// TestServe_NoCatalogue_ReadyzExplainsRatherThanVanishing — the signature a nil catalogue actually
// produces, pinned because a deploy failure was diagnosed with it.
//
// When run 32193784028 answered /healthz and then 404'd, the question was whether the application
// had come up without a catalogue or the edge had not finished routing to it. That was answerable
// only because the two look different from outside: a nil catalogue leaves /index.json
// unregistered (404) while /readyz stays registered and answers 503 WITH A REASON. A 404 on
// /readyz is not a response this binary can produce, so a 404 there means the request never
// reached it — which is how the 404 was traced to the proxy rather than the server.
//
// If /readyz ever becomes conditional too, that inference stops holding and the next deploy
// failure is unreadable from its log. This is the test that says so.
func TestServe_NoCatalogue_ReadyzExplainsRatherThanVanishing(t *testing.T) {
	t.Parallel()

	// The configuration runServe builds when the database could not be opened: readiness is
	// always supplied, the catalogue is not.
	srv := httptest.NewServer(api.New(api.Config{Readiness: readiness{reason: errNoDatabase}}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")

	require.Equal(t, http.StatusOK, statusOf(t.Context(), t, addr, "/healthz"),
		"liveness never depends on the database")
	require.Equal(t, http.StatusServiceUnavailable, statusOf(t.Context(), t, addr, "/readyz"),
		"a nil catalogue must answer 503 and say why; 404 here would mean the route is gone")
	require.Equal(t, http.StatusNotFound, statusOf(t.Context(), t, addr, "/index.json"),
		"a route that exists but cannot work is worse than an honest 404")
}
