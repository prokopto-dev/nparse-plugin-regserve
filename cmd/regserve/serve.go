package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/plugin"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
)

// Every timeout is named for the attack or failure it prevents. A bare number here is a number
// nobody dares change later, because its reason is gone.
const (
	readHeaderTimeout = 10 * time.Second  // Slowloris: headers dribbled forever (gosec G112)
	readTimeout       = 30 * time.Second  // RUDY: a body delivered one byte at a time
	writeTimeout      = 60 * time.Second  // a stalled client holding a response open
	idleTimeout       = 120 * time.Second // keep-alive connections nobody is using
	shutdownTimeout   = 15 * time.Second  // drain in-flight requests before exiting
)

// envSeedPath and envDBPath are consulted when the matching flag is not given, so an image can be
// configured without rewriting its command line. deploy/compose.yaml sets both.
const (
	envSeedPath = "REGSERVE_SEED_PATH"
	envDBPath   = "REGSERVE_DB_PATH"
)

// The two reasons /readyz reports when there is no catalogue behind it.
//
// Neither names a path. The detail is returned verbatim to an unauthenticated caller, and the
// container's filesystem layout is not something to publish; the path is in the boot log, which is
// where the operator reading this is going next.
var (
	errNoDatabase = errors.New("no database is configured; the server was started without --db")

	errDatabaseUnavailable = errors.New("the database could not be opened; see the server log")
)

// readiness answers /readyz. It holds either a catalogue or the reason there is not one.
//
// A named type rather than a closure because the answer has three distinct shapes — not
// configured, unopenable, and open-but-unhappy — and a closure would make which one you got depend
// on where it was built.
type readiness struct {
	cat    *plugin.Catalogue
	reason error
}

func (r readiness) Ready(ctx context.Context) error {
	if r.cat == nil {
		return r.reason
	}
	return r.cat.Ready(ctx)
}

func newServeCmd() *cobra.Command {
	var (
		addr   string
		seed   string
		dbPath string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the registry",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), addr,
				envDefault(cmd.Flags().Changed("db"), dbPath, envDBPath),
				envDefault(cmd.Flags().Changed("seed"), seed, envSeedPath))
		},
	}

	cmd.Flags().StringVar(&addr, "addr", ":8080", "listen address")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"path to the SQLite database; falls back to $"+envDBPath)
	cmd.Flags().StringVar(&seed, "seed", "",
		"path to a schema-v1 index.json to import ONCE into an empty database; "+
			"falls back to $"+envSeedPath)

	return cmd
}

func runServe(ctx context.Context, addr, dbPath, seedPath string) error {
	clk := clock.System{}
	cfg := api.Config{Version: version, Commit: commit, BuildDate: buildDate, Clock: clk}

	// The seed is read and validated BEFORE the database is touched, whether or not it will be
	// needed. LoadSeed validates through the same path the server serves with, so the alternative
	// to failing here is a container that comes up healthy and, on the day the database is empty,
	// discovers the file is unusable — which is the day it matters most. Failing now is visible in
	// `docker compose logs` in seconds.
	var seed *plugin.Seed
	if strings.TrimSpace(seedPath) != "" {
		s, err := plugin.LoadSeed(seedPath)
		if err != nil {
			return err
		}
		seed = &s
	}

	// A database that cannot be opened is logged and the server still serves: /healthz stays green
	// and /readyz explains (canonical §11). Only a failed migration or a schema downgrade is
	// fatal, because both mean the schema is not what this binary was built against.
	db, unavailable := openDatabase(ctx, dbPath)
	ready := readiness{reason: unavailable}

	if db != nil {
		defer func() {
			if err := db.Close(); err != nil {
				slog.ErrorContext(ctx, "close the database", "error", err)
			}
		}()

		cat, err := prepareCatalogue(ctx, db, clk, seed)
		if err != nil {
			return err
		}
		cfg.Catalogue = cat
		ready.cat = cat
	}

	// Readiness is registered either way. An instance with no catalogue is not a build that lacks
	// /readyz, it is an instance that is not ready — and saying which is the endpoint's whole job.
	// Registering it only sometimes turns a misconfiguration into a 404 that reads like "the old
	// image is still running".
	cfg.Readiness = ready

	srv := &http.Server{
		Addr:              addr,
		Handler:           api.New(cfg),
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		slog.InfoContext(ctx, "listening", "addr", addr, "version", version)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		slog.Info("shutting down")
		// WithoutCancel: the parent context is already cancelled — that is why we are here — and
		// passing it would abort the drain immediately, which is the opposite of a graceful stop.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// openDatabase opens the store, or explains why there is not one.
//
// It returns (nil, reason) rather than an error, because neither case is fatal: the reason is what
// /readyz will report, and the server keeps serving /healthz so an orchestrator does not
// restart-loop a container whose volume is a minute away from being remounted.
func openDatabase(ctx context.Context, path string) (*store.DB, error) {
	if strings.TrimSpace(path) == "" {
		slog.WarnContext(ctx, "no database configured; the index endpoints are not registered",
			"flag", "--db", "env", envDBPath)
		return nil, errNoDatabase
	}

	db, err := store.Open(ctx, store.Config{Path: path})
	if err != nil {
		// The path goes in the log, never in the readiness body.
		slog.ErrorContext(ctx, "could not open the database; serving without a catalogue",
			"path", path, "error", err)
		return nil, errDatabaseUnavailable
	}
	return db, nil
}

// prepareCatalogue migrates, imports a seed if the database is empty, and reports what it found.
//
// Errors here ARE fatal. A failed migration means the schema is not what this binary expects, and
// a failed import means an empty database that would serve an index with no plugins in it to every
// installed client — which is the failure that looks like success from the outside.
func prepareCatalogue(
	ctx context.Context, db *store.DB, clk clock.Clock, seed *plugin.Seed,
) (*plugin.Catalogue, error) {
	migrated, err := db.Migrate(ctx)
	if err != nil {
		return nil, err
	}
	if len(migrated.Applied) > 0 {
		slog.InfoContext(ctx, "migrations applied",
			"count", len(migrated.Applied), "schema_at", migrated.Version)
	}

	if seed != nil {
		out, err := plugin.ImportSeed(ctx, db, clk, *seed)
		switch {
		case err != nil:
			return nil, err
		case out.Skip != "":
			// Said out loud, with the reason, so that an operator who edits the seed file and
			// restarts is not left wondering why nothing changed. The reason matters: two of the
			// three mean "as designed", and the third means the file they are looking at is empty.
			slog.InfoContext(ctx, "seed file not imported",
				"path", seed.Path, "reason", string(out.Skip), "plugins_in_database", out.Existing)
		default:
			slog.InfoContext(ctx, "catalogue imported from the seed file",
				"path", seed.Path, "plugins", out.Plugins)
		}
	}

	cat := plugin.NewCatalogue(db)

	// One line at boot saying how many plugins this instance will serve. An empty catalogue is a
	// valid document and not an error, but it is also exactly what a broken transition looks like,
	// and nobody should have to fetch /index.json to find out which one they have.
	listings, err := cat.Listings(ctx)
	switch {
	case err != nil:
		slog.ErrorContext(ctx, "could not read the catalogue at boot", "error", err)
	case len(listings) == 0:
		slog.WarnContext(ctx, "the catalogue is empty; /index.json will list no plugins",
			"seed_configured", seed != nil)
	default:
		slog.InfoContext(ctx, "catalogue loaded", "plugins", len(listings))
	}

	return cat, nil
}
