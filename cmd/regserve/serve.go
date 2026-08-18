package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/plugin"
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

func newServeCmd() *cobra.Command {
	var (
		addr string
		seed string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the registry",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), addr, seed)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", ":8080", "listen address")
	cmd.Flags().StringVar(&seed, "seed", "",
		"path to a schema-v1 index.json to serve (temporary, until the store lands)")

	return cmd
}

func runServe(ctx context.Context, addr, seed string) error {
	cfg := api.Config{Version: version, Commit: commit, BuildDate: buildDate}

	if seed != "" {
		cat, err := plugin.LoadStatic(seed)
		if err != nil {
			return err
		}
		cfg.Catalogue = cat
		slog.InfoContext(ctx, "catalogue loaded from seed file", "path", seed)
	} else {
		// Registering the index routes with no catalogue behind them would answer 500 where an
		// honest 404 says "this instance has no catalogue configured".
		slog.WarnContext(ctx, "no seed file given; the index endpoints are not registered")
	}

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
