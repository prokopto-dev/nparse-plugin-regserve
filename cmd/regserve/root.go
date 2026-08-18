package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// Stamped by -ldflags at build time. Defaults are what a `go run` reports, and saying "dev"
// out loud is better than reporting a version that does not exist.
var (
	version   = "dev"
	commit    = "none"
	buildDate = "unknown"
)

func newRootCmd() *cobra.Command {
	var logLevel string

	cmd := &cobra.Command{
		Use:   "regserve",
		Short: "The nParse+ plugin registry server",
		Long: "regserve is the live plugin registry for nParse+.\n\n" +
			"It serves the schema-v1 index that nParse+ clients read, and the API that plugin\n" +
			"pipelines publish through.",

		// Usage on an error is noise: the error is almost never "you typed the flags wrong", and
		// printing forty lines of help buries the one line that matters.
		SilenceUsage: true,
	}

	cmd.PersistentFlags().StringVar(&logLevel, "log-level", "info", "debug, info, warn or error")
	cmd.PersistentPreRunE = func(_ *cobra.Command, _ []string) error {
		return configureLogging(logLevel)
	}

	cmd.AddCommand(newServeCmd(), newVersionCmd(), newHealthcheckCmd())
	return cmd
}

func configureLogging(level string) error {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
	return nil
}
