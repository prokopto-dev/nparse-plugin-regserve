package main

import (
	"log/slog"
	"os"

	"github.com/spf13/cobra"
)

// envLogLevel is consulted when --log-level is not given. deploy/compose.yaml has always set it;
// until now nothing read it, so a container asked for debug logging and got info without saying so.
const envLogLevel = "REGSERVE_LOG_LEVEL"

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

	cmd.PersistentFlags().StringVar(&logLevel, "log-level", "info",
		"debug, info, warn or error; falls back to $"+envLogLevel)
	cmd.PersistentPreRunE = func(_ *cobra.Command, _ []string) error {
		return configureLogging(
			envDefault(cmd.PersistentFlags().Changed("log-level"), logLevel, envLogLevel))
	}

	cmd.AddCommand(newServeCmd(), newMigrateCmd(), newVersionCmd(), newHealthcheckCmd(),
		newOpenAPICmd(), newAuthzCmd(), newSeedOwnersCmd())
	return cmd
}

// envDefault resolves one setting from a flag and an environment variable.
//
// The flag wins whenever it was actually typed, including when what was typed equals the default:
// an operator who runs the container with `--log-level debug` is working around the environment,
// not asking to be overridden by it.
//
// An empty variable counts as unset. `REGSERVE_LOG_LEVEL=` in a compose file is how a value is
// cleared, and treating it as a request for "" would turn that into a parse error at boot.
func envDefault(flagChanged bool, flagValue, envKey string) string {
	if flagChanged {
		return flagValue
	}
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	return flagValue
}

func configureLogging(level string) error {
	var l slog.Level
	if err := l.UnmarshalText([]byte(level)); err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: l})))
	return nil
}
