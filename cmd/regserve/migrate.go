package main

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
)

// The server migrates itself at boot, so this command is not on the deployment path. It exists for
// the two moments that are not a boot: applying migrations to a local database while developing
// (`make migrate`), and answering "what schema is this file at" during an incident without
// starting a server that would begin serving from it.
func newMigrateCmd() *cobra.Command {
	var dbPath string

	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Apply pending database migrations and exit",
		Long: "Applies every embedded migration that has not run, in order, and prints what it did.\n\n" +
			"Migrations are forward-only: there is no down command, and recovery from a bad one is\n" +
			"restoring the snapshot taken immediately before it ran.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMigrate(cmd, envDefault(cmd.Flags().Changed("db"), dbPath, envDBPath))
		},
	}

	cmd.Flags().StringVar(&dbPath, "db", "",
		"path to the SQLite database; falls back to $"+envDBPath)

	return cmd
}

// The named return is what lets the deferred Close report a failure that would otherwise be
// discarded: a database that could not be closed may not have checkpointed its WAL.
func runMigrate(cmd *cobra.Command, dbPath string) (err error) {
	// Unlike `serve`, a missing path is fatal here: migrating is the entire job, and doing nothing
	// while exiting 0 is how a deploy reports success against a database it never touched. The
	// error says what to type, because the person seeing it is mid-incident often enough.
	if strings.TrimSpace(dbPath) == "" {
		return fmt.Errorf("%w: pass --db or set $%s", store.ErrNoPath, envDBPath)
	}

	db, err := store.Open(cmd.Context(), store.Config{Path: dbPath})
	if err != nil {
		return err
	}
	defer func() {
		if cerr := db.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("close the database: %w", cerr)
		}
	}()

	out, err := db.Migrate(cmd.Context())
	if err != nil {
		return err
	}

	applied := make([]string, 0, len(out.Applied))
	for _, m := range out.Applied {
		applied = append(applied, m.Path)
	}

	// Output goes to cmd.OutOrStdout() as JSON so a script can read it, and so tests can capture
	// it. The server's own migration reports through slog instead.
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	// The key is "schema" rather than the more obvious spelling: gate SCHEMA002 keeps wire-format
	// field names inside internal/registry, and this document is not that document.
	return enc.Encode(map[string]any{
		"database": db.Path(),
		"applied":  applied,
		"schema":   out.Version,
	})
}
