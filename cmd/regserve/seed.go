package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity/github"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
)

// errNoOwnersPath is a run with nothing to import from.
var errNoOwnersPath = errors.New("--owners is required")

// newSeedOwnersCmd imports the static registry's ownership records.
//
// A SEPARATE command from the catalogue seed, and deliberately not part of boot. It makes one
// outbound request per handle against GitHub's unauthenticated rate limit, and a boot path that
// depends on GitHub answering is a boot path that fails when GitHub is slow. The catalogue is
// imported at boot because serving an empty index is an outage; ownership is not on that path —
// nothing a user sees depends on it.
//
// It is idempotent and additive: run it twice and the second run grants nothing. It never removes
// a grant, because once ownership can also be changed through the account surface, a re-run that
// reconciled against the file would silently undo a transfer.
func newSeedOwnersCmd() *cobra.Command {
	var (
		ownersPath string
		dbPath     string
	)

	cmd := &cobra.Command{
		Use:   "seed-owners",
		Short: "Import ownership records from the static registry's owners.json",
		Long: "seed-owners resolves each GitHub handle in owners.json to the immutable numeric\n" +
			"id behind it and records both, then grants the plugin to that account.\n\n" +
			"An account is created for a handle that has never signed in here, with its GitHub\n" +
			"identity linked, so that when the person does sign in they land on it and find\n" +
			"their plugins already there.\n\n" +
			"Safe to re-run: it grants what is missing and removes nothing.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSeedOwners(cmd, ownersPath,
				envDefault(cmd.Flags().Changed("db"), dbPath, envDBPath))
		},
	}

	cmd.Flags().StringVar(&ownersPath, "owners", "",
		"path to owners.json from prokopto-dev/nparseplus-plugins")
	cmd.Flags().StringVar(&dbPath, "db", "",
		"path to the SQLite database; falls back to $"+envDBPath)

	return cmd
}

func runSeedOwners(cmd *cobra.Command, ownersPath, dbPath string) error {
	if strings.TrimSpace(ownersPath) == "" {
		return errNoOwnersPath
	}
	if strings.TrimSpace(dbPath) == "" {
		return store.ErrNoPath
	}

	// The file is read and validated BEFORE anything is opened or asked of GitHub. A malformed
	// owners.json discovered after fifty API calls is fifty calls against a rate limit spent on a
	// run that was never going to finish.
	owners, err := ownership.LoadOwners(ownersPath)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	db, err := store.Open(ctx, store.Config{Path: dbPath})
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }() // a waiver: the command is exiting, and the import error is the one worth reporting

	// The provider is built with placeholder OAuth settings on purpose. Looking up a public
	// profile needs no token, and requiring a client secret for a read-only import would mean an
	// operator putting one on a laptop for a job that does not need it. The constructor validates
	// what a LOGIN needs, so it is given something valid and unused.
	resolver, err := github.New(github.Config{
		ClientID:     "seed-owners",
		ClientSecret: core.NewSecret("unused: this command performs no oauth flow"),
		RedirectURL:  "https://localhost/unused",
	})
	if err != nil {
		return fmt.Errorf("build the github resolver: %w", err)
	}

	out, err := ownership.SeedOwners(ctx, db, clock.System{}, resolver, owners)
	// The outcome is logged even when the import failed part-way. What it managed to grant before
	// a rate limit is exactly what somebody needs to know before running it again.
	out.Log(ctx)
	if err != nil {
		return err
	}

	// A waiver, not an oversight: a write to the command's own stdout that fails has nowhere left
	// to report the failure to, and the outcome is already in the structured log.
	_, _ = fmt.Fprintf(cmd.OutOrStdout(), //nolint:forbidigo // CLI output goes to cmd.OutOrStdout()
		"granted %d, created %d accounts, %d already held\n",
		out.Granted, out.AccountsCreated, out.AlreadyHeld)

	// A non-zero exit for a partial import. It succeeded at what it could and there is something
	// left for a human, and a command that exits 0 with a warning in its log is a command whose
	// warning nobody reads.
	if len(out.UnknownPlugins) > 0 || len(out.UnresolvedHandles) > 0 {
		_, _ = fmt.Fprintf(cmd.OutOrStdout(), //nolint:forbidigo // as above
			"%d plugin ids and %d handles need a human: see the log\n",
			len(out.UnknownPlugins), len(out.UnresolvedHandles))
		return errPartialImport
	}
	return nil
}

// errPartialImport is what a run that could not resolve everything exits with. It carries no
// detail because the detail is in the log, named rather than counted.
var errPartialImport = errors.New("some ownership records could not be imported")
