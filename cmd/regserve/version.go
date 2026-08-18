package main

import (
	"encoding/json"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version, commit and build date",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Output goes to cmd.OutOrStdout() rather than fmt.Print, so tests can capture it and
			// forbidigo does not have to make an exception.
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(map[string]string{
				"version": version,
				"commit":  commit,
				"date":    buildDate,
			})
		},
	}
}
