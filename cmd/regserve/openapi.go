package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
)

// newOpenAPICmd writes the OpenAPI document.
//
// The document is generated from the route registry rather than written by hand, so this command
// is the whole of `make gen`'s openapi step: it registers every operation exactly as the server
// does and marshals the result. Gate GEN001 runs it in CI and fails on any diff against the
// checked-in openapi/openapi.json, which is what makes "never hand-edit a generated file" a
// mechanism rather than a request.
func newOpenAPICmd() *cobra.Command {
	var out string

	cmd := &cobra.Command{
		Use:   "openapi",
		Short: "Write the OpenAPI document for this build",
		Long: "openapi renders the OpenAPI 3.1 document describing every route this binary\n" +
			"serves. With no --out it goes to stdout.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			doc, err := api.SpecJSON()
			if err != nil {
				return err
			}
			if out == "" {
				_, err := cmd.OutOrStdout().Write(doc)
				return err
			}
			// 0o600 rather than 0o644: this is the mode every file this repository creates, and
			// the difference does not reach the committed file — git records only the exec bit.
			if err := os.WriteFile(out, doc, 0o600); err != nil {
				return fmt.Errorf("write the openapi document: %w", err)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&out, "out", "", "write to this path instead of stdout")
	return cmd
}
