package main

import (
	"bytes"
	"fmt"
	"os"

	"github.com/danielgtaylor/huma/v2"
	"github.com/spf13/cobra"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
)

// newAuthzCmd writes the generated artefacts of the permission catalogue.
//
// Canonical §5 makes internal/authz the ONE source for permissions and scopes, and generating the
// documentation from it is how "a hand-written permission list anywhere else is forbidden" becomes
// something other than a request. Gate GEN001 runs this and fails on any diff, so an edit to the
// page is caught rather than reviewed for.
//
// It lives in cmd rather than in internal/authz because the "declared by" column is derived from
// the ROUTE REGISTRY: internal/api imports internal/authz, so the package cannot look the other
// way without a cycle. This command sits above both and hands the answer down — which also means
// the page can only list operations the server actually registers.
func newAuthzCmd() *cobra.Command {
	var docs, schema string

	cmd := &cobra.Command{
		Use:   "authz",
		Short: "Write the generated permission catalogue documentation",
		Long: "authz renders docs/reference/permissions.md from the catalogue in\n" +
			"internal/authz, with the operations that declare each permission taken from the\n" +
			"route registry. With no --docs it goes to stdout.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			page, err := authz.RenderDocs(permissionUsage())
			if err != nil {
				return fmt.Errorf("render the permissions page: %w", err)
			}
			if docs == "" {
				_, err := cmd.OutOrStdout().Write(page)
				return err
			}
			if err := os.WriteFile(docs, page, 0o600); err != nil {
				return fmt.Errorf("write the permissions page: %w", err)
			}
			if schema == "" {
				return nil
			}
			return rewriteScopeCheck(schema)
		},
	}

	cmd.Flags().StringVar(&docs, "docs", "",
		"write the permissions page to this path instead of stdout")
	cmd.Flags().StringVar(&schema, "schema", "",
		"rewrite the generated scope CHECK in this HCL schema file")
	return cmd
}

// rewriteScopeCheck writes the scope enum into db/schema.hcl between its GENERATED markers.
//
// Read, rewrite, compare, write. The comparison is not an optimisation: `make migration` diffs the
// schema with Atlas, and a file whose mtime moved on every generator run would make every diff look
// like it might have changed something.
func rewriteScopeCheck(path string) error {
	current, err := os.ReadFile(path) // #nosec G304 -- a path this repository owns, from a Makefile
	if err != nil {
		return fmt.Errorf("read the schema file %s: %w", path, err)
	}

	updated, err := authz.WriteScopeCheck(current)
	if err != nil {
		return fmt.Errorf("rewrite the scope check in %s: %w", path, err)
	}
	if bytes.Equal(current, updated) {
		return nil
	}
	if err := os.WriteFile(path, updated, 0o600); err != nil {
		return fmt.Errorf("write the schema file %s: %w", path, err)
	}
	return nil
}

// permissionUsage walks the generated OpenAPI document and reports which operations declare which
// permission. A public operation is recorded under the empty permission, which is how the page can
// list "operations that declare no permission" without a second source for that fact.
func permissionUsage() authz.Usage {
	usage := authz.Usage{}
	spec := api.Spec()

	for path, item := range spec.Paths {
		for method, op := range map[string]*huma.Operation{
			"GET": item.Get, "PUT": item.Put, "POST": item.Post, "DELETE": item.Delete,
			"OPTIONS": item.Options, "HEAD": item.Head, "PATCH": item.Patch, "TRACE": item.Trace,
		} {
			if op == nil {
				continue
			}
			key := authz.Permission("")
			if name, ok := op.Extensions[api.ExtPermission].(string); ok {
				key = authz.Permission(name)
			}
			usage[key] = append(usage[key], method+" "+path)
		}
	}
	return usage
}
