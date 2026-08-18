package main

import (
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/spf13/cobra"
)

// The container image is FROM scratch: no shell, no curl, nothing to run a HEALTHCHECK with except
// the binary itself. This subcommand is that.
//
// NET001 allows this file by name. The rule exists to stop unguarded clients reaching
// attacker-supplied URLs; this dials a fixed loopback address that cannot be influenced by a
// request, and it is the only exception. See docs/concepts/invariants.md.
const healthcheckTimeout = 3 * time.Second

func newHealthcheckCmd() *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "healthcheck",
		Short: "Probe the local /healthz endpoint and exit non-zero if it is not serving",
		Long: "Intended for a container HEALTHCHECK. It probes liveness only and never touches the\n" +
			"database — a registry whose disk is briefly unavailable should not be restart-looped\n" +
			"when it would recover on its own. Use /readyz for readiness.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Loopback is not a hostname lookup away: resolving one would let a DNS entry decide
			// what the healthcheck probes.
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return fmt.Errorf("parse addr %q: %w", addr, err)
			}
			if host == "" || host == "0.0.0.0" || host == "::" {
				host = "127.0.0.1"
			}

			client := &http.Client{Timeout: healthcheckTimeout} //nolint:gosec // loopback only
			url := "http://" + net.JoinHostPort(host, port) + "/healthz"

			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, url, nil)
			if err != nil {
				return err
			}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("probe %s: %w", url, err)
			}
			defer func() { _ = resp.Body.Close() }()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("probe %s: status %d", url, resp.StatusCode)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&addr, "addr", ":8080", "address the server is listening on")
	return cmd
}
