// Command regserve is the nParse+ plugin registry server.
//
// This file is the only place context.Background() and os.Exit belong. Everything else takes a
// context and returns an error.
package main

import (
	"context"
	"os"
)

func main() {
	if err := newRootCmd().ExecuteContext(context.Background()); err != nil {
		// Cobra has already printed the error; SilenceErrors is off. Exit non-zero so a shell,
		// a healthcheck or a systemd unit can tell.
		os.Exit(1)
	}
}
