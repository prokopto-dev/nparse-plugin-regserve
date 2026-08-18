// Package api holds every HTTP route in this service. Gate ROUTE001 enforces that.
//
// Routes live in one tree so that "what does this service expose" is answerable by reading a
// directory, and so the coverage tests — which walk the route registry to assert every operation
// declares a permission — cannot be defeated by a route registered somewhere they do not look.
package api

import (
	"context"
	"net/http"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api/middleware"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

// BasePath is the product API. The index endpoints deliberately sit OUTSIDE it — their shape is
// pinned by a parser we do not own, so they must not move when the product API versions. See
// ADR-0009 and canonical §6.
const BasePath = "/api/v1"

// Catalogue is what the API needs in order to render the index.
//
// A consumer-declared interface rather than a concrete store type: it keeps internal/api free of
// database/sql (gate SQL001), and it lets the index endpoints be tested against a fixture without
// a database at all.
type Catalogue interface {
	// Listings returns every publicly visible plugin, in any order. NewIndex sorts.
	Listings(ctx context.Context) ([]registry.Plugin, error)

	// Listing returns one plugin. It must return ErrListingNotFound when the id is unknown or not
	// publicly visible — a delisted plugin is indistinguishable from a missing one to a client.
	Listing(ctx context.Context, id core.PluginID) (registry.Plugin, error)
}

// ReadyChecker reports whether the service can serve traffic that touches the database.
type ReadyChecker interface {
	Ready(ctx context.Context) error
}

// Config is the only argument to New.
//
// One struct rather than a long parameter list, because every caller — the serve command, the
// tests, and later the spec generator — should be constructing the same thing, and a positional
// list of six optional dependencies is a list somebody eventually passes in the wrong order.
type Config struct {
	// Version, Commit and BuildDate are ldflags stamps, reported by GET /api/v1/meta.
	Version   string
	Commit    string
	BuildDate string

	// Clock is injected. A nil Clock falls back to the system clock so tests that do not care
	// about time do not have to say so.
	Clock clock.Clock

	// Catalogue backs the index endpoints. A nil Catalogue means those routes are not registered
	// at all, rather than registered and returning 500 — a route that exists but cannot work is
	// worse than an honest 404.
	Catalogue Catalogue

	// Readiness backs /readyz. Nil means the endpoint is not registered.
	Readiness ReadyChecker
}

// New builds the HTTP handler.
func New(cfg Config) http.Handler {
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}

	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", handleHealthz)
	if cfg.Readiness != nil {
		mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
			handleReadyz(w, r, cfg.Readiness)
		})
	}

	if cfg.Catalogue != nil {
		registerIndex(mux, cfg.Catalogue)
	}

	return middleware.RequestID(mux)
}
