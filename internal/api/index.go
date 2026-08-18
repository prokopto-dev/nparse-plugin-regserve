package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

// ErrListingNotFound is what a Catalogue returns for an id that is unknown or not publicly
// visible. The two are the same answer on purpose: a client cannot tell a delisted plugin from one
// that never existed, and neither can an attacker enumerating ids.
var ErrListingNotFound = errors.New("listing not found")

// PathIndex and PathPluginIndex are pinned URLs.
//
// PathIndex is what a user pastes into nParse+ to add this registry, and what DEFAULT_REGISTRY_URL
// will eventually point at. PathPluginIndex serves the same schema-v1 document scoped to one id,
// which is the shape PluginMeta.update_url declares. Neither may move: the first is recorded as
// provenance in every install, and the second is compiled into published plugins. See ADR-0009.
const (
	PathIndex       = "/index.json"
	PathPluginIndex = "/plugins/{id}/index.json"
)

func registerIndex(mux *http.ServeMux, cat Catalogue) {
	mux.HandleFunc("GET "+PathIndex, func(w http.ResponseWriter, r *http.Request) {
		handleIndex(w, r, cat)
	})
	mux.HandleFunc("GET "+PathPluginIndex, func(w http.ResponseWriter, r *http.Request) {
		handlePluginIndex(w, r, cat)
	})
}

func handleIndex(w http.ResponseWriter, r *http.Request, cat Catalogue) {
	listings, err := cat.Listings(r.Context())
	if err != nil {
		slog.ErrorContext(r.Context(), "load catalogue", "error", err)
		WriteProblem(w, r, NewProblem(http.StatusInternalServerError, CodeInternalError,
			"could not load the catalogue"))
		return
	}
	writeIndex(w, r, listings)
}

func handlePluginIndex(w http.ResponseWriter, r *http.Request, cat Catalogue) {
	id, err := core.ParsePluginID(r.PathValue("id"))
	if err != nil {
		// A malformed id cannot name a real plugin, so this is 404 rather than 400: the resource
		// does not exist, and saying "your id is malformed" invites probing for the ones that are
		// merely absent.
		WriteProblem(w, r, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin"))
		return
	}

	p, err := cat.Listing(r.Context(), id)
	switch {
	case errors.Is(err, ErrListingNotFound):
		WriteProblem(w, r, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin"))
		return
	case err != nil:
		slog.ErrorContext(r.Context(), "load listing", "plugin_id", id.String(), "error", err)
		WriteProblem(w, r, NewProblem(http.StatusInternalServerError, CodeInternalError,
			"could not load the listing"))
		return
	}
	writeIndex(w, r, []registry.Plugin{p})
}

// writeIndex renders and serves a schema-v1 document.
//
// Rendering happens before any byte of the response is written, because NewIndex validates: a
// listing that would not satisfy the client's parser must produce a 500 that we can see in a log,
// not a 200 carrying a document that makes every user's plugin browser report the registry as
// malformed.
func writeIndex(w http.ResponseWriter, r *http.Request, listings []registry.Plugin) {
	idx, err := registry.NewIndex(listings)
	if err != nil {
		slog.ErrorContext(r.Context(), "render index", "error", err)
		WriteProblem(w, r, NewProblem(http.StatusInternalServerError, CodeInternalError,
			"the catalogue could not be rendered"))
		return
	}

	body, err := json.Marshal(idx)
	if err != nil {
		slog.ErrorContext(r.Context(), "marshal index", "error", err)
		WriteProblem(w, r, NewProblem(http.StatusInternalServerError, CodeInternalError,
			"the catalogue could not be rendered"))
		return
	}

	// The client ignores cache headers entirely — it sends no If-None-Match and no
	// If-Modified-Since. These are set for the proxies and CDNs between us and it, which do not.
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=60")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(body); err != nil {
		slog.ErrorContext(r.Context(), "write index", "error", err)
	}
}
