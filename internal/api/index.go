package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

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

// indexCacheControl is for the proxies and CDNs between us and the client. The client itself
// ignores cache headers entirely — it sends no If-None-Match and no If-Modified-Since.
const indexCacheControl = "public, max-age=60"

// indexOutput is the response shape for both index operations, and its Body is []byte on purpose.
//
// Huma writes a []byte body to the response verbatim: no marshaller, no content negotiation, no
// transformer, no field re-ordering, nothing added. That is the whole reason the index endpoints
// are allowed to sit behind a framework at all. The bytes are produced by registry.Index.Marshal,
// in the one package that knows the format, and travel through this layer as an opaque blob.
//
// Content-Type is set explicitly rather than left to negotiation, and not only for the reason
// above: with no Content-Type header at all, net/http would sniff the body and label a JSON
// document `text/plain`.
type indexOutput struct {
	ContentType  string `header:"Content-Type"`
	CacheControl string `header:"Cache-Control"`
	Body         []byte
}

// pluginIndexInput is the per-plugin feed's path parameter.
//
// It deliberately carries no `pattern` tag. Huma would validate the id against it and answer 422
// naming the pattern, where this service answers 404: a malformed id cannot name a real plugin,
// and reporting *why* it was rejected invites probing for the ids that are merely absent. The
// handler parses it with core.ParsePluginID and reports the same "no such plugin" either way.
type pluginIndexInput struct {
	ID string `path:"id" doc:"The plugin id, as declared in PluginMeta.id"`
}

func registerIndex(api huma.API, cat Catalogue) {
	register(api, Public(), huma.Operation{
		OperationID: "getIndex",
		Method:      http.MethodGet,
		Path:        PathIndex,
		Summary:     "The registry index",
		Description: "Every publicly listed plugin, with its latest approved release, as a " +
			"schema-v1 index document.",
		Tags:      []string{"index"},
		Errors:    []int{http.StatusInternalServerError},
		Responses: indexResponses(),
	}, func(ctx context.Context, _ *struct{}) (*indexOutput, error) {
		listings, err := cat.Listings(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "load catalogue", "error", err)
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError,
				"could not load the catalogue")
		}
		return renderIndex(ctx, listings)
	})

	register(api, Public(), huma.Operation{
		OperationID: "getPluginIndex",
		Method:      http.MethodGet,
		Path:        PathPluginIndex,
		Summary:     "One plugin's index",
		Description: "The same schema-v1 document scoped to a single plugin, which is the shape " +
			"PluginMeta.update_url declares. An author can serve updates from here without a " +
			"listing in the full index.",
		Tags:      []string{"index"},
		Errors:    []int{http.StatusNotFound, http.StatusInternalServerError},
		Responses: indexResponses(),
	}, func(ctx context.Context, in *pluginIndexInput) (*indexOutput, error) {
		id, err := core.ParsePluginID(in.ID)
		if err != nil {
			return nil, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
		}

		p, err := cat.Listing(ctx, id)
		switch {
		case errors.Is(err, ErrListingNotFound):
			return nil, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
		case err != nil:
			slog.ErrorContext(ctx, "load listing", "plugin_id", id.String(), "error", err)
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError,
				"could not load the listing")
		}
		return renderIndex(ctx, []registry.Plugin{p})
	})
}

// indexResponses describes the 200 the index operations return.
//
// It is written out rather than reflected from the output type because the output type is []byte,
// which Huma would describe as a base64 string — true of the Go field and useless to a reader. It
// is also NOT a schema of the document: the schema belongs to the client's pydantic models, is
// generated and published upstream, and a copy of it here would be a second definition of a format
// this repository is not allowed to define twice (SCHEMA002).
func indexResponses() map[string]*huma.Response {
	return map[string]*huma.Response{
		"200": {
			Description: "A schema-v1 index document, as defined by " + registry.SchemaURI +
				". The format is owned upstream by the nParse+ client and is not versioned with " +
				"this API.",
			Content: map[string]*huma.MediaType{
				contentTypeJSON: {Schema: &huma.Schema{Type: "object"}},
			},
		},
	}
}

// renderIndex renders listings into the bytes of a response.
//
// Rendering happens before any byte of the response is written, because NewIndex validates: a
// listing that would not satisfy the client's parser must produce a 500 that we can see in a log,
// not a 200 carrying a document that makes every user's plugin browser report the registry as
// malformed.
func renderIndex(ctx context.Context, listings []registry.Plugin) (*indexOutput, error) {
	idx, err := registry.NewIndex(listings)
	if err != nil {
		slog.ErrorContext(ctx, "render index", "error", err)
		return nil, NewProblem(http.StatusInternalServerError, CodeInternalError,
			"the catalogue could not be rendered")
	}

	body, err := idx.Marshal()
	if err != nil {
		slog.ErrorContext(ctx, "marshal index", "error", err)
		return nil, NewProblem(http.StatusInternalServerError, CodeInternalError,
			"the catalogue could not be rendered")
	}

	return &indexOutput{
		ContentType:  contentTypeJSON,
		CacheControl: indexCacheControl,
		Body:         body,
	}, nil
}
