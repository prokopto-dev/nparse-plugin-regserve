package api_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

// The index endpoints are structurally immune to content negotiation: their body is []byte, which
// Huma writes verbatim without consulting Accept at all. That immunity is exactly why they cannot
// be the canary. Registering a second format — `import _ ".../formats/cbor"` adds one to Huma's
// package-level DefaultFormats, and a config that used that map would pick it up — would leave
// /index.json serving JSON while every OTHER response in the service quietly changed shape.
//
// So these tests watch the responses Huma DOES marshal: the health probes and the problem
// documents. If a format ever joins the map, this is where it shows up first, and it shows up as a
// red test rather than as a support ticket from somebody whose client stopped parsing.

// hostileAccepts are headers a proxy, a browser, a curl user or a misconfigured client might send.
var hostileAccepts = []string{
	"",
	"*/*",
	"application/cbor",
	"application/cbor, */*",
	"application/cbor;q=1.0, application/json;q=0.1",
	"application/x-msgpack",
	"text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"application/json",
}

func TestNegotiation_MarshalledResponses_AreAlwaysJSON(t *testing.T) {
	t.Parallel()

	srv := serve(t, fakeCatalogue{plugins: []registry.Plugin{testPlugin("alpha")}})

	for _, accept := range hostileAccepts {
		t.Run("accept="+accept, func(t *testing.T) {
			t.Parallel()

			resp := fetch(t, srv, "/healthz", accept)

			require.Equal(t, http.StatusOK, resp.status)
			require.Equal(t, "application/json", resp.header.Get("Content-Type"),
				"a response Huma marshals must be JSON for every Accept header; %q got through",
				accept)

			var decoded map[string]any
			require.NoError(t, json.Unmarshal(resp.body, &decoded),
				"the body must be JSON, not a binary format that merely claims to be")
			require.Equal(t, "ok", decoded["status"])
		})
	}
}

func TestNegotiation_ProblemDocuments_AreAlwaysProblemJSON(t *testing.T) {
	t.Parallel()

	srv := serve(t, fakeCatalogue{})

	for _, accept := range hostileAccepts {
		t.Run("accept="+accept, func(t *testing.T) {
			t.Parallel()

			resp := fetch(t, srv, "/plugins/never-existed/index.json", accept)

			require.Equal(t, http.StatusNotFound, resp.status)
			require.Equal(t, "application/problem+json", resp.header.Get("Content-Type"),
				"RFC 9457 is the error format for every caller; %q must not change it", accept)

			var p api.Problem
			require.NoError(t, json.Unmarshal(resp.body, &p))
			require.Equal(t, api.CodeNotFound, p.Code)
		})
	}
}

// TestNegotiation_NosniffIsSetOnEveryResponse — including the ones no handler produced.
//
// The 404 for an unrouted path comes from the mux, not from a handler, and it is served to
// whatever sent the request. Setting the header in a wrapper rather than in each handler is what
// makes "every response" true rather than "every response somebody remembered".
func TestNegotiation_NosniffIsSetOnEveryResponse(t *testing.T) {
	t.Parallel()

	srv := serve(t, fakeCatalogue{plugins: []registry.Plugin{testPlugin("alpha")}})

	for _, path := range []string{
		api.PathIndex,
		"/plugins/alpha/index.json",
		"/plugins/never-existed/index.json",
		"/healthz",
		"/nothing-is-routed-here",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			resp := fetch(t, srv, path, "")
			require.Equal(t, "nosniff", resp.header.Get("X-Content-Type-Options"))
		})
	}
}
