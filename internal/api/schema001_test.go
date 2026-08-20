package api_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry/schematest"
)

// Gate SCHEMA001 — the document a client RECEIVES validates against the vendored upstream schema.
//
// It used to validate registry.NewIndex()'s return value: the renderer's output, re-marshalled by
// the test itself. That answered "does the renderer produce a valid document", which is a smaller
// question than the one that matters, and it stopped being sufficient the moment the HTTP layer
// gained a framework (ADR-0012). Everything that can go wrong between a correct Index value and a
// broken response is invisible to a test that never makes a request:
//
//   - content negotiation serving CBOR, or any other format, to a client that sent `*/*`;
//   - a `$schema` member, a `Link` header, or any other key a framework adds to a body;
//   - `plugins` serialising as null instead of [];
//   - field order or omitempty changing under a different marshaller;
//   - the pinned paths moving.
//
// So these tests run a real HTTP server, make a real request, and validate the bytes off the wire.
// A regression in any of the above is now a red test rather than a thing SCHEMA001 would have
// caught only if it happened inside the renderer.
//
// The schema is generated upstream from the pydantic models the client parses with. If one of
// these fails, the server drifted from the client — do not edit the schema to agree.

// serve starts a real server and returns its base URL. httptest.NewServer rather than a
// ResponseRecorder deliberately: a recorder never serialises a header, never sniffs a content
// type, and never sends anything, and two of those are failure modes this gate is about.
func serve(t *testing.T, cat api.Catalogue) *httptest.Server {
	t.Helper()

	srv := httptest.NewServer(api.New(api.Config{Catalogue: cat}))
	t.Cleanup(srv.Close)
	return srv
}

// response is what a test looks at: a status, the headers, and the bytes. It is a value rather
// than the *http.Response deliberately — a response handed back to a caller is a body somebody has
// to remember to close, and `bodyclose` is right to complain about every one of them. Here it is
// read and closed in the one function that opened it.
type response struct {
	status int
	header http.Header
	body   []byte

	// cookies is what the response set. Parsed here rather than by each caller, because
	// http.Response knows how and a hand-written Set-Cookie parser is a second one to be wrong.
	cookies []*http.Cookie
}

// fetch performs a GET and reads the whole response. accept is sent verbatim when non-empty; the
// empty string means the request carries no Accept header at all, which is a case that matters:
// content negotiation with no Accept header is where a default gets to decide.
func fetch(t *testing.T, srv *httptest.Server, path, accept string) response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
	require.NoError(t, err)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return response{status: resp.StatusCode, header: resp.Header.Clone(), body: body, cookies: resp.Cookies()}
}

func schemaV1(t *testing.T) *jsonschema.Schema {
	t.Helper()
	return schematest.Compile(t)
}

// TestSchema001_ServedIndex_ValidatesAgainstUpstreamSchema is the gate.
func TestSchema001_ServedIndex_ValidatesAgainstUpstreamSchema(t *testing.T) {
	t.Parallel()

	s := schemaV1(t)
	srv := serve(t, fakeCatalogue{plugins: []registry.Plugin{testPlugin("beta"), testPlugin("alpha")}})

	for _, path := range []string{api.PathIndex, "/plugins/alpha/index.json"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			resp := fetch(t, srv, path, "")
			require.Equal(t, http.StatusOK, resp.status)
			require.NoError(t, schematest.ValidateBytes(t, s, resp.body),
				"the bytes this server sent must satisfy the schema the client parses with")
		})
	}
}

// TestSchema001_MinimalListing_ValidatesAgainstUpstreamSchema covers the other end: only the
// fields the schema marks required, with the nullable one actually null. Optional fields
// defaulting to "" is the documented behaviour, so a listing that omits them must still be served.
func TestSchema001_MinimalListing_ValidatesAgainstUpstreamSchema(t *testing.T) {
	t.Parallel()

	srv := serve(t, fakeCatalogue{plugins: []registry.Plugin{{
		ID:   "minimal",
		Name: "Minimal",
		Latest: registry.Release{
			Version:     "1.0.0",
			URL:         "https://example.com/minimal.zip",
			SHA256:      strings.Repeat("a", 64),
			RequiresSDK: registry.DefaultRequiresSDK,
		},
	}}})

	resp := fetch(t, srv, api.PathIndex, "")
	require.Equal(t, http.StatusOK, resp.status)
	require.NoError(t, schematest.ValidateBytes(t, schemaV1(t), resp.body))
	require.Contains(t, string(resp.body), `"min_app_version":null`,
		"the client's model declares the field nullable; an absent key and an explicit null are "+
			"different things to the humans who read this document")
}

// TestSchema001_ReleaseNotes_AreAdditiveOnTheWire — the additive field, checked from both ends.
//
// The vendored schema does not describe `release_notes`: it is generated from the pydantic models
// a RELEASED client parses with, and those releases predate the field. That is exactly why this
// gate has to see it. The schema leaves `additionalProperties` unset, mirroring a parser that
// ignores unknown keys, so an added member validates — which means validation alone cannot tell an
// intended additive field from an accidental one. The second half of the test is the half that
// matters: a listing with NO notes must carry no such key, so the document every existing listing
// produces is unchanged.
func TestSchema001_ReleaseNotes_AreAdditiveOnTheWire(t *testing.T) {
	t.Parallel()

	s := schemaV1(t)

	withNotes := testPlugin("annotated")
	withNotes.Latest.ReleaseNotes = "Fixed the price graph on servers with no recent sales."

	srv := serve(t, fakeCatalogue{plugins: []registry.Plugin{withNotes, testPlugin("plain")}})

	resp := fetch(t, srv, api.PathIndex, "")
	require.Equal(t, http.StatusOK, resp.status)
	require.NoError(t, schematest.ValidateBytes(t, s, resp.body),
		"a document carrying the additive field must still satisfy the schema a released client "+
			"parses with; if it does not, the field is not additive")

	// Off the wire, not out of the renderer: the point of this gate is the bytes.
	require.Contains(t, string(resp.body), `"release_notes":"Fixed the price graph`)

	plain := fetch(t, srv, "/plugins/plain/index.json", "")
	require.Equal(t, http.StatusOK, plain.status)
	require.NoError(t, schematest.ValidateBytes(t, s, plain.body))
	require.NotContains(t, string(plain.body), "release_notes",
		"a listing with no notes must be served exactly as it was before the field existed; an "+
			"empty key on every listing is a change to every document already in the field")
}

// TestSchema001_EmptyCatalogue_ServesAValidEmptyDocument — a fresh instance has no plugins, and
// that is a legitimate document rather than an error. `null` for the list would make the client's
// pydantic model reject the whole index, so every user would see "registry is malformed" instead
// of an empty browse list.
func TestSchema001_EmptyCatalogue_ServesAValidEmptyDocument(t *testing.T) {
	t.Parallel()

	resp := fetch(t, serve(t, fakeCatalogue{}), api.PathIndex, "")

	require.Equal(t, http.StatusOK, resp.status)
	require.NoError(t, schematest.ValidateBytes(t, schemaV1(t), resp.body))
	require.Contains(t, string(resp.body), `"plugins":[]`)
	require.NotContains(t, string(resp.body), `"plugins":null`)
}

// TestSchema001_ServedDocument_IsExactlyWhatTheRendererProduced pins the bytes.
//
// Schema validation cannot see an ADDED key: the vendored schema does not set
// additionalProperties:false at the document level, because the client's parser ignores unknown
// keys and the schema describes that parser. So a framework that injected `$schema` — Huma's
// default configuration does exactly this — would pass every validation above while changing the
// document we serve. Comparing the response body to the renderer's own bytes is what catches it.
func TestSchema001_ServedDocument_IsExactlyWhatTheRendererProduced(t *testing.T) {
	t.Parallel()

	plugins := []registry.Plugin{testPlugin("alpha"), testPlugin("beta")}

	idx, err := registry.NewIndex(plugins)
	require.NoError(t, err)
	want, err := idx.Marshal()
	require.NoError(t, err)

	resp := fetch(t, serve(t, fakeCatalogue{plugins: plugins}), api.PathIndex, "")

	require.Equal(t, string(want), string(resp.body),
		"the HTTP layer must serve the renderer's bytes unchanged: not re-marshalled, not "+
			"re-ordered, and with nothing added")
	require.NotContains(t, string(resp.body), "$schema",
		"a $schema member is a key we did not write, in the one format we do not own")
}

// TestSchema001_ContentNegotiation_IsAlwaysJSON is the CBOR guard.
//
// Huma negotiates the response format from Accept against a package-level map of formats that any
// import can add to — `import _ ".../formats/cbor"` anywhere in the build is enough. A client
// sending `*/*` takes the first offered format, so CBOR being registered at all would serve a
// binary document to every released nParse+ install, which would report the registry as
// unreachable. This asserts the outcome rather than the configuration, so it fails whether the
// cause is a config change, a stray import, or a Huma upgrade that changes the default.
func TestSchema001_ContentNegotiation_IsAlwaysJSON(t *testing.T) {
	t.Parallel()

	s := schemaV1(t)
	srv := serve(t, fakeCatalogue{plugins: []registry.Plugin{testPlugin("alpha")}})

	accepts := []struct {
		name   string
		header string
	}{
		{name: "no accept header at all", header: ""},
		{name: "anything", header: "*/*"},
		{name: "cbor", header: "application/cbor"},
		{name: "cbor preferred over json", header: "application/cbor;q=1.0, application/json;q=0.1"},
		{name: "cbor and anything", header: "application/cbor, */*"},
		{name: "yaml", header: "application/yaml"},
		{name: "html, as a browser sends", header: "text/html,application/xhtml+xml,*/*;q=0.8"},
		{name: "json", header: "application/json"},
	}

	for _, tt := range accepts {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			for _, path := range []string{api.PathIndex, "/plugins/alpha/index.json"} {
				resp := fetch(t, srv, path, tt.header)

				require.Equal(t, http.StatusOK, resp.status,
					"an Accept header we cannot satisfy must still serve the index, not 406")
				require.Equal(t, "application/json", resp.header.Get("Content-Type"),
					"the index is JSON for every caller; %q must not change that", tt.header)
				require.True(t, strings.HasPrefix(string(resp.body), "{"),
					"a CBOR body would start with a binary tag, not an object")
				require.NoError(t, schematest.ValidateBytes(t, s, resp.body))
			}
		})
	}
}

// TestSchema001_PinnedPaths_HaveNotMoved — the two URLs are permanent.
//
// The first is recorded as provenance in every install that ever fetched from here; the second is
// compiled into published plugins as PluginMeta.update_url. Neither can be moved by us at any
// point in the foreseeable future (ADR-0009), so the constants are pinned by a test as well as by
// prose, and the live paths are asserted rather than assumed.
func TestSchema001_PinnedPaths_HaveNotMoved(t *testing.T) {
	t.Parallel()

	require.Equal(t, "/index.json", api.PathIndex)
	require.Equal(t, "/plugins/{id}/index.json", api.PathPluginIndex)

	srv := serve(t, fakeCatalogue{plugins: []registry.Plugin{testPlugin("alpha")}})
	for _, path := range []string{"/index.json", "/plugins/alpha/index.json"} {
		resp := fetch(t, srv, path, "")
		require.Equal(t, http.StatusOK, resp.status, "%s must answer at exactly this path", path)
	}
}

// TestSchema001_SchemaVersion_IsOne pins the constant and the served value.
//
// This test exists to be annoying. Changing schema_version is a breaking change for every nParse+
// release in the field — they refuse the whole index and tell the user to update — so it should
// take a deliberate act and a conversation, not a one-character edit that CI waves through.
func TestSchema001_SchemaVersion_IsOne(t *testing.T) {
	t.Parallel()

	require.Equal(t, 1, registry.SchemaVersion,
		"bumping schema_version strands every released client; see ADR-0009")

	resp := fetch(t, serve(t, fakeCatalogue{}), api.PathIndex, "")
	idx, err := registry.ParseIndex(resp.body)
	require.NoError(t, err)
	require.Equal(t, 1, idx.SchemaVersion, "the served document must declare schema_version 1")
}
