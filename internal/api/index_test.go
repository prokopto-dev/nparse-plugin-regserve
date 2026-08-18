package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api/middleware"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

// fakeCatalogue is a hand-written stand-in rather than a generated mock: the interface is two
// methods, and a fake whose failure modes are visible in the test file is easier to trust than a
// mock whose expectations live in a builder chain.
type fakeCatalogue struct {
	plugins []registry.Plugin
	err     error
}

func (f fakeCatalogue) Listings(context.Context) ([]registry.Plugin, error) {
	return f.plugins, f.err
}

func (f fakeCatalogue) Listing(_ context.Context, id core.PluginID) (registry.Plugin, error) {
	if f.err != nil {
		return registry.Plugin{}, f.err
	}
	for _, p := range f.plugins {
		if p.ID == id.String() {
			return p, nil
		}
	}
	return registry.Plugin{}, api.ErrListingNotFound
}

func testPlugin(id string) registry.Plugin {
	min := "2.1.0"
	return registry.Plugin{
		ID:       id,
		Name:     "Test " + id,
		Homepage: "https://example.com/" + id,
		Latest: registry.Release{
			Version:       "1.0.0",
			URL:           "https://example.com/" + id + ".zip",
			SHA256:        strings.Repeat("b", 64),
			RequiresSDK:   registry.DefaultRequiresSDK,
			MinAppVersion: &min,
		},
	}
}

func newServer(t *testing.T, cat api.Catalogue) http.Handler {
	t.Helper()
	return api.New(api.Config{Catalogue: cat})
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil))
	return rec
}

func TestIndex_WithListings_ReturnsSchemaV1(t *testing.T) {
	t.Parallel()

	h := newServer(t, fakeCatalogue{plugins: []registry.Plugin{testPlugin("beta"), testPlugin("alpha")}})
	rec := get(t, h, api.PathIndex)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	require.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))

	var idx registry.Index
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &idx))
	require.Equal(t, registry.SchemaVersion, idx.SchemaVersion)
	require.Equal(t, []string{"alpha", "beta"}, []string{idx.Plugins[0].ID, idx.Plugins[1].ID},
		"the handler must serve sorted output; the client renders in array order")
}

// TestIndex_EmptyCatalogue_ServesEmptyArray — a fresh instance has no plugins, and that is a valid
// document. Serving `null` for the list would make the client's pydantic model reject the whole
// index, so every user would see "registry is malformed" rather than an empty browse list.
func TestIndex_EmptyCatalogue_ServesEmptyArray(t *testing.T) {
	t.Parallel()

	rec := get(t, newServer(t, fakeCatalogue{}), api.PathIndex)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"plugins":[]`)
	require.NotContains(t, rec.Body.String(), `"plugins":null`)
}

// TestIndex_CatalogueError_IsFiveHundredNotPartial — never serve a partial catalogue.
//
// A truncated index is indistinguishable from "those plugins were delisted", so the user sees
// plugins silently disappear. Failing the request is louder and smaller.
func TestIndex_CatalogueError_IsFiveHundredNotPartial(t *testing.T) {
	t.Parallel()

	rec := get(t, newServer(t, fakeCatalogue{err: errors.New("database is on fire")}), api.PathIndex)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))
	require.NotContains(t, rec.Body.String(), "on fire",
		"an internal error's detail must not leak the underlying failure to the public index")
}

func TestPluginIndex_KnownPlugin_ReturnsOnlyThatPlugin(t *testing.T) {
	t.Parallel()

	h := newServer(t, fakeCatalogue{plugins: []registry.Plugin{testPlugin("alpha"), testPlugin("beta")}})
	rec := get(t, h, "/plugins/alpha/index.json")

	require.Equal(t, http.StatusOK, rec.Code)

	var idx registry.Index
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &idx))
	require.Len(t, idx.Plugins, 1, "PluginMeta.update_url feeds are scoped to one id")
	require.Equal(t, "alpha", idx.Plugins[0].ID)
	require.Equal(t, registry.SchemaVersion, idx.SchemaVersion,
		"the per-plugin feed is the same wire format, not a variant")
}

// TestPluginIndex_UnknownAndMalformed_BothReturn404 — a delisted plugin, a plugin that never
// existed and a syntactically impossible id are one answer on purpose. Distinguishing them lets
// someone enumerate ids, and tells a legitimate user nothing they can act on.
func TestPluginIndex_UnknownAndMalformed_BothReturn404(t *testing.T) {
	t.Parallel()

	h := newServer(t, fakeCatalogue{plugins: []registry.Plugin{testPlugin("alpha")}})

	for _, path := range []string{
		"/plugins/never-existed/index.json",
		"/plugins/Not-Valid/index.json",
		"/plugins/9lives/index.json",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			rec := get(t, h, path)

			require.Equal(t, http.StatusNotFound, rec.Code)
			require.Equal(t, "application/problem+json", rec.Header().Get("Content-Type"))

			var p api.Problem
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p))
			require.Equal(t, api.CodeNotFound, p.Code)
		})
	}
}

// TestIndex_NoCatalogue_RoutesAreNotRegistered — an instance with no catalogue answers 404, not
// 500. A route that exists but cannot work is worse than an honest absence.
func TestIndex_NoCatalogue_RoutesAreNotRegistered(t *testing.T) {
	t.Parallel()

	rec := get(t, api.New(api.Config{}), api.PathIndex)
	require.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHealthz_AlwaysOK_EvenWithNoCatalogue(t *testing.T) {
	t.Parallel()

	rec := get(t, api.New(api.Config{}), "/healthz")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"ok"`)
}

type failingReady struct{ err error }

func (f failingReady) Ready(context.Context) error { return f.err }

func TestReadyz_ReportsWhy(t *testing.T) {
	t.Parallel()

	t.Run("ready", func(t *testing.T) {
		t.Parallel()
		h := api.New(api.Config{Readiness: failingReady{}})
		require.Equal(t, http.StatusOK, get(t, h, "/readyz").Code)
	})

	t.Run("not ready explains itself", func(t *testing.T) {
		t.Parallel()
		h := api.New(api.Config{Readiness: failingReady{err: errors.New("migration pending")}})
		rec := get(t, h, "/readyz")

		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		require.Contains(t, rec.Body.String(), "migration pending",
			"a bare 503 turns every incident into a log-reading exercise")
	})

	t.Run("not registered without a checker", func(t *testing.T) {
		t.Parallel()
		require.Equal(t, http.StatusNotFound, get(t, api.New(api.Config{}), "/readyz").Code)
	})
}

func TestRequestID_IsAlwaysSet(t *testing.T) {
	t.Parallel()

	h := api.New(api.Config{})

	t.Run("minted when absent", func(t *testing.T) {
		t.Parallel()
		require.NotEmpty(t, get(t, h, "/healthz").Header().Get(middleware.HeaderRequestID))
	})

	t.Run("client value echoed", func(t *testing.T) {
		t.Parallel()
		rec := httptest.NewRecorder()
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
		r.Header.Set(middleware.HeaderRequestID, "client-supplied-id")
		h.ServeHTTP(rec, r)
		require.Equal(t, "client-supplied-id", rec.Header().Get(middleware.HeaderRequestID))
	})

	// A newline in an echoed header is header injection on the way out and log injection on the
	// way in, and both are silent. Reject the value; do not sanitise it into something plausible.
	t.Run("hostile client value is replaced", func(t *testing.T) {
		t.Parallel()
		for _, hostile := range []string{
			"bad\r\nX-Injected: yes",
			"bad\nsecond line",
			strings.Repeat("a", 200),
			"nul\x00byte",
		} {
			rec := httptest.NewRecorder()
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/healthz", nil)
			r.Header.Set(middleware.HeaderRequestID, hostile)
			h.ServeHTTP(rec, r)

			got := rec.Header().Get(middleware.HeaderRequestID)
			require.NotEqual(t, hostile, got)
			require.NotContains(t, got, "\n")
			require.NotContains(t, got, "\r")
			require.NotEmpty(t, got, "a rejected client id must still be replaced with a real one")
		}
	})
}
