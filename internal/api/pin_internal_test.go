package api

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
)

// A token's PLUGIN PIN, enforced over HTTP.
//
// ADR-0005's containment argument has two halves: the scope says what a credential may do, and the
// pin says what it may do it to. A pin nothing compares fails open and behaves exactly like no pin
// at all — silently — so a token leaked from plugin A's pipeline would publish to plugin B. The
// route that will exercise this for real is the publish endpoint in Phase 3; the enforcement and
// its tests land with the pin rather than with the route, because the mechanism is what stops that
// route from being written wrong.
//
// An INTERNAL test because it registers synthetic operations through the unexported helper, which
// is the only way to have a plugin-scoped, token-callable route before Phase 3 has written one.

// pinnedAuthn resolves every request to one principal.
type pinnedAuthn struct{ principal auth.Principal }

func (a pinnedAuthn) Resolve(context.Context, auth.Credentials) (auth.Principal, error) {
	return a.principal, nil
}

// pinServer registers two synthetic routes and serves them: one that declares which path parameter
// names a plugin, and one that does not.
func pinServer(t *testing.T, principal auth.Principal) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	api := newHumaAPI(mux)
	api.UseMiddleware(authMiddleware(api, pinnedAuthn{principal: principal}))

	ok := func(context.Context, *pluginScopedInput) (*struct{}, error) { return &struct{}{}, nil }

	register(api, Requires("plugin.publish", "plugin:publish").OnPlugin("id"), huma.Operation{
		OperationID: "syntheticPublish",
		Method:      http.MethodPost,
		Path:        "/api/v1/plugins/{id}/releases",
		Summary:     "A plugin-scoped route that exists only in this test",
	}, ok)

	// Deliberately declares no plugin parameter. A pinned token calling it cannot have its pin
	// checked, and "cannot check" must not resolve to "allow".
	register(api, Requires("plugin.read", "plugin:read"), huma.Operation{
		OperationID: "syntheticUnscoped",
		Method:      http.MethodPost,
		Path:        "/api/v1/unscoped",
		Summary:     "A route that does not act on a plugin",
	}, func(context.Context, *struct{}) (*struct{}, error) { return &struct{}{}, nil })

	srv := httptest.NewServer(RefuseTokenInQuery(mux))
	t.Cleanup(srv.Close)
	return srv
}

type pluginScopedInput struct {
	ID string `path:"id"`
}

func post(t *testing.T, srv *httptest.Server, path string) (int, Problem) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+path, nil)
	require.NoError(t, err)

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var p Problem
	if resp.StatusCode >= http.StatusBadRequest {
		require.NoError(t, json.Unmarshal(body, &p), "body was %s", body)
	}
	return resp.StatusCode, p
}

func pinnedTo(pluginID string) auth.Principal {
	return auth.Principal{
		AccountID:   "acct",
		TokenID:     "tok",
		TokenPrefix: "abcd1234",
		Scopes:      authz.Scopes(),
		PluginID:    pluginID,
	}
}

// TestPluginPin_ATokenPinnedToOnePlugin_CannotActOnAnother — the whole point of the pin.
func TestPluginPin_ATokenPinnedToOnePlugin_CannotActOnAnother(t *testing.T) {
	t.Parallel()

	srv := pinServer(t, pinnedTo("merchant-mode"))

	t.Run("its own plugin", func(t *testing.T) {
		status, _ := post(t, srv, "/api/v1/plugins/merchant-mode/releases")
		require.Equal(t, http.StatusNoContent, status,
			"a pinned token must still work on the plugin it was minted for, or the pin is just a ban")
	})

	t.Run("somebody else's plugin", func(t *testing.T) {
		status, problem := post(t, srv, "/api/v1/plugins/raid-tools/releases")
		require.Equal(t, http.StatusForbidden, status,
			"a token leaked from one plugin's pipeline must not reach another")
		require.Equal(t, CodeForbidden, problem.Code)
		require.Contains(t, problem.Detail, "pinned to a different plugin")
		// The token's own plugin is not named: the holder knows it, and anybody who stole the
		// token would be learning where to point it.
		require.NotContains(t, problem.Detail, "merchant-mode")
	})

	t.Run("an operation that does not act on a plugin", func(t *testing.T) {
		status, problem := post(t, srv, "/api/v1/unscoped")
		require.Equal(t, http.StatusForbidden, status,
			"the pin cannot be checked there, and 'cannot check' must not resolve to 'allow'")
		require.Contains(t, problem.Detail, "does not act on one")
	})
}

// TestPluginPin_AnUnpinnedCredential_IsUnaffected — the other side of the boundary.
//
// A check that refused everything would pass every case above. An unpinned token and a session
// must reach both routes; whether the ACCOUNT owns the plugin is a separate question, answered per
// request against plugin_owner by the handler (ADR-0005).
func TestPluginPin_AnUnpinnedCredential_IsUnaffected(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name      string
		principal auth.Principal
	}{
		{name: "an unpinned token", principal: pinnedTo("")},
		{
			name:      "a browser session",
			principal: auth.Principal{AccountID: "acct", SessionID: "sess"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := pinServer(t, tt.principal)
			for _, path := range []string{
				"/api/v1/plugins/merchant-mode/releases",
				"/api/v1/plugins/raid-tools/releases",
				"/api/v1/unscoped",
			} {
				status, _ := post(t, srv, path)
				require.Equal(t, http.StatusNoContent, status, "%s must be reachable", path)
			}
		})
	}
}

func TestPrincipal_AllowsPlugin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		pin    string
		plugin string
		want   bool
	}{
		{name: "unpinned reaches anything", pin: "", plugin: "merchant-mode", want: true},
		{name: "unpinned reaches an empty id", pin: "", plugin: "", want: true},
		{name: "pinned reaches its own", pin: "merchant-mode", plugin: "merchant-mode", want: true},
		{name: "pinned refuses another", pin: "merchant-mode", plugin: "raid-tools"},
		// A missing path value must not read as a match. This is the shape a route with a
		// mis-declared parameter name would produce, and it must fail closed.
		{name: "pinned refuses an empty id", pin: "merchant-mode", plugin: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, auth.Principal{PluginID: tt.pin}.AllowsPlugin(tt.plugin))
		})
	}
}
