package api_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
)

// The sign-in journey, over real HTTP.
//
// These are handler tests rather than service tests: internal/auth is covered against a real
// database in its own package, and what is left to get wrong here is everything HTTP — the cookie
// attributes, which failure becomes which status, and whether the middleware refuses what it is
// supposed to before a handler ever runs.

const testState = "a-state-value"

// fakeLogin is the Login interface with the answers set per test.
type fakeLogin struct {
	begun       auth.Begun
	beginErr    error
	completed   auth.Completed
	completeErr error

	sawState, sawCookieState, sawCode string
	sawRedirect                       string
}

func (f *fakeLogin) Begin(_ context.Context, _ identity.Kind, redirectTo string) (auth.Begun, error) {
	f.sawRedirect = redirectTo
	return f.begun, f.beginErr
}

func (f *fakeLogin) Complete(_ context.Context, _ identity.Kind, state, cookieState, code string) (
	auth.Completed, error,
) {
	f.sawState, f.sawCookieState, f.sawCode = state, cookieState, code
	return f.completed, f.completeErr
}

// fakeSessions is the SessionIssuer interface.
type fakeSessions struct {
	created   auth.NewSession
	createErr error
	revoked   []string
	revokeErr error
}

func (f *fakeSessions) Create(context.Context, string) (auth.NewSession, error) {
	return f.created, f.createErr
}

func (f *fakeSessions) Revoke(_ context.Context, p auth.Principal) error {
	f.revoked = append(f.revoked, p.SessionID)
	return f.revokeErr
}

// fakeAuthn resolves every request to one principal, or to one error. The middleware is what is
// under test, not the resolution.
type fakeAuthn struct {
	principal auth.Principal
	err       error
	sawCreds  auth.Credentials
}

func (f *fakeAuthn) Resolve(_ context.Context, creds auth.Credentials) (auth.Principal, error) {
	f.sawCreds = creds
	return f.principal, f.err
}

// harness is a running server plus the fakes behind it.
type harness struct {
	srv      *httptest.Server
	login    *fakeLogin
	sessions *fakeSessions
	authn    *fakeAuthn
}

// newHarness builds a server with sign-in wired up. mutate runs before New so a test can take a
// dependency away — which is itself a case worth covering.
func newHarness(t *testing.T, mutate ...func(cfg *api.Config, h *harness)) *harness {
	t.Helper()

	h := &harness{
		login: &fakeLogin{
			begun: auth.Begun{
				AuthorizeURL: "https://github.example/login/oauth/authorize?state=" + testState,
				State:        testState,
				ExpiresAt:    time.Date(2026, 8, 20, 12, 10, 0, 0, time.UTC),
			},
			completed: auth.Completed{AccountID: "acct", DisplayName: "someone", Handle: "someone"},
		},
		sessions: &fakeSessions{
			created: auth.NewSession{
				Secret:    "a-session-secret",
				ExpiresAt: time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC),
			},
		},
		authn: &fakeAuthn{err: auth.ErrNoCredential},
	}

	cfg := api.Config{
		Login:     h.login,
		Sessions:  h.sessions,
		Providers: identity.NewRegistry(stubProvider{}),
		Authn:     h.authn,
	}
	for _, m := range mutate {
		m(&cfg, h)
	}

	h.srv = httptest.NewServer(api.New(cfg))
	t.Cleanup(h.srv.Close)
	return h
}

// stubProvider exists only so the registry has `github` in it. Nothing calls it: the handlers go
// through the Login interface, and the registry is consulted to resolve the path parameter.
type stubProvider struct{}

func (stubProvider) Kind() identity.Kind             { return identity.KindGitHub }
func (stubProvider) AuthorizeURL(_, _ string) string { return "" }
func (stubProvider) Exchange(context.Context, string, string) (identity.Identity, error) {
	return identity.Identity{}, errors.New("the stub provider is never called")
}

// do makes a request that does NOT follow redirects: the redirect is the response under test.
func (h *harness) do(t *testing.T, method, path string, cookies ...*http.Cookie) response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, h.srv.URL+path, nil)
	require.NoError(t, err)
	for _, c := range cookies {
		req.AddCookie(c)
	}

	resp, err := h.client().Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return response{
		status:  resp.StatusCode,
		header:  resp.Header.Clone(),
		body:    body,
		cookies: resp.Cookies(),
	}
}

// doWithToken posts to the logout route with a bearer token instead of a cookie.
func (h *harness) doWithToken(t *testing.T, token string) response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.srv.URL+"/auth/logout", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := h.client().Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return response{status: resp.StatusCode, header: resp.Header.Clone(), body: body}
}

// client is THIS server's client, and never a bare &http.Client{}.
//
// A client with no Transport uses http.DefaultTransport, which every test in the process shares —
// and httptest.Server.Close calls CloseIdleConnections on it. With tests running in parallel, one
// test's cleanup then breaks another's in-flight keep-alive connection, which surfaces as
// "transport connection broken: http: CloseIdleConnections called" on a request that had nothing
// to do with it. srv.Client() has its own Transport, scoped to this server.
func (h *harness) client() *http.Client {
	c := h.srv.Client()
	// The redirect IS the response under test on almost every route here.
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

// cookie returns the Set-Cookie with the given name, or nil.
func cookie(resp response, name string) *http.Cookie {
	for _, c := range resp.cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// problemOf decodes the RFC 9457 body and asserts the media type. Never 200 with an error body.
func problemOf(t *testing.T, resp response) api.Problem {
	t.Helper()

	require.Equal(t, "application/problem+json", resp.header.Get("Content-Type"))

	var p api.Problem
	require.NoError(t, json.Unmarshal(resp.body, &p), "body was %s", resp.body)
	require.Equal(t, resp.status, p.Status, "the status and the document must not disagree")
	return p
}

func TestStartLogin_RedirectsAndBindsTheStateToThisBrowser(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	resp := h.do(t, http.MethodGet, "/auth/github/login?next=/account")

	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Equal(t, h.login.begun.AuthorizeURL, resp.header.Get("Location"))
	require.Equal(t, "/account", h.login.sawRedirect)

	c := cookie(resp, auth.OAuthStateCookieName)
	require.NotNil(t, c, "without the state cookie the callback has nothing to bind against")
	require.Equal(t, testState, c.Value)

	// Each attribute is load-bearing, so each is asserted rather than eyeballed. The `__Host-`
	// prefix is only honoured when Secure is set and Path is exactly "/" with no Domain.
	require.True(t, c.Secure)
	require.True(t, c.HttpOnly)
	require.Equal(t, "/", c.Path)
	require.Empty(t, c.Domain)
	// Lax, not Strict: the callback arrives as a top-level navigation FROM the provider, and
	// Strict would withhold the cookie on exactly that request.
	require.Equal(t, http.SameSiteLaxMode, c.SameSite)
}

func TestStartLogin_UnknownProvider_Is404(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	resp := h.do(t, http.MethodGet, "/auth/discord/login")

	require.Equal(t, http.StatusNotFound, resp.status)
	require.Equal(t, api.CodeNotFound, problemOf(t, resp).Code)
	require.Empty(t, resp.cookies, "a refused login sets nothing")
}

func TestCompleteLogin_SetsTheSessionCookieAndClearsTheStateCookie(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.login.completed.RedirectTo = "/account/tokens"

	resp := h.do(t, http.MethodGet, "/auth/github/callback?code=the-code&state="+testState,
		&http.Cookie{Name: auth.OAuthStateCookieName, Value: testState})

	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Equal(t, "/account/tokens", resp.header.Get("Location"))

	// The handler must hand both halves of the state to the service and compare neither itself.
	require.Equal(t, testState, h.login.sawState)
	require.Equal(t, testState, h.login.sawCookieState)
	require.Equal(t, "the-code", h.login.sawCode)

	session := cookie(resp, auth.SessionCookieName)
	require.NotNil(t, session)
	require.Equal(t, "a-session-secret", session.Value)
	require.True(t, session.Secure)
	require.True(t, session.HttpOnly)
	require.Equal(t, "/", session.Path)
	require.Equal(t, http.SameSiteLaxMode, session.SameSite)

	// The state cookie has done its job. A credential-shaped value that outlives its purpose is
	// one more thing to reason about later.
	cleared := cookie(resp, auth.OAuthStateCookieName)
	require.NotNil(t, cleared, "the state cookie is cleared in the same response")
	require.Empty(t, cleared.Value)
	require.Negative(t, cleared.MaxAge)
}

func TestCompleteLogin_WithNoRedirect_LandsOnTheAccountPage(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	resp := h.do(t, http.MethodGet, "/auth/github/callback?code=c&state="+testState,
		&http.Cookie{Name: auth.OAuthStateCookieName, Value: testState})

	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Equal(t, "/account", resp.header.Get("Location"))
}

// TestCompleteLogin_MapsEachFailureOntoItsOwnStatus — the answer tells the person what to do.
//
// A rejected credential and an unreachable provider produce different advice, and "start again"
// is advice that cannot work while GitHub is down.
func TestCompleteLogin_MapsEachFailureOntoItsOwnStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantCode   api.Code
	}{
		{
			name:       "the callback did not start in this browser",
			err:        auth.ErrStateMismatch,
			wantStatus: http.StatusForbidden,
			wantCode:   api.CodeForbidden,
		},
		{
			name:       "the flow expired or was already used",
			err:        auth.ErrFlowUnknown,
			wantStatus: http.StatusBadRequest,
			wantCode:   api.CodeInvalidRequest,
		},
		{
			name:       "the provider rejected the code",
			err:        identity.ErrExchangeRejected,
			wantStatus: http.StatusBadRequest,
			wantCode:   api.CodeInvalidRequest,
		},
		{
			name:       "the account is disabled",
			err:        auth.ErrAccountDisabled,
			wantStatus: http.StatusForbidden,
			wantCode:   api.CodeForbidden,
		},
		{
			name:       "the provider is unreachable",
			err:        identity.ErrProviderUnavailable,
			wantStatus: http.StatusBadGateway,
			wantCode:   api.CodeServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t)
			h.login.completeErr = tt.err

			resp := h.do(t, http.MethodGet, "/auth/github/callback?code=c&state="+testState,
				&http.Cookie{Name: auth.OAuthStateCookieName, Value: testState})

			require.Equal(t, tt.wantStatus, resp.status)
			require.Equal(t, tt.wantCode, problemOf(t, resp).Code)
			require.Nil(t, cookie(resp, auth.SessionCookieName),
				"a failed sign-in must not set a session cookie")
		})
	}
}

// TestCompleteLogin_DoesNotEchoTheProvidersErrorDescription — attacker-influenced text in a URL.
//
// `error_description` arrives in a query string somebody else controls. Reflecting it puts our
// domain in front of whatever message a phishing page wants shown.
func TestCompleteLogin_DoesNotEchoTheProvidersErrorDescription(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	resp := h.do(t, http.MethodGet,
		"/auth/github/callback?error=access_denied&error_description=Call+555-1234+to+unlock")

	require.Equal(t, http.StatusForbidden, resp.status)
	p := problemOf(t, resp)
	require.NotContains(t, p.Detail, "555-1234")
	require.NotContains(t, p.Detail, "unlock")
}

func TestEndSession_RevokesAndClearsTheCookie(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.authn.principal = auth.Principal{AccountID: "acct", SessionID: "sess"}
	h.authn.err = nil

	resp := h.do(t, http.MethodPost, "/auth/logout",
		&http.Cookie{Name: auth.SessionCookieName, Value: "a-session-secret"})

	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Equal(t, "/", resp.header.Get("Location"))
	require.Equal(t, []string{"sess"}, h.sessions.revoked)

	cleared := cookie(resp, auth.SessionCookieName)
	require.NotNil(t, cleared)
	require.Empty(t, cleared.Value)
	require.Negative(t, cleared.MaxAge)

	// The middleware must read the cookie by the one name canonical §6 fixes.
	require.Equal(t, "a-session-secret", h.authn.sawCreds.SessionCookie)
}

func TestEndSession_WithNoCredential_Is401(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	resp := h.do(t, http.MethodPost, "/auth/logout")

	require.Equal(t, http.StatusUnauthorized, resp.status)
	require.Equal(t, api.CodeUnauthorized, problemOf(t, resp).Code)
	require.Empty(t, h.sessions.revoked, "the handler must not have run")
}

// TestEndSession_RefusesAToken — the capability floor, over HTTP.
//
// Signing out is declared Floor("session.end"). A token that could perform a floor operation would
// be equivalent to the account, so the refusal is on the credential KIND and holds whatever scopes
// the token carries.
func TestEndSession_RefusesAToken(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.authn.principal = auth.Principal{
		AccountID:   "acct",
		TokenID:     "tok",
		TokenPrefix: "abcd1234",
		Scopes:      authz.Scopes(),
	}
	h.authn.err = nil

	resp := h.doWithToken(t, auth.TokenPrefix+"abcd1234_secret")

	require.Equal(t, http.StatusForbidden, resp.status)
	p := problemOf(t, resp)
	require.Equal(t, api.CodeForbidden, p.Code)
	require.Contains(t, p.Detail, "session-only",
		"the refusal has to say WHY, or it reads as a scope somebody forgot to grant")
	require.Empty(t, h.sessions.revoked)

	// The bearer value is parsed out of the header and handed on; the header itself never becomes
	// the credential.
	require.Equal(t, auth.TokenPrefix+"abcd1234_secret", h.authn.sawCreds.BearerToken)
}

// TestATokenInAQueryString_IsAlwaysRefused — canonical §6, with no exception.
//
// Query strings land in access logs, proxy logs and browser history, so a token that appears in
// one is already leaked. The refusal covers PUBLIC routes too: the rule is about the value being
// in a URL, not about what it was sent to.
func TestATokenInAQueryString_IsAlwaysRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		path string
	}{
		{name: "the conventional parameter name", path: "/auth/logout?access_token=" + auth.TokenPrefix + "abcd1234_secret"},
		{name: "any other parameter name", path: "/auth/logout?t=" + auth.TokenPrefix + "abcd1234_secret"},
		{name: "on a public route", path: "/healthz?access_token=" + auth.TokenPrefix + "abcd1234_secret"},
		// The two below are the reason this check is NOT Huma middleware: neither route matches,
		// so the mux would answer 404 or 405 and the check would never run.
		{name: "on a path that does not exist", path: "/nothing-here?t=" + auth.TokenPrefix + "abcd1234_secret"},
		{name: "with a method the route does not serve", path: "/auth/logout?t=" + auth.TokenPrefix + "abcd1234_secret"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t)
			resp := h.do(t, http.MethodGet, tt.path)

			require.Equal(t, http.StatusUnauthorized, resp.status)
			p := problemOf(t, resp)
			require.Equal(t, api.CodeUnauthorized, p.Code)
			require.Contains(t, p.Detail, "query string")
		})
	}
}

func TestAQueryStringWithoutAToken_IsUntouched(t *testing.T) {
	t.Parallel()

	// The other side of the boundary: a gate that refused every query string would be caught by
	// nothing above, and `?next=` is on the login route.
	h := newHarness(t)
	resp := h.do(t, http.MethodGet, "/auth/github/login?next=/account&other=nprs_pat")

	require.Equal(t, http.StatusSeeOther, resp.status)
}

// TestAnAuthenticatedRoute_WithNoAuthenticator_Is503 — a nil dependency must not open a door.
//
// The middleware runs whether or not sign-in is configured. If a missing Authenticator meant
// "let it through", the one instance where a route was left undeclared would be the one with no
// enforcement at all.
func TestAnAuthenticatedRoute_WithNoAuthenticator_Is503(t *testing.T) {
	t.Parallel()

	h := newHarness(t, func(cfg *api.Config, _ *harness) { cfg.Authn = nil })
	resp := h.do(t, http.MethodPost, "/auth/logout",
		&http.Cookie{Name: auth.SessionCookieName, Value: "anything"})

	require.Equal(t, http.StatusServiceUnavailable, resp.status)
	require.Equal(t, api.CodeServiceUnavailable, problemOf(t, resp).Code)
	require.Empty(t, h.sessions.revoked)
}

// TestSignInRoutes_AreNotRegisteredWhenSignInIsNotConfigured — an honest 404.
//
// The live deployment is in this state today. A sign-in route that exists and cannot work is worse
// than one that is absent: the first is a 500 somebody debugs, the second is a fact.
func TestSignInRoutes_AreNotRegisteredWhenSignInIsNotConfigured(t *testing.T) {
	t.Parallel()

	h := newHarness(t, func(cfg *api.Config, _ *harness) {
		cfg.Login, cfg.Sessions, cfg.Providers = nil, nil, nil
	})

	for _, path := range []string{"/auth/github/login", "/auth/github/callback", "/auth/logout"} {
		resp := h.do(t, http.MethodGet, path)
		require.Equal(t, http.StatusNotFound, resp.status, "%s must not be served", path)
	}
}

// TestSecuritySchemes_NameTheCookieTheServerActuallyReads — the document is a promise.
//
// A client author reads `components.securitySchemes` to find out how to authenticate. A name there
// that the server does not read is a promise nobody can keep.
func TestSecuritySchemes_NameTheCookieTheServerActuallyReads(t *testing.T) {
	t.Parallel()

	spec := api.Spec()
	scheme := spec.Components.SecuritySchemes[api.SchemeSession]
	require.NotNil(t, scheme)
	require.Equal(t, "cookie", scheme.In)
	require.Equal(t, auth.SessionCookieName, scheme.Name)
	require.True(t, strings.HasPrefix(scheme.Name, "__Host-"),
		"the prefix is what stops a subdomain planting a session this service would honour")
}
