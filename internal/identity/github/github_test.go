package github_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity/github"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity/guard"
)

// endpoints is the fake GitHub these tests exchange against.
//
// A real server on a real socket rather than a stubbed http.RoundTripper, because half of what is
// being tested is what this code sends: the Accept header that makes the token endpoint answer
// JSON, and the fact that the response is read through the guarded client rather than around it.
type endpoints struct {
	token func(w http.ResponseWriter, r *http.Request)
	user  func(w http.ResponseWriter, r *http.Request)
}

func newProvider(t *testing.T, e endpoints) *github.Provider {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc("/token", e.token)
	mux.HandleFunc("/user", e.user)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	p, err := github.New(github.Config{
		ClientID:     "client-id",
		ClientSecret: core.NewSecret("client-secret"),
		RedirectURL:  "https://registry.example/auth/github/callback",
		// PermitLoopback is the only reason this can reach httptest at all, and it widens exactly
		// that one category — see the guard package's tests.
		Client:        guard.NewClient(guard.Config{PermitLoopback: true}),
		TokenEndpoint: srv.URL + "/token",
		UserEndpoint:  srv.URL + "/user",
	})
	require.NoError(t, err)
	return p
}

func okToken(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"access_token":"gho_secret","token_type":"bearer"}`))
}

func okUser(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"id":12345,"login":"prokopto-dev","name":"Courtney Caldwell"}`))
}

func TestNew_RefusesAHalfConfiguredProvider(t *testing.T) {
	t.Parallel()

	base := github.Config{
		ClientID:     "id",
		ClientSecret: core.NewSecret("secret"),
		RedirectURL:  "https://registry.example/auth/github/callback",
	}

	tests := []struct {
		name   string
		mutate func(c *github.Config)
	}{
		{name: "no client id", mutate: func(c *github.Config) { c.ClientID = "" }},
		{name: "blank client id", mutate: func(c *github.Config) { c.ClientID = "   " }},
		{name: "no client secret", mutate: func(c *github.Config) { c.ClientSecret = core.Secret{} }},
		{name: "no redirect url", mutate: func(c *github.Config) { c.RedirectURL = "" }},
		// An authorization code delivered over http crosses the network in the clear, and the
		// __Host- session cookie the callback sets would be refused by the browser anyway.
		{name: "an http redirect url", mutate: func(c *github.Config) {
			c.RedirectURL = "http://registry.example/auth/github/callback"
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := base
			tt.mutate(&cfg)
			_, err := github.New(cfg)
			require.Error(t, err, "a provider that cannot work must not be constructed")
		})
	}

	p, err := github.New(base)
	require.NoError(t, err)
	require.Equal(t, identity.KindGitHub, p.Kind())
}

// TestAuthorizeURL_CarriesStatePKCEAndNoScope — what the browser is sent to.
//
// No scope is requested: an unscoped token reads the public profile, which is the numeric id and
// the login, and that is everything this service needs. Asking for more would be an access grant
// with no use and a consent screen that frightens the people we want publishing plugins.
func TestAuthorizeURL_CarriesStatePKCEAndNoScope(t *testing.T) {
	t.Parallel()

	p, err := github.New(github.Config{
		ClientID:     "client-id",
		ClientSecret: core.NewSecret("client-secret"),
		RedirectURL:  "https://registry.example/auth/github/callback",
	})
	require.NoError(t, err)

	raw := p.AuthorizeURL("the-state", "the-challenge")
	u, err := url.Parse(raw)
	require.NoError(t, err)
	q := u.Query()

	require.Equal(t, "https", u.Scheme)
	require.Equal(t, "github.com", u.Host)
	require.Equal(t, "client-id", q.Get("client_id"))
	require.Equal(t, "https://registry.example/auth/github/callback", q.Get("redirect_uri"))
	require.Equal(t, "the-state", q.Get("state"))
	require.Equal(t, "the-challenge", q.Get("code_challenge"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))

	require.False(t, q.Has("scope"), "no scope is requested; see the method comment")
	require.NotContains(t, raw, "client-secret", "the secret never reaches the browser")
}

func TestExchange_ResolvesTheNumericIdAndTheHandle(t *testing.T) {
	t.Parallel()

	var sawAccept, sawAuthorization, sawVerifier string
	p := newProvider(t, endpoints{
		token: func(w http.ResponseWriter, r *http.Request) {
			sawAccept = r.Header.Get("Accept")
			require.NoError(t, r.ParseForm())
			sawVerifier = r.PostForm.Get("code_verifier")
			require.Equal(t, "the-code", r.PostForm.Get("code"))
			require.Equal(t, "client-secret", r.PostForm.Get("client_secret"))
			okToken(w, r)
		},
		user: func(w http.ResponseWriter, r *http.Request) {
			sawAuthorization = r.Header.Get("Authorization")
			okUser(w, r)
		},
	})

	id, err := p.Exchange(t.Context(), "the-code", "the-verifier")
	require.NoError(t, err)

	require.Equal(t, identity.Identity{
		Provider:    identity.KindGitHub,
		Subject:     "12345",
		Handle:      "prokopto-dev",
		DisplayName: "Courtney Caldwell",
	}, id, "the subject is the immutable numeric id, never the handle (ADR-0003)")

	// Without this header GitHub answers form-encoded, and the token is parsed out of a shape
	// nobody validated.
	require.Equal(t, "application/json", sawAccept)
	require.Equal(t, "Bearer gho_secret", sawAuthorization)
	require.Equal(t, "the-verifier", sawVerifier)
}

// TestExchange_TreatsA200WithAnErrorMemberAsARejection — the classic version of this bug.
//
// GitHub reports a reused, expired or invalid code as HTTP 200 with an `error` member. Reading the
// status alone leaves an empty access token, which is then sent to the user endpoint, and the
// failure surfaces one call later as something that looks like a permissions problem.
func TestExchange_TreatsA200WithAnErrorMemberAsARejection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want error
	}{
		{
			name: "an error member",
			body: `{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired."}`,
			want: identity.ErrExchangeRejected,
		},
		{
			name: "no access token at all",
			body: `{"token_type":"bearer"}`,
			want: identity.ErrExchangeRejected,
		},
		{
			name: "a body that is not json",
			body: `not json`,
			want: identity.ErrProviderUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			userCalled := false
			p := newProvider(t, endpoints{
				token: func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(tt.body))
				},
				user: func(w http.ResponseWriter, r *http.Request) {
					userCalled = true
					okUser(w, r)
				},
			})

			_, err := p.Exchange(t.Context(), "the-code", "the-verifier")
			require.ErrorIs(t, err, tt.want)
			require.False(t, userCalled,
				"a failed token exchange must not go on to call the user endpoint")
		})
	}
}

func TestExchange_RefusesAUserWithNoNumericId(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want error
	}{
		// Zero is not a GitHub user id, so it means the field was absent or was not a number. An
		// empty subject would collapse every such login onto ONE account.
		{name: "no id", body: `{"login":"someone"}`, want: identity.ErrNoSubject},
		{name: "a zero id", body: `{"id":0,"login":"someone"}`, want: identity.ErrNoSubject},
		// A string id is something pretending to be GitHub. It must not become a subject.
		{name: "a string id", body: `{"id":"12345","login":"someone"}`, want: identity.ErrProviderUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := newProvider(t, endpoints{
				token: okToken,
				user: func(w http.ResponseWriter, _ *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(tt.body))
				},
			})

			_, err := p.Exchange(t.Context(), "the-code", "the-verifier")
			require.ErrorIs(t, err, tt.want)
		})
	}
}

// TestExchange_SeparatesARejectedCredentialFromAnUnreachableProvider — the two are not one error.
//
// One is the person's login and the answer is "start again"; the other is our dependency and the
// answer is "try shortly". Telling a user to sign in again while GitHub is down is advice that
// cannot work.
func TestExchange_SeparatesARejectedCredentialFromAnUnreachableProvider(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
		want   error
	}{
		{name: "the token was refused", status: http.StatusUnauthorized, want: identity.ErrExchangeRejected},
		{name: "github is unwell", status: http.StatusInternalServerError, want: identity.ErrProviderUnavailable},
		{name: "rate limited", status: http.StatusForbidden, want: identity.ErrProviderUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			p := newProvider(t, endpoints{
				token: okToken,
				user: func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(tt.status)
				},
			})

			_, err := p.Exchange(t.Context(), "the-code", "the-verifier")
			require.ErrorIs(t, err, tt.want)
		})
	}
}

// TestExchange_TokenEndpointFailure_DoesNotEchoTheBody — the request carried the client secret.
//
// An error path that includes the far end's response is how a secret reaches a log, and this is
// the one response that is an answer to a request containing one.
func TestExchange_TokenEndpointFailure_DoesNotEchoTheBody(t *testing.T) {
	t.Parallel()

	p := newProvider(t, endpoints{
		token: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"you_sent":"client-secret"}`))
		},
		user: okUser,
	})

	_, err := p.Exchange(t.Context(), "the-code", "the-verifier")
	require.ErrorIs(t, err, identity.ErrProviderUnavailable)
	require.NotContains(t, err.Error(), "client-secret")
}
