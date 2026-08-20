package main

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// The boot-time configuration of sign-in.
//
// The case that matters most is the FIRST one. deploy/compose.yaml has always required
// REGSERVE_TOKEN_PEPPER, so the live deployment runs with a pepper set and no OAuth application
// behind it. A rule that read "a pepper means somebody wants sign-in" would refuse to start the
// exact deployment this code has to land on, and it would do so on a droplet, at deploy time,
// after the image had already been built.

func configure(t *testing.T, env map[string]string) (api.Config, error) {
	t.Helper()

	// Every variable is set explicitly, including to the empty string, so a value left in the
	// developer's environment cannot decide the result of a test.
	for _, k := range []string{envPublicURL, envTokenPepper, envGitHubClientID, envGitHubClientSecret} {
		t.Setenv(k, env[k])
	}

	var cfg api.Config
	err := configureIdentity(t.Context(), &cfg, storetest.New(t), clock.Fixed{})
	return cfg, err
}

func TestConfigureIdentity_APepperWithNoOAuthApp_LeavesSignInOff(t *testing.T) {
	cfg, err := configure(t, map[string]string{
		envPublicURL:   "https://nparseplugins.prokopto.dev",
		envTokenPepper: "a-pepper",
	})

	require.NoError(t, err,
		"this is the live deployment's configuration; refusing to start on it would be an outage")
	require.Nil(t, cfg.Login, "the sign-in routes are not registered, which is an honest 404")
	require.Nil(t, cfg.Sessions)
	require.Nil(t, cfg.Providers)
	require.Nil(t, cfg.Authn)
}

func TestConfigureIdentity_NothingSetAtAll_LeavesSignInOff(t *testing.T) {
	cfg, err := configure(t, nil)

	require.NoError(t, err)
	require.Nil(t, cfg.Login)
}

func TestConfigureIdentity_HalfAnOAuthApp_IsFatal(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
	}{
		{
			name: "a client id and no secret",
			env: map[string]string{
				envPublicURL: "https://registry.example", envTokenPepper: "a-pepper",
				envGitHubClientID: "id",
			},
		},
		{
			name: "a secret and no client id",
			env: map[string]string{
				envPublicURL: "https://registry.example", envTokenPepper: "a-pepper",
				envGitHubClientSecret: "secret",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := configure(t, tt.env)
			require.ErrorContains(t, err, "half configured",
				"a login button that 500s and a server that ignores its configuration are both "+
					"worse than a boot failure")
			// Never the value, and not even which half was present: the message sends somebody to
			// their .env, it does not confirm a guess.
			require.NotContains(t, err.Error(), "secret\"")
		})
	}
}

func TestConfigureIdentity_AnOAuthAppWithNoPepper_IsFatal(t *testing.T) {
	_, err := configure(t, map[string]string{
		envPublicURL:      "https://registry.example",
		envGitHubClientID: "id", envGitHubClientSecret: "secret",
	})

	require.ErrorContains(t, err, envTokenPepper,
		"every credential hash is keyed on it; without one the hashes are keyed on nothing")
}

// TestConfigureIdentity_AnHTTPPublicURL_IsFatal — the __Host- cookie, at boot rather than in a
// browser console.
//
// A browser refuses a `__Host-` cookie that did not arrive over https. Sign-in from an http origin
// would therefore complete, set nothing, and leave the user on a signed-out account page with no
// error anywhere — which is a bug somebody debugs for an afternoon.
func TestConfigureIdentity_AnHTTPPublicURL_IsFatal(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{name: "http", url: "http://registry.example"},
		{name: "empty", url: ""},
		{name: "a bare host", url: "registry.example"},
		// These name no host. They pass a prefix check, and what follows is worse than a rejection:
		// sign-in comes up with a callback URL of `https:///auth/github/callback`, which GitHub
		// cannot redirect to — a configuration accepted at boot that fails in a browser.
		{name: "a scheme and nothing else", url: "https://"},
		{name: "a scheme and a query", url: "https://?x"},
		{name: "a scheme and a path", url: "https:///auth/github/callback"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := configure(t, map[string]string{
				envPublicURL: tt.url, envTokenPepper: "a-pepper",
				envGitHubClientID: "id", envGitHubClientSecret: "secret",
			})
			require.ErrorContains(t, err, envPublicURL)
			require.ErrorContains(t, err, "https")
		})
	}
}

// TestConfigureIdentity_APublicURLWithAHost_IsAccepted — the other side of the boundary.
//
// A gate that refused every https URL would be caught by nothing in the table above, which only
// ever asserts refusals. A base URL with no path is the normal case and must keep working.
func TestConfigureIdentity_APublicURLWithAHost_IsAccepted(t *testing.T) {
	for _, u := range []string{
		"https://nparseplugins.prokopto.dev",
		"https://nparseplugins.prokopto.dev/",
		"https://localhost:8443",
	} {
		t.Run(u, func(t *testing.T) {
			cfg, err := configure(t, map[string]string{
				envPublicURL: u, envTokenPepper: "a-pepper",
				envGitHubClientID: "id", envGitHubClientSecret: "secret",
			})
			require.NoError(t, err)
			require.NotNil(t, cfg.Login)
		})
	}
}

func TestConfigureIdentity_FullyConfigured_WiresEveryPart(t *testing.T) {
	cfg, err := configure(t, map[string]string{
		envPublicURL:      "https://nparseplugins.prokopto.dev/",
		envTokenPepper:    "a-pepper",
		envGitHubClientID: "id", envGitHubClientSecret: "secret",
	})

	require.NoError(t, err)
	require.NotNil(t, cfg.Login)
	require.NotNil(t, cfg.Sessions)
	require.NotNil(t, cfg.Authn)
	require.NotNil(t, cfg.Providers)

	// The callback URL is built from the route it is registered at, with the trailing slash on the
	// public URL absorbed. A second literal would be a URL that silently stops matching the route.
	begun, err := cfg.Login.Begin(t.Context(), "github", "/account")
	require.NoError(t, err)
	require.Contains(t, begun.AuthorizeURL,
		"redirect_uri=https%3A%2F%2Fnparseplugins.prokopto.dev%2Fauth%2Fgithub%2Fcallback")
}
