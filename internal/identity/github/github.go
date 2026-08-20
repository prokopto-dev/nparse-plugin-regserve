// Package github is the only identity provider implementation (ADR-0011).
//
// It implements identity.Provider over GitHub's OAuth App flow. Everything it sends goes through
// internal/identity/guard, which is what gate NET001 exists to keep true: the endpoints below are
// configuration, and configuration is the thing that gets pointed somewhere else by a mistake in a
// compose file.
package github

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity/guard"
)

// GitHub's endpoints. They are constants rather than configuration on purpose: an operator-settable
// token endpoint is an operator-settable place to send a client secret.
const (
	authorizeEndpoint = "https://github.com/login/oauth/authorize"
	tokenEndpoint     = "https://github.com/login/oauth/access_token" //nolint:gosec // G101: a URL, not a credential
	userEndpoint      = "https://api.github.com/user"
)

// maxResponseBytes caps every response read from GitHub.
//
// A user profile is a couple of kilobytes and a token response is a few hundred bytes. 256 KiB is
// far above both and far below anything that could hurt: the cap is not a tuning parameter, it is
// the difference between an error and an allocation chosen by the far end.
const maxResponseBytes = 256 * 1024

// apiVersion pins the REST API's response shape. GitHub versions its API by date header, and an
// unpinned client is one whose parsing breaks on a schedule somebody else sets.
const apiVersion = "2022-11-28"

// Config is what an operator supplies. It is validated by New; a provider that is half-configured
// is not registered at all, so a login button never leads to a 500.
type Config struct {
	// ClientID is public: it appears in the authorize URL the browser follows.
	ClientID string

	// ClientSecret is one of the two secrets this service holds (canonical §10). It is a
	// core.Secret so that a config struct reaching a log line or an error message redacts it.
	ClientSecret core.Secret

	// RedirectURL is the absolute callback this service serves, and must match what is registered
	// on the OAuth App. It is sent on both the authorize and the token request because GitHub
	// compares them, which is one more binding between the two halves of the flow.
	RedirectURL string

	// Client is the guarded HTTP client. Nil means one built from guard's defaults; a test passes
	// one pointed at an httptest server.
	Client *http.Client

	// AuthorizeEndpoint, TokenEndpoint and UserEndpoint override the constants above. They exist
	// for tests and are empty everywhere else — see Config.endpoints.
	AuthorizeEndpoint string
	TokenEndpoint     string
	UserEndpoint      string
}

// Provider is the GitHub identity provider.
type Provider struct {
	clientID     string
	clientSecret core.Secret
	redirectURL  string
	client       *http.Client

	authorizeEndpoint string
	tokenEndpoint     string
	userEndpoint      string
}

// ErrNotConfigured is returned by New when a required setting is missing. It names which one,
// because "GitHub login is not configured" sends an operator to read four environment variables.
type ErrNotConfigured struct{ Setting string }

func (e ErrNotConfigured) Error() string {
	return "github identity provider is not configured: " + e.Setting + " is empty"
}

// New validates the configuration and builds the provider.
func New(cfg Config) (*Provider, error) {
	switch {
	case strings.TrimSpace(cfg.ClientID) == "":
		return nil, ErrNotConfigured{Setting: "client id"}
	case cfg.ClientSecret.IsZero():
		return nil, ErrNotConfigured{Setting: "client secret"}
	case strings.TrimSpace(cfg.RedirectURL) == "":
		return nil, ErrNotConfigured{Setting: "redirect url"}
	}
	if err := guard.RequireHTTPS(cfg.RedirectURL); err != nil {
		// The redirect URL is where an authorization code is delivered. Over http that code
		// crosses the network in the clear, and the `__Host-` session cookie the callback sets
		// would be refused by the browser anyway.
		return nil, fmt.Errorf("github redirect url: %w", err)
	}

	client := cfg.Client
	if client == nil {
		client = guard.NewClient(guard.Config{})
	}

	p := &Provider{
		clientID:          cfg.ClientID,
		clientSecret:      cfg.ClientSecret,
		redirectURL:       cfg.RedirectURL,
		client:            client,
		authorizeEndpoint: firstNonEmpty(cfg.AuthorizeEndpoint, authorizeEndpoint),
		tokenEndpoint:     firstNonEmpty(cfg.TokenEndpoint, tokenEndpoint),
		userEndpoint:      firstNonEmpty(cfg.UserEndpoint, userEndpoint),
	}
	return p, nil
}

// Kind is identity.KindGitHub.
func (p *Provider) Kind() identity.Kind { return identity.KindGitHub }

// AuthorizeURL is where the browser is sent to consent.
//
// NO SCOPE IS REQUESTED. An unscoped GitHub token reads the public profile, which is the numeric
// id and the login — everything this service needs. Asking for more would be an access grant we
// have no use for and a consent screen that frightens the people we want to publish plugins.
//
// The PKCE challenge is sent even though GitHub's OAuth App flow does not document support for it:
// an ignored parameter costs one query string entry, and the day it stops being ignored the flow
// is already correct. It is NOT what the flow's safety rests on today — `state`, bound to a
// short-lived cookie the browser must return, is. That distinction is written down rather than
// assumed, because "we implement PKCE" reads like a guarantee.
func (p *Provider) AuthorizeURL(state, challenge string) string {
	q := url.Values{}
	q.Set("client_id", p.clientID)
	q.Set("redirect_uri", p.redirectURL)
	q.Set("state", state)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	// allow_signup is left at GitHub's default: somebody without an account who wants to publish a
	// plugin needs one, and sending them to the sign-up page is the correct end of that journey.
	return p.authorizeEndpoint + "?" + q.Encode()
}

// tokenResponse is GitHub's answer to the token request.
//
// AccessToken is read into a plain string, used within Exchange, and never returned. It is not a
// core.Secret because it does not live long enough to be logged by accident — but it is also never
// put in a log line, an error, or a struct that outlives this function.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// userResponse is the part of GitHub's user object this service reads.
//
// ID is a number in the JSON and is decoded as one so that a string "12345" from something
// pretending to be GitHub cannot become a subject. It is stored as text because canonical §7 makes
// every identifier column TEXT, and because a provider added later may not have a numeric id.
type userResponse struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
	Name  string `json:"name"`
}

// Exchange trades the authorization code for the identity behind it.
func (p *Provider) Exchange(ctx context.Context, code, verifier string) (identity.Identity, error) {
	tok, err := p.token(ctx, code, verifier)
	if err != nil {
		return identity.Identity{}, err
	}
	return p.user(ctx, tok)
}

func (p *Provider) token(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{}
	form.Set("client_id", p.clientID)
	form.Set("client_secret", p.clientSecret.Reveal())
	form.Set("code", code)
	form.Set("redirect_uri", p.redirectURL)
	form.Set("code_verifier", verifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenEndpoint,
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build the github token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Without this GitHub answers form-encoded, which parses into a token nobody validated the
	// shape of. Asking for JSON means a malformed answer is a parse error rather than a surprise.
	req.Header.Set("Accept", "application/json")

	resp, err := guard.Do(ctx, p.client, req, maxResponseBytes)
	if err != nil {
		return "", fmt.Errorf("%w: %w", identity.ErrProviderUnavailable, err)
	}
	if resp.StatusCode != http.StatusOK {
		// The body is NOT included. It is a response to a request that carried the client secret,
		// and an error path that echoes the far end's body is how a secret reaches a log.
		return "", fmt.Errorf("%w: token endpoint answered %d",
			identity.ErrProviderUnavailable, resp.StatusCode)
	}

	var parsed tokenResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return "", fmt.Errorf("%w: parse the token response: %w", identity.ErrProviderUnavailable, err)
	}
	// GitHub reports a bad, reused or expired code as 200 with an `error` member. Treating a 200
	// as success here is the classic version of this bug, and it ends with an empty access token
	// being sent to the user endpoint.
	if parsed.Error != "" {
		return "", fmt.Errorf("%w: %s", identity.ErrExchangeRejected, parsed.Error)
	}
	if parsed.AccessToken == "" {
		return "", fmt.Errorf("%w: the token response carried no access token",
			identity.ErrExchangeRejected)
	}
	return parsed.AccessToken, nil
}

func (p *Provider) user(ctx context.Context, accessToken string) (identity.Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userEndpoint, nil)
	if err != nil {
		return identity.Identity{}, fmt.Errorf("build the github user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", apiVersion)

	resp, err := guard.Do(ctx, p.client, req, maxResponseBytes)
	if err != nil {
		return identity.Identity{}, fmt.Errorf("%w: %w", identity.ErrProviderUnavailable, err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return identity.Identity{}, fmt.Errorf("%w: the access token was refused",
			identity.ErrExchangeRejected)
	case resp.StatusCode != http.StatusOK:
		return identity.Identity{}, fmt.Errorf("%w: user endpoint answered %d",
			identity.ErrProviderUnavailable, resp.StatusCode)
	}

	var parsed userResponse
	if err := json.Unmarshal(resp.Body, &parsed); err != nil {
		return identity.Identity{}, fmt.Errorf("%w: parse the user response: %w",
			identity.ErrProviderUnavailable, err)
	}
	if parsed.ID == 0 {
		// Zero is not a GitHub user id, so it means the field was absent or was not a number. An
		// empty subject would collapse every such login onto one account.
		return identity.Identity{}, identity.ErrNoSubject
	}

	return identity.Identity{
		Provider:    identity.KindGitHub,
		Subject:     strconv.FormatInt(parsed.ID, 10),
		Handle:      parsed.Login,
		DisplayName: parsed.Name,
	}, nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

var _ identity.Provider = (*Provider)(nil)
