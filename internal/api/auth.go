package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
)

// The login paths. They sit OUTSIDE /api/v1 next to the account surface, because they are browser
// journeys rather than API operations: the thing that follows them is a person, and the response
// is a redirect and a cookie rather than a document. Versioning them alongside the product API
// would mean an OAuth App's registered callback URL changes when the API does.
const (
	PathLogin    = "/auth/{provider}/login"
	PathCallback = "/auth/{provider}/callback"
	PathLogout   = "/auth/logout"
)

// PathAccount is where a completed login lands by default. The page itself arrives with the
// account surface; the constant is here because the callback needs somewhere to send a browser and
// two spellings of the same path is how one of them stops being maintained.
const PathAccount = "/account"

// tagAuth groups the sign-in operations in the OpenAPI document, and in the SDKs generated from
// it. One spelling, because a tag is how a reader finds the group and two spellings make two.
const tagAuth = "auth"

// Login is what internal/api needs in order to run a login. A consumer-declared interface, so the
// handlers can be tested without a database or a provider.
type Login interface {
	// Begin starts a handshake and says where to send the browser.
	Begin(ctx context.Context, kind identity.Kind, redirectTo string) (auth.Begun, error)

	// Complete redeems a callback. It takes the state from the URL and the state from the cookie
	// separately and compares them itself — a caller that pre-compared them would be a caller who
	// could forget to.
	Complete(ctx context.Context, kind identity.Kind, state, cookieState, code string) (
		auth.Completed, error)
}

// SessionIssuer mints and ends browser sessions.
type SessionIssuer interface {
	Create(ctx context.Context, accountID string) (auth.NewSession, error)
	Revoke(ctx context.Context, p auth.Principal) error
}

// redirectOutput is a 303 with cookies. It carries no body on purpose: a browser follows the
// Location header and never renders it, and a body here would be a page nobody has designed.
//
// 303 rather than 302 because the logout route is a POST: 303 tells the browser to follow with GET,
// where 302's behaviour is historically inconsistent and can re-POST.
type redirectOutput struct {
	Status    int
	Location  string        `header:"Location"`
	SetCookie []http.Cookie `header:"Set-Cookie"`
}

type loginInput struct {
	Provider string `path:"provider" doc:"The identity provider to sign in with. Only github exists."`

	// RedirectTo is where to land after signing in. It is validated as a same-site absolute path
	// and discarded otherwise: an open redirect on a login callback is a phishing primitive, not a
	// cosmetic bug.
	RedirectTo string `query:"next" doc:"A same-site absolute path to return to after signing in."`
}

type callbackInput struct {
	Provider string `path:"provider"`
	Code     string `query:"code"`
	State    string `query:"state"`

	// StateCookie is the other half of the state check. The tag has to be a literal, so the cookie
	// name appears here as well as in internal/auth — TestCallbackInput_StateCookieTag_MatchesAuth
	// is what stops the two drifting apart.
	StateCookie string `cookie:"__Host-regserve_oauth"`

	// Error and ErrorDescription are what the provider sends when the person pressed "cancel".
	// They are read so that the answer is "you cancelled" rather than "no such login in progress",
	// which reads as a broken service to somebody who deliberately backed out.
	Error            string `query:"error"`
	ErrorDescription string `query:"error_description"`
}

func registerAuth(api huma.API, login Login, sessions SessionIssuer, providers *identity.Registry) {
	register(api, Public(), huma.Operation{
		OperationID: "startLogin",
		Method:      http.MethodGet,
		Path:        PathLogin,
		Summary:     "Start a sign-in",
		Description: "Redirects the browser to the provider's consent screen. Sets a short-lived " +
			"`" + auth.OAuthStateCookieName + "` cookie which the callback requires: the `state` " +
			"parameter alone is a nonce anybody can supply, and the cookie is what binds the " +
			"callback to the browser that started the flow.",
		Tags:      []string{tagAuth},
		Errors:    []int{http.StatusNotFound, http.StatusInternalServerError},
		Responses: redirectResponses("The provider's consent screen."),
	}, func(ctx context.Context, in *loginInput) (*redirectOutput, error) {
		kind, err := providerKind(providers, in.Provider)
		if err != nil {
			return nil, err
		}

		begun, err := login.Begin(ctx, kind, in.RedirectTo)
		if err != nil {
			slog.ErrorContext(ctx, "start a login", "provider", kind.String(), "error", err)
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError,
				"the sign-in could not be started")
		}

		return &redirectOutput{
			Status:   http.StatusSeeOther,
			Location: begun.AuthorizeURL,
			// The state cookie's lifetime is the flow's, not the session's. A stale one left in a
			// browser for a week would be a second, older login waiting to be completed.
			SetCookie: []http.Cookie{stateCookie(begun.State, begun.ExpiresAt)},
		}, nil
	})

	register(api, Public(), huma.Operation{
		OperationID: "completeLogin",
		Method:      http.MethodGet,
		Path:        PathCallback,
		Summary:     "Complete a sign-in",
		Description: "The provider's redirect target. Exchanges the authorization code, resolves " +
			"the account behind the provider identity, and sets the session cookie.",
		Tags:      []string{tagAuth},
		Errors:    []int{http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusBadGateway},
		Responses: redirectResponses("The account page, or wherever the sign-in started from."),
	}, func(ctx context.Context, in *callbackInput) (*redirectOutput, error) {
		kind, err := providerKind(providers, in.Provider)
		if err != nil {
			return nil, err
		}
		if in.Error != "" {
			// The provider's own words are NOT echoed. `error_description` is attacker-influenced
			// text arriving in a URL, and reflecting it is how a phishing page gets our domain in
			// front of the message it wants shown.
			slog.InfoContext(ctx, "the provider refused a login",
				"provider", kind.String(), "error", in.Error)
			return nil, NewProblem(http.StatusForbidden, CodeForbidden,
				"the sign-in was refused or cancelled at "+kind.String())
		}

		done, err := login.Complete(ctx, kind, in.State, in.StateCookie, in.Code)
		if err != nil {
			return nil, callbackProblem(ctx, kind, err)
		}

		session, err := sessions.Create(ctx, done.AccountID)
		if err != nil {
			slog.ErrorContext(ctx, "create a session", "error", err)
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError,
				"the sign-in could not be completed")
		}
		slog.InfoContext(ctx, "signed in",
			"account_id", done.AccountID, "handle", done.Handle, "new_account", done.NewAccount)

		to := done.RedirectTo
		if to == "" {
			to = PathAccount
		}
		return &redirectOutput{
			Status:   http.StatusSeeOther,
			Location: to,
			SetCookie: []http.Cookie{
				sessionCookie(session.Secret, session.ExpiresAt),
				// The state cookie has done its job and is cleared in the same response. Leaving it
				// would let a later callback reuse it against a flow row that no longer exists —
				// harmless, and still a credential-shaped value living longer than its purpose.
				expiredCookie(auth.OAuthStateCookieName),
			},
		}, nil
	})

	register(api, Floor("session.end"), huma.Operation{
		OperationID: "endSession",
		Method:      http.MethodPost,
		Path:        PathLogout,
		Summary:     "Sign out",
		Description: "Revokes the session the request was made with and clears the cookie. It is " +
			"a capability-floor operation: no personal access token can end a browser session, " +
			"because a token holds no session to end.",
		Tags:      []string{tagAuth},
		Errors:    []int{http.StatusUnauthorized, http.StatusForbidden},
		Responses: redirectResponses("The home page."),
	}, func(ctx context.Context, _ *struct{}) (*redirectOutput, error) {
		p, ok := PrincipalFrom(ctx)
		if !ok {
			// Unreachable: the middleware answers 401 before an authenticated handler runs.
			return nil, NewProblem(http.StatusUnauthorized, CodeUnauthorized, "not signed in")
		}
		if err := sessions.Revoke(ctx, p); err != nil {
			slog.ErrorContext(ctx, "revoke a session", "account_id", p.AccountID, "error", err)
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError,
				"the sign-out could not be recorded")
		}
		return &redirectOutput{
			Status:    http.StatusSeeOther,
			Location:  "/",
			SetCookie: []http.Cookie{expiredCookie(auth.SessionCookieName)},
		}, nil
	})
}

// callbackProblem maps a handshake failure onto the closed error enum.
//
// Every branch names what the person should do, and none of them says which of several rejections
// it was where that would tell a prober how close they got.
func callbackProblem(ctx context.Context, kind identity.Kind, err error) error {
	switch {
	case errors.Is(err, auth.ErrStateMismatch):
		// The one that is never an accident: somebody trying to sign a victim's browser in as
		// themselves. It is logged at warn because it is worth seeing in an incident review.
		slog.WarnContext(ctx, "login state did not match the browser", "provider", kind.String())
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"this sign-in did not start in this browser; start again from the sign-in page")
	case errors.Is(err, auth.ErrFlowUnknown), errors.Is(err, identity.ErrExchangeRejected):
		return NewProblem(http.StatusBadRequest, CodeInvalidRequest,
			"this sign-in has expired or was already used; start again from the sign-in page")
	case errors.Is(err, auth.ErrAccountDisabled):
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"this account is disabled")
	case errors.Is(err, identity.ErrProviderUnavailable), errors.Is(err, identity.ErrNoSubject):
		slog.ErrorContext(ctx, "the identity provider could not be used",
			"provider", kind.String(), "error", err)
		return NewProblem(http.StatusBadGateway, CodeServiceUnavailable,
			"the identity provider could not be reached; try again shortly")
	default:
		slog.ErrorContext(ctx, "complete a login", "provider", kind.String(), "error", err)
		return NewProblem(http.StatusInternalServerError, CodeInternalError,
			"the sign-in could not be completed")
	}
}

// providerKind resolves the path parameter against the registry.
//
// An unknown provider is a 404 rather than a 400: the route for a provider this build does not
// implement does not exist, and saying "that is not a valid provider" enumerates the ones that are.
func providerKind(providers *identity.Registry, name string) (identity.Kind, error) {
	kind := identity.Kind(name)
	if _, err := providers.Get(kind); err != nil {
		return "", NewProblem(http.StatusNotFound, CodeNotFound, "no such sign-in provider")
	}
	return kind, nil
}

// sessionCookie builds the session cookie. Every attribute is required rather than advisable:
//
//   - the `__Host-` prefix means a browser only accepts it when Secure is set, Path is `/` and
//     there is no Domain — so no subdomain can plant a session this service would honour;
//   - HttpOnly keeps it out of reach of any script on the page, which is what makes an XSS a
//     defacement rather than an account takeover;
//   - SameSite=Lax is the first of the two CSRF defences (the second is the form token), and Lax
//     rather than Strict so that following a link from GitHub lands signed in rather than signed
//     out for one navigation.
func sessionCookie(secret string, expires time.Time) http.Cookie {
	return http.Cookie{
		Name:     auth.SessionCookieName,
		Value:    secret,
		Path:     "/",
		Expires:  expires,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// stateCookie carries the OAuth `state` for the length of the handshake.
//
// SameSite=Lax, not Strict: the callback arrives as a top-level navigation FROM the provider, and
// Strict would withhold the cookie on exactly that request — which would make every login fail
// with "this sign-in did not start in this browser".
func stateCookie(state string, expires time.Time) http.Cookie {
	return http.Cookie{
		Name:     auth.OAuthStateCookieName,
		Value:    state,
		Path:     "/",
		Expires:  expires,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// expiredCookie clears one. MaxAge is negative AND Expires is in the past, because browsers
// disagree about which they honour and a session cookie that survives a sign-out is the bug.
func expiredCookie(name string) http.Cookie {
	return http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// redirectResponses describes the 303 these operations answer with.
//
// Written out rather than reflected, for the same reason as the index endpoints: the output type
// says nothing a reader of the document wants, and the interesting part is the Location header.
func redirectResponses(where string) map[string]*huma.Response {
	return map[string]*huma.Response{
		"303": {
			Description: "A redirect. " + where,
			Headers: map[string]*huma.Param{
				"Location": {Description: "Where to go next.", Schema: &huma.Schema{Type: "string"}},
			},
		},
	}
}
