package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
)

// Authenticator resolves whatever credential a request carried into a principal.
//
// A consumer-declared interface, like Catalogue: internal/api describes what it needs and the
// wiring supplies it. What it deliberately does NOT describe is which credential kinds exist —
// Resolve takes both and decides, so adding personal access tokens is a change in one package
// rather than a new method every implementation has to grow.
type Authenticator interface {
	Resolve(ctx context.Context, creds auth.Credentials) (auth.Principal, error)
}

// ReviewerCheck answers whether an account may moderate this registry.
//
// A consumer-declared interface like the rest: this package says what it needs and the wiring
// supplies it. It takes an account id rather than a principal so that the implementation cannot
// accidentally depend on HOW somebody authenticated — the floor has already settled that, and this
// answers a different question.
type ReviewerCheck interface {
	IsReviewer(ctx context.Context, accountID string) (bool, error)
}

// principalKey is the context key the middleware stores the resolved principal under. It is an
// unexported struct type so nothing outside this package can write one, which is the difference
// between "the middleware decided who you are" and "somebody set a value".
type principalKey struct{}

// PrincipalFrom returns the principal the middleware resolved for this request.
//
// The boolean is second so that ignoring it cannot compile into a handler acting as an empty
// account. A handler for an authenticated operation can rely on it being present: the middleware
// answers 401 before the handler runs, so `false` there means the route was declared public.
func PrincipalFrom(ctx context.Context) (auth.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(auth.Principal)
	return p, ok
}

// metaAccess is the Metadata key register() stores the Access under.
//
// Metadata rather than Extensions because Metadata is NOT serialised into the OpenAPI document:
// the extensions are the public description of the rule and this is the rule itself, read back by
// the middleware that enforces it. One declaration, rendered for readers and executed for callers,
// so the document cannot describe an access rule the server does not apply.
const metaAccess = "regserve.access"

// authMiddleware enforces the Access every operation declared.
//
// It is the other half of law 6. PERM001 asserts that every operation DECLARES who may call it;
// this is what makes the declaration do something. Enforcing from the same value the document is
// rendered from means "the spec says a session is required" and "the server requires a session"
// cannot drift apart — there is one value and two readers.
func authMiddleware(
	api huma.API, authn Authenticator, reviewers ReviewerCheck,
) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		access, ok := accessFor(ctx)
		if !ok {
			// Unreachable through register(), which always sets it. Refusing rather than allowing
			// is the only safe reading of "this route did not say who may call it".
			slog.ErrorContext(ctx.Context(), "operation carries no access declaration",
				"operation", operationID(ctx))
			writeProblem(api, ctx, http.StatusInternalServerError, "")
			return
		}
		if access.public {
			next(withBrowserSession(ctx, authn))
			return
		}

		if authn == nil {
			// An authenticated route registered on a build with no way to authenticate is a wiring
			// bug, not a client error. It is a 503 rather than a 500 because the honest statement
			// is "this instance cannot serve this yet".
			writeProblem(api, ctx, http.StatusServiceUnavailable,
				"this instance is not configured to authenticate requests")
			return
		}

		principal, err := authn.Resolve(ctx.Context(), credentialsFrom(ctx))
		switch {
		case errors.Is(err, auth.ErrNoCredential):
			writeProblem(api, ctx, http.StatusUnauthorized,
				"this operation needs a signed-in session or a personal access token")
			return
		case errors.Is(err, auth.ErrCredentialRejected):
			// One message for expired, revoked, unknown and disabled. Distinguishing them would
			// tell a holder whether the value they have was ever real.
			writeProblem(api, ctx, http.StatusUnauthorized,
				"the credential presented was not accepted")
			return
		case err != nil:
			slog.ErrorContext(ctx.Context(), "resolve the request credential", "error", err)
			writeProblem(api, ctx, http.StatusInternalServerError, "")
			return
		}

		if detail, denied := access.deny(principal); denied {
			writeProblem(api, ctx, http.StatusForbidden, detail)
			return
		}
		if detail, denied := access.denyPlugin(principal, ctx); denied {
			writeProblem(api, ctx, http.StatusForbidden, detail)
			return
		}
		if !allowReviewer(ctx, api, access, principal, reviewers) {
			return
		}

		next(huma.WithValue(ctx, principalKey{}, principal))
	}
}

// deny reports why a resolved principal may not perform this operation, and whether it may not.
//
// It lives on Access so that the rule and its rendering are the same object. The capability floor
// is checked BEFORE the scopes: "no token may ever do this" is not a scope that has not been
// granted, and a 403 that suggests minting a better-scoped token would be advice to do something
// impossible.
func (a Access) deny(p auth.Principal) (string, bool) {
	if !p.ViaToken() {
		// A session is the account. Per-plugin ownership is checked by the handler at the moment
		// of the change (ADR-0005), not here — this layer answers "may this credential act at
		// all", and the handler answers "on this plugin".
		return "", false
	}
	if a.patForbidden {
		return "this operation is session-only: a token that could perform it would be equivalent " +
			"to the account, so no token carries it however it is scoped", true
	}
	if !authz.Satisfies(a.permission, p.Scopes) {
		return "this token does not carry a scope that grants " + a.permission.String(), true
	}
	return "", false
}

// denyPlugin enforces a token's plugin pin against the plugin the operation acts on.
//
// This is the second half of ADR-0005's containment: the scope says what a credential may do, the
// pin says what it may do it to, and a token leaked from one plugin's pipeline is contained only
// if both are checked. It runs in the middleware rather than in handlers because a check a handler
// performs is a check the next handler forgets — and the failure is silent, since a pinned token
// that is never compared behaves exactly like an unpinned one.
//
// A pinned token calling an operation that declares NO plugin parameter is refused. That is
// deliberate and conservative: the pin cannot be checked there, and "cannot check" must not
// resolve to "allow" — that is precisely how a pin becomes decorative. An operation that should be
// callable by a pinned token declares its parameter with Access.OnPlugin.
func (a Access) denyPlugin(p auth.Principal, ctx huma.Context) (string, bool) {
	if !p.Pinned() {
		return "", false
	}
	if a.pluginParam == "" {
		return "this token is pinned to a single plugin, and this operation does not act on one", true
	}
	if !p.AllowsPlugin(ctx.Param(a.pluginParam)) {
		// The token's own plugin is NOT named in the message. The holder knows it; anybody who has
		// stolen the token would be learning which plugin to point it at.
		return "this token is pinned to a different plugin", true
	}
	return "", false
}

// allowReviewer enforces Access.Reviewer, and reports whether the request may continue.
//
// It writes its own refusal rather than returning one, because there are three of them and each is
// a different statement: a build with no reviewer check wired, a failure to answer the question,
// and an account that is simply not a reviewer.
func allowReviewer(
	ctx huma.Context, api huma.API, access Access, p auth.Principal, reviewers ReviewerCheck,
) bool {
	if !access.reviewerOnly {
		return true
	}
	if reviewers == nil {
		// A reviewer-only route registered on a build that cannot answer the question. Refusing is
		// the only safe reading; 503 because the honest statement is "this instance cannot serve
		// this", exactly as for a nil Authenticator.
		writeProblem(api, ctx, http.StatusServiceUnavailable,
			"this instance is not configured to decide who may review")
		return false
	}

	ok, err := reviewers.IsReviewer(ctx.Context(), p.AccountID)
	if err != nil {
		// "We could not check" must never resolve to "allow". The cause goes to the log.
		slog.ErrorContext(ctx.Context(), "check whether the caller may review",
			"operation", operationID(ctx), "error", err)
		writeProblem(api, ctx, http.StatusInternalServerError, "")
		return false
	}
	if !ok {
		// 403 and not 404. Unlike a plugin somebody does not own, the existence of a review queue
		// is not a secret, and hiding it would only confuse an operator who has misspelled their
		// own handle in the deployment configuration.
		writeProblem(api, ctx, http.StatusForbidden,
			"this registry's reviewers are configured by whoever operates the deployment, and "+
				"this account is not one of them")
		return false
	}
	return true
}

// credentialsFrom reads whatever the request presented. It never logs either value.
// withBrowserSession attaches the principal a PUBLIC request's session cookie resolves to, if
// there is one, and otherwise changes nothing.
//
// It exists so that a public page can be honest about who is reading it. Without it, the directory
// would greet a signed-in visitor with a "sign in" link, which is the confident mistake this
// repository is written against: a page that states something false about the reader's own state.
//
// THREE PROPERTIES, EACH DELIBERATE.
//
//   - IT NEVER REFUSES. A public operation was already allowed before this ran, and no failure
//     here changes that: a revoked session, an expired one, a database that will not answer, all
//     produce an anonymous page rather than an error. Attaching decoration must not be able to
//     take a route away.
//   - IT COSTS NOTHING WITHOUT A COOKIE. The lookup happens only for a request carrying the
//     session cookie, so /index.json, /healthz and every client poll are untouched: they carry
//     no cookie and never reach the store.
//   - IT IGNORES THE AUTHORIZATION HEADER. A personal access token must not authenticate a browser
//     surface, and this is a browser surface: only the session cookie is offered to the resolver,
//     so a token cannot put an account's name on a page however it is scoped.
func withBrowserSession(ctx huma.Context, authn Authenticator) huma.Context {
	if authn == nil {
		return ctx
	}
	cookie, err := huma.ReadCookie(ctx, auth.SessionCookieName)
	if err != nil || cookie.Value == "" {
		return ctx
	}

	principal, err := authn.Resolve(ctx.Context(), auth.Credentials{SessionCookie: cookie.Value})
	if err != nil || principal.AccountID == "" {
		// Not logged at error: an expired cookie on a public page is an ordinary Tuesday, and a
		// log line per visit would bury the ones that matter.
		return ctx
	}
	return huma.WithValue(ctx, principalKey{}, principal)
}

func credentialsFrom(ctx huma.Context) auth.Credentials {
	var creds auth.Credentials
	if c, err := huma.ReadCookie(ctx, auth.SessionCookieName); err == nil {
		creds.SessionCookie = c.Value
	}
	if h := ctx.Header("Authorization"); h != "" {
		if rest, ok := strings.CutPrefix(h, "Bearer "); ok {
			creds.BearerToken = strings.TrimSpace(rest)
		}
	}
	return creds
}

// RefuseTokenInQuery answers 401 to any request carrying something shaped like a PAT in its query
// string. Canonical §6: no exception.
//
// A plain http.Handler wrapper rather than Huma middleware, for the reason the request-id and
// secure-header wrappers give: Huma middleware runs only for a route that MATCHED, so a token sent
// to a misspelled path or with the wrong method would be answered 404 or 405 by the mux with the
// check never running. The rule is about the value being in a URL — by the time it is there it is
// in an access log, a proxy log and a browser history — so what it was sent to does not enter into
// it, and neither does whether the route was public.
//
// It matches on the token's own prefix rather than on parameter names. `?access_token=` is the
// spelling people expect; a token sent as `?t=` is in exactly as many logs.
func RefuseTokenInQuery(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !tokenInQuery(r.URL) {
			next.ServeHTTP(w, r)
			return
		}

		// Written here rather than through Huma, which is not in this layer. It is the same
		// document type handlers return, so a client parses one shape whatever refused it.
		problem := NewProblem(http.StatusUnauthorized, CodeUnauthorized,
			"a token in a query string is never accepted; send it as an Authorization header")
		body, err := json.Marshal(problem)
		if err != nil {
			// Unreachable: Problem is four strings and an int. Refusing loudly beats serving the
			// request we just decided to refuse.
			slog.ErrorContext(r.Context(), "render the query-token problem", "error", err)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", problemContentType)
		w.WriteHeader(http.StatusUnauthorized)
		if _, err := w.Write(body); err != nil {
			slog.ErrorContext(r.Context(), "write the query-token problem", "error", err)
		}
	})
}

// tokenInQuery reports whether any query parameter carries something shaped like a PAT.
func tokenInQuery(u *url.URL) bool {
	if u == nil || !strings.Contains(u.RawQuery, auth.TokenPrefix) {
		return false
	}
	for _, values := range u.Query() {
		for _, v := range values {
			if strings.HasPrefix(v, auth.TokenPrefix) {
				return true
			}
		}
	}
	return false
}

func accessFor(ctx huma.Context) (Access, bool) {
	op := ctx.Operation()
	if op == nil || op.Metadata == nil {
		return Access{}, false
	}
	a, ok := op.Metadata[metaAccess].(Access)
	return a, ok
}

func operationID(ctx huma.Context) string {
	if op := ctx.Operation(); op != nil {
		return op.OperationID
	}
	return ""
}

// writeProblem writes one of the closed-enum problem documents from middleware.
//
// It goes through huma.WriteErr, which goes through huma.NewError, which errors.go has replaced
// with *Problem — so a refusal raised here is the same document, with the same `code` member and
// the same `application/problem+json` type, as one a handler returns. Two shapes of error response
// would mean a client needs two parsers to find out it is not signed in.
//
// The `code` is NOT passed: codeForStatus is the one mapping from a status to the closed enum, and
// letting middleware choose its own would be a second place where 403 decides what it means. A
// detail is ignored for 5xx by design — see detailFor.
func writeProblem(api huma.API, ctx huma.Context, status int, detail string) {
	if err := huma.WriteErr(api, ctx, status, detail); err != nil {
		slog.ErrorContext(ctx.Context(), "write the problem document", "error", err)
	}
}
