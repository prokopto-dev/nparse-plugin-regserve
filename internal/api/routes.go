package api

import (
	"context"

	"github.com/danielgtaylor/huma/v2"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
)

// The OpenAPI extension keys. They are `x-regserve-` prefixed because an extension is public API
// too: a generated SDK, the docs site and the coverage gate all read them.
const (
	// ExtPermission names the permission an operation requires, from the catalogue in
	// internal/authz. Its presence is what law 6's coverage is derived FROM — the gate walks the
	// generated document, so a new operation that declares nothing is a red test rather than a
	// route nobody wrote a test for.
	ExtPermission = "x-regserve-permission"

	// ExtPublic marks an operation as deliberately unauthenticated. A permission and this are
	// mutually exclusive, and an operation with neither is the failure the gate exists to catch:
	// "public" has to be a decision somebody wrote down, not the absence of one.
	ExtPublic = "x-regserve-public"

	// ExtPATForbidden marks a capability-floor operation: one no token may perform, however
	// scoped, because a token that could would be equivalent to the account. Canonical §5.
	ExtPATForbidden = "x-regserve-pat-forbidden"

	// ExtReviewer marks an operation only a configured reviewer of this registry may perform:
	// approving a release, rejecting one, asking the server to fetch an artifact again. It is
	// ALWAYS paired with the capability floor — PERM001 fails a reviewer operation that is not —
	// because "only a reviewer may do this" and "no token may do this" are both true and the
	// second is the stronger statement.
	ExtReviewer = "x-regserve-reviewer"

	// ExtPluginParam names the path parameter identifying the plugin an operation acts on, so a
	// token's plugin pin can be enforced against it. Its ABSENCE on a token-callable operation
	// under /plugins/{…} is what gate PERM001 fails: a pin nothing compares is decorative, and it
	// fails open.
	ExtPluginParam = "x-regserve-plugin-param"
)

// The security scheme names an operation's requirements refer to. They are declared once, in the
// document's components, and named here so a requirement cannot cite a scheme that does not exist.
const (
	SchemePAT     = "pat"
	SchemeSession = "session"
)

// Access declares who may call an operation.
//
// Its fields are unexported and it is built only through the constructors below, so the zero value
// is not a usable declaration — it is the absence of one, which is exactly what the coverage gate
// looks for. A route added without saying who may call it cannot compile into something that looks
// decided.
type Access struct {
	public       bool
	permission   authz.Permission
	scopes       []authz.Scope
	patForbidden bool

	// pluginParam names the PATH PARAMETER that identifies the plugin an operation acts on, and is
	// empty for an operation that does not act on one. See OnPlugin.
	pluginParam string

	// reviewerOnly restricts the operation to a configured reviewer of this registry. See Reviewer.
	reviewerOnly bool
}

// Reviewer restricts an operation to a configured reviewer of this registry.
//
// Moderation is not a permission anybody can be granted through this service. Reviewers are named
// in the deployment's environment, so the people who may approve what gets listed are the people
// who control what the droplet runs — the same place the authority came from when this was a
// GitHub repository and a merge button. internal/review says why that is not a database row.
//
// It composes with Floor rather than replacing it: `Floor("release.review").Reviewer()`. The floor
// says no token may ever do this, and this says not every session may either. PERM001 fails a
// reviewer operation that is not also floor, because a reviewer-only operation reachable by a
// scoped token would be moderation delegated to a CI credential.
//
// The check runs in the MIDDLEWARE, from this declaration, for the reason the plugin pin does: a
// check a handler performs is a check the next handler forgets, and the failure is silent.
func (a Access) Reviewer() Access {
	a.reviewerOnly = true
	return a
}

// OnPlugin declares which path parameter names the plugin this operation acts on.
//
// It is what makes a token's plugin pin enforceable. A PAT may be minted for one plugin (ADR-0005)
// so that the credential sitting in one repository's CI can do exactly one thing to exactly one
// plugin — and that is only true if something compares the pin against the plugin being acted on.
// Declaring the parameter here means the comparison happens in the middleware, before the handler
// runs, rather than in each handler that remembers to.
//
// The parameter has to be NAMED rather than guessed. `/plugins/{id}/releases` and
// `/account/tokens/{id}/revoke` both have an `{id}`, and one of them is not a plugin.
func (a Access) OnPlugin(param string) Access {
	a.pluginParam = param
	return a
}

// Public is an operation anyone may call with no credential at all: the index endpoints a desktop
// client polls, and the health probes an orchestrator hits.
func Public() Access { return Access{public: true} }

// Requires is an operation a caller must be authenticated for, holding permission p.
//
// Scopes are what a PAT must carry as well. Passing none means the operation is session-only by
// omission — a token cannot reach it because no scope names it — which canonical §5 distinguishes
// from the capability floor below: the floor is a deliberate refusal, this is simply an operation
// no scope has been minted for yet.
func Requires(p authz.Permission, scopes ...authz.Scope) Access {
	return Access{permission: p, scopes: scopes}
}

// Floor is a capability-floor operation: session-only, no scope, and no token may ever perform it.
//
// Minting tokens, changing owners, and setting trust levels are the members. A token that could do
// any of them would be equivalent to the account, which is the thing there is deliberately no way
// to mint. There is no `admin:*`.
func Floor(p authz.Permission) Access {
	return Access{permission: p, patForbidden: true}
}

// security renders the OpenAPI security requirement.
//
// A public operation gets an explicitly EMPTY list rather than no list. In OpenAPI those mean
// different things: an absent `security` inherits the document-level default, so an operation that
// simply forgot to say would silently become authenticated (or silently not) depending on a
// setting somewhere else. `security: []` says "this one, deliberately, needs nothing".
func (a Access) security() []map[string][]string {
	if a.public {
		return []map[string][]string{}
	}

	// The session cookie always satisfies an authenticated operation: it is the credential a human
	// has in a browser, and the capability floor accepts nothing else.
	reqs := []map[string][]string{}
	if len(a.scopes) > 0 && !a.patForbidden {
		scopes := make([]string, 0, len(a.scopes))
		for _, s := range a.scopes {
			scopes = append(scopes, s.String())
		}
		reqs = append(reqs, map[string][]string{SchemePAT: scopes})
	}
	return append(reqs, map[string][]string{SchemeSession: {}})
}

// extensions renders the x-regserve-* metadata onto the operation.
func (a Access) extensions(into map[string]any) map[string]any {
	if into == nil {
		into = map[string]any{}
	}
	if a.public {
		into[ExtPublic] = true
		return into
	}
	into[ExtPermission] = a.permission.String()
	if a.patForbidden {
		into[ExtPATForbidden] = true
	}
	if a.reviewerOnly {
		into[ExtReviewer] = true
	}
	return into
}

// register is the ONLY way a route enters this service.
//
// Taking the access declaration as a required argument alongside the operation is the mechanism:
// there is no overload that omits it, so "we forgot to decide who may call this" is not a state a
// registered route can be in. Gate PERM001 asserts both halves — that every operation in the
// generated document carries a declaration, and that nothing in this package calls huma.Register
// around the side of this function.
//
// The handler signature is Huma's: it takes a typed input and returns a typed output or an error.
// It never sees an http.ResponseWriter, which is what stops a handler from inventing a status, a
// content type, or a body shape that the OpenAPI document does not describe (canonical §6).
func register[I, O any](
	api huma.API, access Access, op huma.Operation, handler func(context.Context, *I) (*O, error),
) {
	op.Security = access.security()
	op.Extensions = access.extensions(op.Extensions)
	if access.pluginParam != "" {
		op.Extensions[ExtPluginParam] = access.pluginParam
	}

	// The same declaration, stored twice for two readers. Extensions are the PUBLIC description of
	// the rule and go into the OpenAPI document; Metadata is not serialised and is what the
	// enforcing middleware reads back. One value, so "the spec says a session is required" and
	// "the server requires a session" cannot become different statements.
	if op.Metadata == nil {
		op.Metadata = map[string]any{}
	}
	op.Metadata[metaAccess] = access

	huma.Register(api, op, handler)
}
