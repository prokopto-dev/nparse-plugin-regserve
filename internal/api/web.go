package api

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
)

// The account surface: server-rendered HTML from this same binary.
//
// It exists because the capability floor (canonical §5) makes minting a token, changing owners and
// setting trust SESSION-ONLY — which is to say browser-only. Without pages, Phase 2 would ship a
// floor nobody can reach. There is no JavaScript build, no separate deploy target and no new
// service in compose: html/template and one embedded stylesheet.
//
// THESE ROUTES GO THROUGH THE SAME REGISTRY AS EVERY OTHER ROUTE, and are therefore in the OpenAPI
// document. Huma can hide an operation, and hiding these would have been tidier — the document is
// an SDK contract and nobody generates an SDK for an HTML page. It is deliberately not done:
// PERM001 walks that document, so a hidden route is a route whose access declaration no gate
// checks. A slightly noisier spec is the price of the coverage being real.
//
// Every authenticated page here is Floor(...): a PAT must not authenticate a browser surface, and
// each of these pages exists to perform an operation the floor already covers.
const (
	// PathHome is the directory, and is registered in directory.go rather than here: it is a
	// PUBLIC page now, wired from the catalogue rather than from the sign-in machinery. The
	// constant stays in this list because the layout every page shares links to it.
	PathHome           = "/"
	PathAccountPage    = "/account"
	PathMintToken      = "/account/tokens"
	PathRevokeToken    = "/account/tokens/{id}/revoke"
	PathPluginSettings = "/plugins/{id}/settings"
	PathPluginOwners   = "/plugins/{id}/owners"

	// PathClaimPlugin is the browser form that registers a plugin id. It sits under /account and
	// not at /plugins for the reason the token forms do: it is a form on the account surface, and
	// the account surface is the only place a capability-floor operation can be performed at all.
	//
	// It is a SECOND door onto the same act as POST /api/v1/plugins, not a replacement for it. The
	// JSON endpoint is the contract; this is the form, and both go through the same Claimer and
	// the same Floor declaration. What existed before was only the first, which is a
	// session-only operation with no session-shaped way to reach it — so the answer to "how do I
	// claim an id" was "send the request yourself", and the author this shipped for did not.
	PathClaimPlugin = "/account/plugins"
)

// tagAccount groups the browser pages in the document, away from the API operations.
const tagAccount = "account"

// contentTypeHTML is written explicitly. With no Content-Type at all net/http sniffs the body, and
// a page that begins with a comment can be sniffed as text/plain.
const contentTypeHTML = "text/html; charset=utf-8"

//go:embed webtmpl/*.html webtmpl/assets/*.svg
var webFiles embed.FS

// pages is parsed once, at package init, because a template that fails to parse should take the
// build's tests down rather than the first request that reaches it.
//
// html/template, NOT text/template: it escapes by contextual position — inside an attribute, a URL,
// a script — and that is what makes a plugin id or a display name coming from a provider safe to
// render. Nothing here reaches for template.HTML to make something render; if a value needs it,
// the answer is that the value is wrong.
//
// The vendored mark is parsed alongside the pages, and that is what lets layout.html inline it
// with `{{template "nparseplus-mark.svg" .}}`: a template's own body is literal markup, so the SVG
// is emitted verbatim without template.HTML and without a hand-copied second version of it in the
// layout. html/template elides the file's long provenance comment on the way out, so the page
// carries the markup and the reasoning stays on disk where somebody editing it will read it.
var pages = template.Must(template.ParseFS(webFiles, "webtmpl/*.html", "webtmpl/assets/*.svg"))

// WebDeps is what the account surface needs. Consumer-declared, like every other dependency in
// this package.
type WebDeps struct {
	Sessions  SessionIssuer
	Tokens    TokenService
	Ownership OwnershipService
	Providers *identity.Registry

	// Claimer registers plugin ids. NIL MEANS THE FORM IS NOT REGISTERED AND NOT RENDERED — the
	// same principle every other optional dependency here follows. A page that offered a form
	// posting to a route this build does not serve would be an on-ramp ending in a 404, which is
	// the exact failure this form exists to remove.
	Claimer Claimer

	// Queue and Reviewers back the review pages, and are needed TOGETHER for the reason the JSON
	// API needs them together: a reviewer-only route on a build that cannot say who reviews is a
	// wiring bug worth making unrepresentable rather than answering 503 for.
	//
	// Nil means the review pages are not registered at all — an honest 404 rather than a queue
	// nobody can work.
	Queue     ReviewQueue
	Reviewers ReviewerCheck
}

// Claimer is declared in plugins.go, next to the JSON endpoint that was its first consumer. The
// account surface takes the same interface rather than a second spelling of it: one act, one
// service, two doors.

// OwnershipService is the part of internal/ownership the pages use.
type OwnershipService interface {
	Mine(ctx context.Context, accountID string) ([]ownership.Plugin, error)
	Owners(ctx context.Context, pluginID, callerID string) ([]ownership.Owner, error)
	RoleOf(ctx context.Context, pluginID, accountID string) (ownership.Role, bool, error)
	Add(ctx context.Context, pluginID, callerID, handle string, role ownership.Role) error
	Remove(ctx context.Context, pluginID, callerID, targetID string) error
}

// pageData is what every template is rendered with. One type, so the layout can rely on the header
// fields being present whatever page is inside it.
type pageData struct {
	Title     string
	Account   *auth.Principal
	CSRFField string
	CSRFToken string

	// Notice and Problem are the two ways a page talks back after a form post. They are set from
	// a fixed set of messages this package writes, never from user input — a page that echoes what
	// was submitted is a page that renders whatever was submitted.
	Notice  string
	Problem string

	Providers []identity.Kind
	Plugins   []ownership.Plugin
	Tokens    []auth.Listing
	Scopes    []scopeOption
	NewToken  string
	Plugin    *ownership.Plugin
	Owners    []ownership.Owner

	// CanClaim decides whether a page offers the claim form, and HasAccountPage whether it may
	// send a reader to /account at all. Both are WIRING and not authorisation — every session may
	// claim an id — and both are false only where the routes in question are not registered.
	//
	// The public on-ramp needs the second as well as the first: an instance with sign-in and no
	// Claimer serves /account and mints tokens and cannot claim an id, so "there is no account
	// page here" and "you cannot claim here" are different sentences and it must not print the
	// wrong one.
	CanClaim       bool
	HasAccountPage bool

	// HasClaimEndpoint is whether POST /api/v1/plugins is served AND reachable. The public
	// on-ramp needs it as a third state: a build can serve that endpoint with no account page at
	// all, and telling its readers there is no way to claim an id would be false.
	HasClaimEndpoint bool

	// CanManageOwners gates the owner forms. A maintainer holds the plugin and may publish to it,
	// and may not change who holds it — so the page does not offer controls the service will
	// refuse. Both this and the refusal read the same fact through Role.CanManageOwners.
	CanManageOwners bool

	// Queue and Release are the review surface's data. Release is a pointer because "no release on
	// this page" is a real state and a zero-valued one would render as a release with no id.
	Queue   []review.Waiting
	Release *review.Detail

	// The public directory's fields. Query is the SEARCH TEXT the visitor typed, echoed back into
	// the box so a result page can be read and refined rather than retyped — the one value on any
	// of these pages that comes from a caller and is rendered back to them. html/template escapes
	// it by position, which is why that is safe to do here and would not be safe as a Notice: a
	// notice is prose this package writes, and a value that becomes prose is a value that becomes
	// whatever was submitted.
	Query   string
	Found   *Browsed
	Listing *registry.Plugin

	// IndexPath is always this service's index route; IndexURL is the absolute form, and is empty
	// on an instance that was never told its own public URL. The page shows whichever it has and
	// never assembles one from the request's Host header, which the caller controls.
	IndexPath string
	IndexURL  string

	// IsReviewer decides whether the layout offers a link to the queue. It is DECORATION and not
	// authorisation: the middleware refuses a non-reviewer at every review route whatever this
	// says, and a page that hid the link would still be a page that could not be reached. Its job
	// is that a reviewer landing on their account page can find the queue at all.
	IsReviewer bool

	// NoReviewers says this deployment has named NOBODY who may moderate, which is a different
	// statement from "you may not" and the one nothing was making.
	//
	// Without it the two are one blank page. `REGSERVE_REVIEWERS` is defaulted empty in the
	// compose file, so an instance where every submission queues for ever and no human can act on
	// any of it looks exactly like an instance whose queue happens to be empty — from the account
	// page, from the missing link, and from the outside. That ambiguity is what "never hide a row
	// silently" is about, and it costs an author waiting on a release more than it costs anybody
	// else.
	//
	// It is a FACT ABOUT THE DEPLOYMENT and is therefore shown to every signed-in account rather
	// than to operators only: the person who most needs it is whoever is wondering why their
	// release has not appeared, and there is nothing here to keep back — a registry that can
	// approve nothing is the safest state this service has, not an exploitable one. What is kept
	// back is who the reviewers ARE, and how many: see review.Reviewers.Configured.
	NoReviewers bool
}

// scopeOption is one checkbox on the mint form, from the catalogue rather than from a list here.
type scopeOption struct {
	Name    string
	Summary string
}

// htmlOutput is a rendered page. Body is []byte for the same reason the index endpoints' is: Huma
// writes it verbatim, so the bytes that leave are the bytes html/template produced.
type htmlOutput struct {
	Status       int
	ContentType  string `header:"Content-Type"`
	CacheControl string `header:"Cache-Control"`
	Body         []byte
}

func registerWeb(api huma.API, deps WebDeps) {
	registerAccountPage(api, deps)
	registerTokenForms(api, deps)
	registerPluginPages(api, deps)

	// Registered only when there is something to claim through, and the page asks the same
	// question before it renders the form. Both read deps.Claimer, so the form and the route
	// cannot disagree about whether this build can claim an id.
	if deps.Claimer != nil {
		registerClaimForm(api, deps)
	}

	// Both or neither, exactly as the JSON API's review routes are wired: a reviewer-only page on
	// a build that cannot answer "is this account a reviewer" is a page the middleware refuses
	// with a 503, which reads to an operator like an outage rather than a missing variable.
	if deps.Queue != nil && deps.Reviewers != nil {
		registerReviewPages(api, deps)
	}
}

func registerAccountPage(api huma.API, deps WebDeps) {
	register(api, Floor("token.read"), huma.Operation{
		OperationID: "getAccountPage",
		Method:      http.MethodGet,
		Path:        PathAccountPage,
		Summary:     "Your plugins and your tokens",
		Description: "An HTML page. Capability-floor: a personal access token cannot read this, " +
			"because a token that could list and mint tokens would be equivalent to the account.",
		Tags:      []string{tagAccount},
		Errors:    []int{http.StatusUnauthorized, http.StatusForbidden},
		Responses: htmlResponses(),
	}, func(ctx context.Context, in *accountInput) (*htmlOutput, error) {
		p, err := requirePrincipal(ctx)
		if err != nil {
			return nil, err
		}
		data, err := accountData(ctx, deps, p)
		if err != nil {
			return nil, err
		}
		data.Notice, data.Problem = messageFor(in.Message)
		return renderPage(ctx, "account.html", data)
	})
}

// accountInput is what a redirect after a form post carries back.
//
// A message CODE, never a message. Prose in a query string is prose an attacker can put there: a
// crafted link would render whatever sentence they chose, inside our page, under our domain. It
// would be escaped — html/template sees to that — and it would still say what they wrote. The code
// is looked up in a fixed table, so a value nobody wrote renders nothing.
//
// There is deliberately NO parameter carrying a minted token. Canonical §6 refuses a token in a
// query string with no exception, and this service enforces that on every request before a handler
// runs — including its own redirects. See mintToken for where the secret goes instead.
type accountInput struct {
	Message string `query:"msg" doc:"A message code from a completed form post."`
}

type pluginPageInput struct {
	ID      string `path:"id"`
	Message string `query:"msg"`
}

func registerTokenForms(api huma.API, deps WebDeps) {
	register(api, Floor("token.mint"), huma.Operation{
		OperationID:  "mintToken",
		MaxBodyBytes: maxFormBytes,
		Method:       http.MethodPost,
		Path:         PathMintToken,
		Summary:      "Mint a personal access token",
		Description: "An HTML form post. The secret is shown exactly once and is never " +
			"recoverable afterwards: what is stored is a keyed hash of it.",
		Tags:      []string{tagAccount},
		Errors:    []int{http.StatusUnauthorized, http.StatusForbidden},
		Responses: htmlResponses(),
	}, func(ctx context.Context, in *mintTokenInput) (*htmlOutput, error) {
		form := parseForm(in.RawBody)
		p, err := requireFormPrincipal(ctx, deps, form.Get(auth.CSRFFieldName))
		if err != nil {
			return nil, err
		}

		requested := form["scope"]
		scopes := make([]authz.Scope, 0, len(requested))
		for _, s := range requested {
			scopes = append(scopes, authz.Scope(s))
		}

		data, dataErr := accountData(ctx, deps, p)
		if dataErr != nil {
			return nil, dataErr
		}

		minted, err := deps.Tokens.Mint(ctx, auth.MintRequest{
			AccountID: p.AccountID,
			Name:      form.Get("name"),
			Scopes:    scopes,
			PluginID:  form.Get("plugin_id"),
		})
		if err != nil {
			data.Problem = mintProblem(ctx, err)
			return renderPage(ctx, "account.html", data)
		}
		// The prefix is logged and the secret is not. That is what the public half is for.
		slog.InfoContext(ctx, "token minted",
			"account_id", p.AccountID, "token_prefix", minted.Prefix, "scopes", requested)

		// THE SECRET IS RENDERED INTO THIS RESPONSE AND GOES NOWHERE ELSE. Every other form here
		// answers with post/redirect/get; this one deliberately does not, and the reason is that
		// the alternatives are all worse:
		//
		//   - a redirect carrying the token in the query string is refused by this service's own
		//     middleware, and rightly — canonical §6 has no exception, and a URL is a thing that
		//     reaches access logs, proxy logs and browser history;
		//   - a redirect carrying it in a cookie writes the secret to the client's disk;
		//   - a server-side flash means storing the secret, and the entire argument for this
		//     design is that the secret is never stored.
		//
		// So it exists in exactly one place for exactly one response, which is the strongest
		// property available. The cost, stated rather than hidden: a browser refresh re-posts the
		// form and mints a SECOND token. That is visible on the page it lands on and revocable
		// from it, which is a cost, not a hole.
		data.NewToken = minted.Secret
		data.Tokens = append([]auth.Listing{{
			ID: minted.ID, Prefix: minted.Prefix, Name: strings.TrimSpace(form.Get("name")),
			Scopes: scopes, PluginID: form.Get("plugin_id"),
		}}, data.Tokens...)
		return renderPage(ctx, "account.html", data)
	})

	register(api, Floor("token.revoke"), huma.Operation{
		OperationID:  "revokeToken",
		MaxBodyBytes: maxFormBytes,
		Method:       http.MethodPost,
		Path:         PathRevokeToken,
		Summary:      "Revoke a personal access token",
		Tags:         []string{tagAccount},
		Errors:       []int{http.StatusUnauthorized, http.StatusForbidden},
		Responses:    redirectResponses("Your account page."),
	}, func(ctx context.Context, in *revokeTokenInput) (*redirectOutput, error) {
		p, err := requireFormPrincipal(ctx, deps, parseForm(in.RawBody).Get(auth.CSRFFieldName))
		if err != nil {
			return nil, err
		}

		switch err := deps.Tokens.Revoke(ctx, p.AccountID, in.ID); {
		case errors.Is(err, auth.ErrNoSuchToken):
			// The same answer for "not yours" and "already revoked". The id came from a page, but
			// it arrives in a URL, and distinguishing the two would be an oracle for other
			// people's token ids.
			return redirectTo(PathAccountPage, msgTokenNotRevoked), nil
		case err != nil:
			slog.ErrorContext(ctx, "revoke a token", "account_id", p.AccountID, "error", err)
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError,
				"the token could not be revoked")
		}
		return redirectTo(PathAccountPage, msgTokenRevoked), nil
	})
}

// The form inputs.
//
// Huma binds JSON bodies and multipart forms; it does NOT bind
// `application/x-www-form-urlencoded` fields onto struct tags, so the body arrives as bytes and is
// parsed here. That is explicit rather than clever, which suits a surface where the interesting
// question is what happens to a field somebody forged.
//
// MaxBodyBytes is set on every one of these operations. A form here is a few hundred bytes; the
// cap is what stops a POST to a browser route from being an allocation chosen by the caller.
type mintTokenInput struct {
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

type revokeTokenInput struct {
	ID      string `path:"id"`
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

func registerPluginPages(api huma.API, deps WebDeps) {
	register(api, Floor("owner.manage"), huma.Operation{
		OperationID: "getPluginSettingsPage",
		Method:      http.MethodGet,
		Path:        PathPluginSettings,
		Summary:     "A plugin's settings",
		Description: "An HTML page listing a plugin's owners. Capability-floor: changing owners " +
			"is session-only, and this is the page that does it.",
		Tags:      []string{tagAccount},
		Errors:    []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
		Responses: htmlResponses(),
	}, func(ctx context.Context, in *pluginPageInput) (*htmlOutput, error) {
		p, err := requirePrincipal(ctx)
		if err != nil {
			return nil, err
		}

		data, err := pluginData(ctx, deps, p, in.ID)
		if err != nil {
			return nil, err
		}
		data.Notice, data.Problem = messageFor(in.Message)
		return renderPage(ctx, "plugin.html", data)
	})

	register(api, Floor("owner.manage"), huma.Operation{
		OperationID:  "managePluginOwners",
		MaxBodyBytes: maxFormBytes,
		Method:       http.MethodPost,
		Path:         PathPluginOwners,
		Summary:      "Add or remove a plugin's owners",
		Description: "An HTML form post. A transfer is two steps — add the new owner, let them " +
			"mint their own token, then remove the old one — because a token stops working the " +
			"moment its holder stops being an owner.",
		Tags:      []string{tagAccount},
		Errors:    []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
		Responses: redirectResponses("The plugin's settings page."),
	}, func(ctx context.Context, in *ownersInput) (*redirectOutput, error) {
		form := parseForm(in.RawBody)
		p, err := requireFormPrincipal(ctx, deps, form.Get(auth.CSRFFieldName))
		if err != nil {
			return nil, err
		}

		id, err := core.ParsePluginID(in.ID)
		if err != nil {
			return nil, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
		}

		var opErr error
		switch form.Get("action") {
		case "add":
			// An unrecognised role becomes the NARROWER one. A form field is caller-controlled,
			// and the failure mode of guessing generously is a co-maintainer who can hand the
			// plugin to somebody else.
			role := ownership.Role(form.Get("role"))
			if !role.Valid() {
				role = ownership.RoleMaintainer
			}
			opErr = deps.Ownership.Add(ctx, id.String(), p.AccountID, form.Get("handle"), role)
		case "remove":
			opErr = deps.Ownership.Remove(ctx, id.String(), p.AccountID, form.Get("account_id"))
		default:
			return nil, NewProblem(http.StatusBadRequest, CodeInvalidRequest,
				"that is not something this form does")
		}

		if errors.Is(opErr, ownership.ErrNotAnOwner) {
			// Unknown and not-yours are the same answer: otherwise a signed-in account could
			// enumerate which plugin ids exist.
			return nil, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
		}
		return redirectTo("/plugins/"+id.String()+"/settings", ownerMessage(ctx, opErr)), nil
	})
}

type ownersInput struct {
	ID      string `path:"id"`
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

// registerClaimForm wires the browser form that registers a plugin id.
//
// THE SAME FLOOR AS THE JSON ENDPOINT, from the same catalogue permission: session-only, no scope,
// no token, ever. A form is not a softer door — it is the door the floor always implied and never
// had. ADR-0005's argument is that a deployment credential must not be able to grow its own reach,
// and that argument is untouched by there being a text box.
func registerClaimForm(api huma.API, deps WebDeps) {
	register(api, Floor("plugin.claim"), huma.Operation{
		// NOT `claimPlugin`: that is the JSON endpoint's OperationID, it is an SDK method name,
		// and OAPI001 requires ids to be unique. This one is the form post.
		OperationID:  "submitPluginClaim",
		MaxBodyBytes: maxFormBytes,
		Method:       http.MethodPost,
		Path:         PathClaimPlugin,
		Summary:      "Claim a plugin id",
		Description: "An HTML form post, and the browser half of `POST /api/v1/plugins`. " +
			"Capability-floor: claiming is session-only, so no personal access token can reach " +
			"either door, however scoped.\n\n" +
			"**Ids are first-come, permanent and never recycled.** Claiming does not list " +
			"anything: the first release of a new id always goes to human review.",
		Tags:      []string{tagAccount},
		Errors:    []int{http.StatusUnauthorized, http.StatusForbidden},
		Responses: redirectResponses("Your account page."),
	}, func(ctx context.Context, in *claimFormInput) (*redirectOutput, error) {
		form := parseForm(in.RawBody)
		p, err := requireFormPrincipal(ctx, deps, form.Get(auth.CSRFFieldName))
		if err != nil {
			return nil, err
		}

		id, err := core.ParsePluginID(strings.TrimSpace(form.Get("id")))
		if err != nil {
			// Refused before the claim is built, and the page says what an id looks like rather
			// than echoing what was typed. The rule itself is core's, so this cannot drift from
			// what the JSON endpoint accepts.
			return redirectTo(PathAccountPage, msgPluginIDInvalid), nil
		}

		claim := ownership.Claim{
			PluginID:    id,
			Name:        form.Get("name"),
			Description: form.Get("description"),
			Author:      form.Get("author"),
			Homepage:    form.Get("homepage"),
		}

		claimErr := deps.Claimer.ClaimID(ctx, claim, p.AccountID)
		if claimErr == nil {
			// The prefix of an audit trail rather than a celebration: an id is permanent, so a
			// claim is the one action on this page nobody can undo.
			slog.InfoContext(ctx, "plugin id claimed",
				"account_id", p.AccountID, "plugin_id", id.String())
		}
		return redirectTo(PathAccountPage, claimMessage(ctx, claimErr)), nil
	})
}

type claimFormInput struct {
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

// claimMessage maps a claim failure onto a message code.
//
// A CODE, looked up in a fixed table, and never the error's own sentence: ownership.ErrBadListing
// carries the field that was wrong, which is a fact about what the caller submitted, and prose in
// a redirect is prose somebody can put in a link. The page says what a name and a homepage have to
// be; it does not repeat what was typed.
func claimMessage(ctx context.Context, err error) string {
	switch {
	case err == nil:
		return msgPluginClaimed
	case errors.Is(err, ownership.ErrAlreadyClaimed):
		return msgPluginIDTaken
	case errors.Is(err, core.ErrInvalidPluginID):
		return msgPluginIDInvalid
	case errors.Is(err, ownership.ErrBadListing):
		return msgPluginDetailsInvalid
	default:
		slog.ErrorContext(ctx, "claim a plugin id", "error", err)
		return msgPluginClaimFailed
	}
}

// maxFormBytes caps a form post. Every field on these pages is a handle, a name, a plugin id or a
// scope; 16 KiB is far above any of them and far below anything that could hurt.
const maxFormBytes int64 = 16 * 1024

// parseForm decodes an urlencoded body.
//
// A body that does not parse is treated as an empty form rather than an error, and the CSRF check
// then refuses it — one refusal path instead of two, and the one that does not tell a prober
// whether their body was well-formed.
func parseForm(raw []byte) url.Values {
	values, err := url.ParseQuery(string(raw))
	if err != nil {
		return url.Values{}
	}
	return values
}

// requirePrincipal reads the principal the middleware resolved.
//
// Unreachable on a floor operation — the middleware answers 401 before the handler runs — so this
// is the belt to that braces. A handler that assumed and got a zero principal would render
// somebody's account page as the empty account.
func requirePrincipal(ctx context.Context) (auth.Principal, error) {
	p, ok := PrincipalFrom(ctx)
	if !ok || p.AccountID == "" {
		return auth.Principal{}, NewProblem(http.StatusUnauthorized, CodeUnauthorized,
			"sign in to see this page")
	}
	return p, nil
}

// requireFormPrincipal is requirePrincipal plus the CSRF check.
//
// EVERY mutating form goes through it. A session cookie plus a form post is the classic hole, and
// the cookie's SameSite=Lax is a browser behaviour this repository neither controls nor can test —
// so the token is the half that is ours. It is checked before anything is read from the form,
// because a handler that validates input first is a handler that has already done work on behalf
// of a request it is about to refuse.
func requireFormPrincipal(ctx context.Context, deps WebDeps, presented string) (auth.Principal, error) {
	p, err := requirePrincipal(ctx)
	if err != nil {
		return auth.Principal{}, err
	}
	if !deps.Sessions.CheckCSRF(p, presented) {
		slog.WarnContext(ctx, "form token did not match the session", "account_id", p.AccountID)
		return auth.Principal{}, NewProblem(http.StatusForbidden, CodeForbidden,
			"this form did not come from this session; reload the page and try again")
	}
	return p, nil
}

func accountData(ctx context.Context, deps WebDeps, p auth.Principal) (pageData, error) {
	plugins, err := deps.Ownership.Mine(ctx, p.AccountID)
	if err != nil {
		slog.ErrorContext(ctx, "list plugins", "account_id", p.AccountID, "error", err)
		return pageData{}, NewProblem(http.StatusInternalServerError, CodeInternalError,
			"your account could not be loaded")
	}
	tokens, err := deps.Tokens.List(ctx, p.AccountID)
	if err != nil {
		slog.ErrorContext(ctx, "list tokens", "account_id", p.AccountID, "error", err)
		return pageData{}, NewProblem(http.StatusInternalServerError, CodeInternalError,
			"your account could not be loaded")
	}

	// The mint form's checkboxes come from the catalogue, so a scope added there appears here
	// without anybody remembering to add it — and one removed cannot be offered.
	options := make([]scopeOption, 0, len(authz.Scopes()))
	for _, s := range authz.Scopes() {
		summary := ""
		for _, e := range authz.Catalogue() {
			for _, es := range e.Scopes {
				if es == s && summary == "" {
					summary = e.Summary
				}
			}
		}
		options = append(options, scopeOption{Name: s.String(), Summary: summary})
	}

	return pageData{
		Title:     "Your account",
		Account:   &p,
		CSRFField: auth.CSRFFieldName,
		CSRFToken: deps.Sessions.CSRFToken(p),
		Plugins:   plugins,
		Tokens:    tokens,
		Scopes:    options,
		CanClaim:  deps.Claimer != nil,
		// Whether to OFFER the queue, not whether it may be reached. Asked per request rather than
		// resolved at sign-in, like every other reviewer check: an operator who adds a handle and
		// redeploys should not need everybody to sign in again.
		IsReviewer:  isReviewer(ctx, deps, p),
		NoReviewers: noReviewers(deps),
	}, nil
}

// noReviewers reports whether this deployment has named anybody who may moderate.
//
// A nil check is FALSE — the account surface is registered only when the reviewer check is wired
// (see registerWeb), so nil here is a build that cannot answer rather than one with an empty list,
// and announcing a fault we cannot see would be the confident mistake pointing the other way.
func noReviewers(deps WebDeps) bool {
	return deps.Reviewers != nil && !deps.Reviewers.Configured()
}

// isReviewer answers whether to show the queue link, and never opens a door.
//
// An error is FALSE and is logged. That direction is the only safe one — "we could not check" must
// never resolve to "yes" — and the cost of being wrong is a missing link on a page, not a
// permission: every review route asks the same question again in the middleware before a handler
// runs.
func isReviewer(ctx context.Context, deps WebDeps, p auth.Principal) bool {
	if deps.Reviewers == nil {
		return false
	}
	ok, err := deps.Reviewers.IsReviewer(ctx, p.AccountID)
	if err != nil {
		slog.ErrorContext(ctx, "check whether to offer the review queue",
			"account_id", p.AccountID, "error", err)
		return false
	}
	return ok
}

func pluginData(ctx context.Context, deps WebDeps, p auth.Principal, rawID string) (pageData, error) {
	id, err := core.ParsePluginID(rawID)
	if err != nil {
		return pageData{}, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
	}

	owners, err := deps.Ownership.Owners(ctx, id.String(), p.AccountID)
	switch {
	case errors.Is(err, ownership.ErrNotAnOwner):
		// Not yours and does not exist are the same answer, so a signed-in account cannot
		// enumerate plugin ids by watching which give a 403.
		return pageData{}, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
	case err != nil:
		slog.ErrorContext(ctx, "list owners", "plugin_id", id.String(), "error", err)
		return pageData{}, NewProblem(http.StatusInternalServerError, CodeInternalError,
			"the plugin could not be loaded")
	}

	mine, err := deps.Ownership.Mine(ctx, p.AccountID)
	if err != nil {
		return pageData{}, NewProblem(http.StatusInternalServerError, CodeInternalError,
			"the plugin could not be loaded")
	}
	var current *ownership.Plugin
	for i := range mine {
		if mine[i].ID == id.String() {
			current = &mine[i]
		}
	}
	if current == nil {
		return pageData{}, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
	}

	role, held, err := deps.Ownership.RoleOf(ctx, id.String(), p.AccountID)
	if err != nil {
		slog.ErrorContext(ctx, "read the role", "plugin_id", id.String(), "error", err)
		return pageData{}, NewProblem(http.StatusInternalServerError, CodeInternalError,
			"the plugin could not be loaded")
	}

	return pageData{
		Title:           current.ID,
		Account:         &p,
		CSRFField:       auth.CSRFFieldName,
		CSRFToken:       deps.Sessions.CSRFToken(p),
		Plugin:          current,
		Owners:          owners,
		CanManageOwners: held && role.CanManageOwners(),
	}, nil
}

// mintProblem turns a mint failure into a sentence for the page. It never includes the caller's
// input: a page that echoes what was submitted is a page that renders what was submitted.
func mintProblem(ctx context.Context, err error) string {
	switch {
	case errors.Is(err, auth.ErrNoScopes):
		return "Choose at least one scope. A token with none can do nothing."
	case errors.Is(err, auth.ErrUnknownScope):
		return "That is not a scope this registry issues."
	default:
		slog.ErrorContext(ctx, "mint a token", "error", err)
		return "The token could not be minted."
	}
}

// The message codes a redirect may carry.
//
// A CODE and never a sentence. Prose in a query string is prose an attacker chooses: a crafted
// link would render their words inside our page, under our domain — escaped, and still saying what
// they wrote. Looking a code up in a fixed table means a value nobody here wrote renders nothing
// at all.
const (
	msgTokenRevoked    = "token_revoked"
	msgTokenNotRevoked = "token_not_revoked"
	msgOwnersUpdated   = "owners_updated"
	msgOwnerUnknown    = "owner_unknown"
	msgOwnerDuplicate  = "owner_duplicate"
	msgOwnerLast       = "owner_last"
	msgOwnerDisabled   = "owner_disabled"
	msgOwnerFailed     = "owner_failed"

	// A maintainer holds the plugin and may publish to it. Changing who holds it is an owner's
	// business, and saying so plainly is better than a generic refusal that reads as a bug.
	msgOwnerRoleTooNarrow = "owner_role_too_narrow"

	// Claiming an id. Each outcome is told apart because the actions they call for are different:
	// a taken id needs a different id, a malformed one needs a correction, and a rejected listing
	// needs a name or a homepage fixed.
	msgPluginClaimed        = "plugin_claimed"
	msgPluginIDTaken        = "plugin_id_taken"
	msgPluginIDInvalid      = "plugin_id_invalid"
	msgPluginDetailsInvalid = "plugin_details_invalid"
	msgPluginClaimFailed    = "plugin_claim_failed"

	// The review surface. Each is a distinct outcome a reviewer needs told apart — in particular
	// "re-verified" and "still could not be fetched", which a single "done" would collapse into
	// the confident mistake this whole service is designed against.
	msgReleaseDecided         = "release_decided"
	msgReleaseStillUnverified = "release_still_unverified"
	msgReleaseNotPending      = "release_not_pending"
	msgReleaseNotVerified     = "release_not_verified"
	msgReleaseAlreadyVerified = "release_already_verified"
	msgReleaseNoReason        = "release_no_reason"
	msgReleaseFailed          = "release_failed"
)

// messages maps each code onto the sentence a page shows, and whether it is good news.
var messages = map[string]struct {
	text    string
	problem bool
}{
	msgTokenRevoked:    {text: "Token revoked."},
	msgTokenNotRevoked: {text: "That token could not be revoked.", problem: true},
	msgOwnersUpdated:   {text: "Owners updated."},
	msgOwnerUnknown: {
		text:    "Nobody has signed in here with that handle yet. Ask them to sign in once first.",
		problem: true,
	},
	msgOwnerDuplicate: {text: "They already hold this plugin.", problem: true},
	msgOwnerLast: {
		text:    "A plugin cannot be left with no owners. Add somebody else first.",
		problem: true,
	},
	msgOwnerDisabled: {text: "That account is disabled.", problem: true},
	msgOwnerFailed:   {text: "That change could not be made.", problem: true},
	msgOwnerRoleTooNarrow: {
		text:    "You hold this plugin as a maintainer. Only an owner can change who holds it.",
		problem: true,
	},

	msgPluginClaimed: {
		text: "That id is yours, permanently. It is not listed yet: publish a release to it, and " +
			"the first release of a new id always goes to human review. Mint a token pinned to " +
			"it below and your pipeline can publish.",
	},
	msgPluginIDTaken: {
		// It says nothing about WHO holds it. The list of listed ids is public; which account
		// holds an unlisted one is not, and answering that would make this form a way to map ids
		// to people.
		text: "That plugin id is already claimed. Ids are first-come and permanent, so nobody " +
			"can release one — pick another.",
		problem: true,
	},
	msgPluginIDInvalid: {
		text: "A plugin id starts with a lowercase letter and is 2 to 40 characters of lowercase " +
			"letters, digits, hyphens and underscores. Use the id your plugin's manifest declares.",
		problem: true,
	},
	msgPluginDetailsInvalid: {
		text: "Those details cannot be stored. A name is required, a homepage must be an " +
			"ordinary https URL, and none of the fields may carry control characters — every one " +
			"of them is rendered inside a desktop application.",
		problem: true,
	},
	msgPluginClaimFailed: {text: "That id could not be claimed.", problem: true},

	msgReleaseDecided: {text: "Recorded. The audit trail below says what happened and when."},
	msgReleaseStillUnverified: {
		text: "The artifact still could not be fetched, so its bytes are still unchecked. The " +
			"release is unchanged and the reason is on it; the attempt is in the audit trail.",
		problem: true,
	},
	msgReleaseNotPending: {
		text: "That release is no longer waiting: somebody else decided it while this page was " +
			"open. Reload to see what they did.",
		problem: true,
	},
	msgReleaseNotVerified: {
		text: "That release cannot be approved: this server never managed to fetch and hash its " +
			"artifact, so there is no verified hash to publish. Re-verify it, or reject it.",
		problem: true,
	},
	msgReleaseAlreadyVerified: {
		text: "That release already carries a hash this server computed. Re-verification can only " +
			"fill in a blank, never replace a hash clients may already have seen.",
		problem: true,
	},
	msgReleaseNoReason: {
		text: "A rejection must say why. The author cannot see this queue and has no other way to " +
			"learn what to fix.",
		problem: true,
	},
	msgReleaseFailed: {text: "That could not be recorded.", problem: true},
}

// messageFor returns (notice, problem) for a code. An unknown code renders nothing.
func messageFor(code string) (string, string) {
	m, ok := messages[code]
	switch {
	case !ok:
		return "", ""
	case m.problem:
		return "", m.text
	default:
		return m.text, ""
	}
}

// ownerMessage maps an ownership failure onto a code.
func ownerMessage(ctx context.Context, err error) string {
	switch {
	case err == nil:
		return msgOwnersUpdated
	case errors.Is(err, ownership.ErrNoSuchAccount):
		return msgOwnerUnknown
	case errors.Is(err, ownership.ErrAlreadyAnOwner):
		return msgOwnerDuplicate
	case errors.Is(err, ownership.ErrLastOwner):
		return msgOwnerLast
	case errors.Is(err, ownership.ErrAccountDisabled):
		return msgOwnerDisabled
	case errors.Is(err, ownership.ErrRoleCannotManageOwners):
		return msgOwnerRoleTooNarrow
	default:
		slog.ErrorContext(ctx, "change plugin owners", "error", err)
		return msgOwnerFailed
	}
}

// redirectTo is post/redirect/get: a browser refresh re-issues the GET rather than the POST.
//
// The only thing it carries is a message code, which is why the destination can be assembled by
// concatenation without an escaping question — the codes are constants in this file.
func redirectTo(path, code string) *redirectOutput {
	to := path
	if code != "" {
		to += "?msg=" + code
	}
	return &redirectOutput{Status: http.StatusSeeOther, Location: to}
}

// renderPage executes a template into bytes.
//
// Into a buffer first, then to the response: a template that fails halfway through would otherwise
// have already written a partial page with a 200 on it, and a truncated HTML document renders as
// something that looks like it worked.
func renderPage(ctx context.Context, name string, data pageData) (*htmlOutput, error) {
	tmpl, err := pages.Clone()
	if err != nil {
		slog.ErrorContext(ctx, "clone the templates", "error", err)
		return nil, NewProblem(http.StatusInternalServerError, CodeInternalError, "")
	}
	// The page defines "content"; the layout is what is executed. Cloning per request is what lets
	// two pages define the same block name without one of them winning globally.
	if _, err := tmpl.ParseFS(webFiles, "webtmpl/"+name); err != nil {
		slog.ErrorContext(ctx, "parse a page template", "page", name, "error", err)
		return nil, NewProblem(http.StatusInternalServerError, CodeInternalError, "")
	}

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "layout", data); err != nil {
		slog.ErrorContext(ctx, "render a page", "page", name, "error", err)
		return nil, NewProblem(http.StatusInternalServerError, CodeInternalError, "")
	}

	return &htmlOutput{
		Status:      http.StatusOK,
		ContentType: contentTypeHTML,
		// A page that depends on who is signed in must never be held by a shared cache. `private`
		// is the part that matters; `no-store` is what keeps it out of a browser's back-forward
		// cache after a sign-out.
		CacheControl: "private, no-store",
		Body:         buf.Bytes(),
	}, nil
}

// htmlResponses describes the 200 these pages answer with. Written out rather than reflected,
// because the output body is []byte and Huma would describe it as a base64 string.
func htmlResponses() map[string]*huma.Response {
	return map[string]*huma.Response{
		"200": {
			Description: "An HTML page for a browser. Not part of the machine API; the shape is " +
				"not a contract and may change with the design.",
			Content: map[string]*huma.MediaType{
				contentTypeHTML: {Schema: &huma.Schema{Type: "string"}},
			},
		},
	}
}
