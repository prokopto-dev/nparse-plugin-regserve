package api

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
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
	PathHome           = "/"
	PathAccountPage    = "/account"
	PathMintToken      = "/account/tokens"
	PathRevokeToken    = "/account/tokens/{id}/revoke"
	PathPluginSettings = "/plugins/{id}/settings"
	PathPluginOwners   = "/plugins/{id}/owners"
)

// tagAccount groups the browser pages in the document, away from the API operations.
const tagAccount = "account"

// contentTypeHTML is written explicitly. With no Content-Type at all net/http sniffs the body, and
// a page that begins with a comment can be sniffed as text/plain.
const contentTypeHTML = "text/html; charset=utf-8"

//go:embed webtmpl/*.html
var webFiles embed.FS

// pages is parsed once, at package init, because a template that fails to parse should take the
// build's tests down rather than the first request that reaches it.
//
// html/template, NOT text/template: it escapes by contextual position — inside an attribute, a URL,
// a script — and that is what makes a plugin id or a display name coming from a provider safe to
// render. Nothing here reaches for template.HTML to make something render; if a value needs it,
// the answer is that the value is wrong.
var pages = template.Must(template.ParseFS(webFiles, "webtmpl/*.html"))

// WebDeps is what the account surface needs. Consumer-declared, like every other dependency in
// this package.
type WebDeps struct {
	Sessions  SessionIssuer
	Tokens    TokenService
	Ownership OwnershipService
	Providers *identity.Registry
}

// OwnershipService is the part of internal/ownership the pages use.
type OwnershipService interface {
	Mine(ctx context.Context, accountID string) ([]ownership.Plugin, error)
	Owners(ctx context.Context, pluginID, callerID string) ([]ownership.Owner, error)
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
	registerHomePage(api, deps)
	registerAccountPage(api, deps)
	registerTokenForms(api, deps)
	registerPluginPages(api, deps)
}

func registerHomePage(api huma.API, deps WebDeps) {
	register(api, Public(), huma.Operation{
		OperationID: "getHomePage",
		Method:      http.MethodGet,
		Path:        PathHome,
		Summary:     "The sign-in page",
		Description: "An HTML page. Anonymous visitors see a sign-in link; a signed-in one is " +
			"pointed at their account.",
		Tags:      []string{tagAccount},
		Responses: htmlResponses(),
	}, func(ctx context.Context, _ *struct{}) (*htmlOutput, error) {
		data := pageData{Title: "Sign in", Providers: deps.Providers.Kinds()}
		// The home page is PUBLIC, so there may be no principal — and if there is one, it is worth
		// showing, because a signed-in person landing on a sign-in page assumes they are not.
		if p, ok := PrincipalFrom(ctx); ok {
			data.Account = &p
			data.CSRFField, data.CSRFToken = auth.CSRFFieldName, deps.Sessions.CSRFToken(p)
		}
		return renderPage(ctx, "home.html", data)
	})
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
		OperationID: "mintToken",
		Method:      http.MethodPost,
		Path:        PathMintToken,
		Summary:     "Mint a personal access token",
		Description: "An HTML form post. The secret is shown exactly once and is never " +
			"recoverable afterwards: what is stored is a keyed hash of it.",
		Tags:      []string{tagAccount},
		Errors:    []int{http.StatusUnauthorized, http.StatusForbidden},
		Responses: htmlResponses(),
	}, func(ctx context.Context, in *mintTokenInput) (*htmlOutput, error) {
		p, err := requireFormPrincipal(ctx, deps, in.CSRFToken)
		if err != nil {
			return nil, err
		}

		scopes := make([]authz.Scope, 0, len(in.Scopes))
		for _, s := range in.Scopes {
			scopes = append(scopes, authz.Scope(s))
		}

		data, dataErr := accountData(ctx, deps, p)
		if dataErr != nil {
			return nil, dataErr
		}

		minted, err := deps.Tokens.Mint(ctx, auth.MintRequest{
			AccountID: p.AccountID,
			Name:      in.Name,
			Scopes:    scopes,
			PluginID:  in.PluginID,
		})
		if err != nil {
			data.Problem = mintProblem(ctx, err)
			return renderPage(ctx, "account.html", data)
		}
		// The prefix is logged and the secret is not. That is what the public half is for.
		slog.InfoContext(ctx, "token minted",
			"account_id", p.AccountID, "token_prefix", minted.Prefix, "scopes", in.Scopes)

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
			ID: minted.ID, Prefix: minted.Prefix, Name: strings.TrimSpace(in.Name),
			Scopes: scopes, PluginID: in.PluginID,
		}}, data.Tokens...)
		return renderPage(ctx, "account.html", data)
	})

	register(api, Floor("token.revoke"), huma.Operation{
		OperationID: "revokeToken",
		Method:      http.MethodPost,
		Path:        PathRevokeToken,
		Summary:     "Revoke a personal access token",
		Tags:        []string{tagAccount},
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden},
		Responses:   redirectResponses("Your account page."),
	}, func(ctx context.Context, in *revokeTokenInput) (*redirectOutput, error) {
		p, err := requireFormPrincipal(ctx, deps, in.CSRFToken)
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

type mintTokenInput struct {
	RawBody   struct{} `contentType:"application/x-www-form-urlencoded"`
	CSRFToken string   `formData:"csrf_token"`
	Name      string   `formData:"name"`
	PluginID  string   `formData:"plugin_id"`
	Scopes    []string `formData:"scope"`
}

type revokeTokenInput struct {
	ID        string   `path:"id"`
	RawBody   struct{} `contentType:"application/x-www-form-urlencoded"`
	CSRFToken string   `formData:"csrf_token"`
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
		OperationID: "managePluginOwners",
		Method:      http.MethodPost,
		Path:        PathPluginOwners,
		Summary:     "Add or remove a plugin's owners",
		Description: "An HTML form post. A transfer is two steps — add the new owner, let them " +
			"mint their own token, then remove the old one — because a token stops working the " +
			"moment its holder stops being an owner.",
		Tags:      []string{tagAccount},
		Errors:    []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound},
		Responses: redirectResponses("The plugin's settings page."),
	}, func(ctx context.Context, in *ownersInput) (*redirectOutput, error) {
		p, err := requireFormPrincipal(ctx, deps, in.CSRFToken)
		if err != nil {
			return nil, err
		}

		id, err := core.ParsePluginID(in.ID)
		if err != nil {
			return nil, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
		}

		var opErr error
		switch in.Action {
		case "add":
			role := ownership.Role(in.Role)
			if !role.Valid() {
				role = ownership.RoleMaintainer
			}
			opErr = deps.Ownership.Add(ctx, id.String(), p.AccountID, in.Handle, role)
		case "remove":
			opErr = deps.Ownership.Remove(ctx, id.String(), p.AccountID, in.AccountID)
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
	ID        string   `path:"id"`
	RawBody   struct{} `contentType:"application/x-www-form-urlencoded"`
	CSRFToken string   `formData:"csrf_token"`
	Action    string   `formData:"action"`
	Handle    string   `formData:"handle"`
	Role      string   `formData:"role"`
	AccountID string   `formData:"account_id"`
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
	}, nil
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

	return pageData{
		Title:     current.ID,
		Account:   &p,
		CSRFField: auth.CSRFFieldName,
		CSRFToken: deps.Sessions.CSRFToken(p),
		Plugin:    current,
		Owners:    owners,
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
