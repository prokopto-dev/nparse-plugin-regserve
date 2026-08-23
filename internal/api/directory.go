package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/danielgtaylor/huma/v2"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

// The public plugin directory: what a visitor sees at `/`.
//
// THESE PAGES ARE PUBLIC, and that is the point of them. `/index.json` is unauthenticated — every
// nParse+ install reads it without a credential — so a human-readable view of the same catalogue
// that demanded a sign-in would be a worse-informed version of a document anybody can already
// fetch. Before this, `/` was a sign-in page: the registry's front door asked who you were before
// telling you what it carried.
//
// The search is a GET form. The query is in the querystring, so a result page is a URL somebody
// can paste into an issue and the back button does what it looks like it does; it is rendered on
// the server, so it works with JavaScript disabled, in a terminal browser, and in whatever a
// screen reader does with a page that has no client-side state at all. There is no JavaScript
// here, because there is nothing here JavaScript would do.
const (
	// PathPluginListing is a plugin's public page. It sits beside the machine-readable
	// /plugins/{id}/index.json rather than under /api/v1, for the reason ADR-0009 gives about the
	// index: a URL a human pastes into a chat window should not carry an API version it does not
	// mean, and should not move when one changes.
	PathPluginListing = "/plugins/{id}"

	// PathPublish is the author on-ramp: how somebody who wants to WRITE a plugin gets from the
	// template repository to a listing. It is public and deliberately not under /account — a
	// visitor with no account is exactly the reader it is for, and a page that asked them to sign
	// in before telling them what signing in would be for is a page that answers the question
	// after they have stopped asking it.
	PathPublish = "/publish"

	// tagDirectory groups the public pages in the OpenAPI document, away from both the account
	// surface and the machine API.
	tagDirectory = "directory"
)

// maxQueryRunes caps the search text.
//
// A cap is not optional on a field that reaches a database: without one, the length of the string
// scanned against every row of the catalogue is chosen by whoever sends the request. 128 is far
// longer than any plugin name, id or author, and far shorter than anything that could hurt. A
// longer query is TRUNCATED rather than refused, and the page says so — a search box that answers
// "400 Bad Request" to a pasted paragraph is a search box that looks broken.
const maxQueryRunes = 128

// Directory is what the public pages read.
//
// It is the Catalogue plus a search, declared as one interface because the two are the same
// question asked twice — "what is publicly visible" — and a build that could answer one and not
// the other would be a build whose directory and index disagree.
type Directory interface {
	Catalogue

	// Browse returns the listings matching query, and the counts of what is NOT in them. An empty
	// query means everything.
	//
	// The counts are part of the answer rather than a second call because they are what stops a
	// filtered page from being a silent one: a row this service declines to show has to be
	// countable somewhere the visitor can see it.
	Browse(ctx context.Context, query string) (Browsed, error)
}

// Browsed is one directory query's answer: the rows to show, and an honest account of the rows
// that are not there.
type Browsed struct {
	// Plugins are the listings that matched, in the same order the index uses.
	Plugins []registry.Plugin

	// Listed is every publicly listed plugin, before the query filtered anything, so a search can
	// say "3 of 12" rather than "3".
	Listed int

	// Awaiting is claimed ids with no approved release behind them. They are not in the index
	// either, and a visitor comparing the two should not have to guess why the numbers differ.
	Awaiting int

	// Delisted is ids whose listing has been removed. The id stays claimed forever and is never
	// recycled, so this number only goes up, and saying it out loud is the difference between a
	// registry that lost a plugin and one that delisted it.
	Delisted int
}

// DirectoryDeps is what the public pages need. Consumer-declared, like every other dependency in
// this package.
type DirectoryDeps struct {
	Listings Directory

	// Providers decides whether the header offers a sign-in link at all. Nil is an instance with
	// no OAuth application configured, which serves the catalogue perfectly well.
	Providers *identity.Registry

	// Sessions is only used to mint the CSRF token the header's sign-out form carries, for a
	// visitor who is already signed in. Nil means no form is rendered rather than a form that
	// would be refused.
	Sessions SessionIssuer

	// Reviewers decides whether the header offers the review queue. Decoration, never
	// authorisation: every review route asks again in the middleware.
	Reviewers ReviewerCheck

	// AccountPage and ClaimForm say what this build actually serves, so the author on-ramp can
	// only tell a reader to do things that are possible here. They are computed in New from the
	// same conditions the routes are registered on — never inferred from Providers, which says
	// only that somebody can sign in and nothing about what they will find.
	AccountPage bool
	ClaimForm   bool

	// IndexURL is the absolute URL of this registry's index, for the "add this registry" line.
	// Empty on an instance that was not told its own public URL, and the page then shows the path
	// rather than inventing a host — a Host header is caller-controlled, and a URL somebody is
	// told to paste into their client is the last place to start trusting one.
	IndexURL string
}

func registerDirectory(api huma.API, deps DirectoryDeps) {
	register(api, Public(), huma.Operation{
		OperationID: "getHomePage",
		Method:      http.MethodGet,
		Path:        PathHome,
		Summary:     "The plugin directory",
		Description: "An HTML page listing every publicly listed plugin, with a server-rendered " +
			"search. Public: this is the human-readable view of the same catalogue " +
			"`GET /index.json` serves to every client without a credential.",
		Tags:      []string{tagDirectory},
		Errors:    []int{http.StatusInternalServerError},
		Responses: htmlResponses(),
	}, func(ctx context.Context, in *directoryInput) (*htmlOutput, error) {
		query, truncated := normaliseQuery(in.Query)

		found, err := deps.Listings.Browse(ctx, query)
		if err != nil {
			slog.ErrorContext(ctx, "browse the catalogue", "error", err)
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError,
				"the catalogue could not be read")
		}

		data := directoryData(ctx, deps, "Plugins")
		data.Query = query
		data.Found = &found
		if truncated {
			data.Notice = "That search was longer than this registry matches on, so only the " +
				"first " + strconv.Itoa(maxQueryRunes) + " characters were used."
		}
		return renderPage(ctx, "directory.html", data)
	})

	register(api, Public(), huma.Operation{
		OperationID: "getPluginListingPage",
		Method:      http.MethodGet,
		Path:        PathPluginListing,
		Summary:     "One plugin's public page",
		Description: "An HTML page for a single listing: what it is, who publishes it, its latest " +
			"approved release, and the release notes if there are any. Public, and the same " +
			"answer for a delisted plugin as for one that never existed.",
		Tags:      []string{tagDirectory},
		Errors:    []int{http.StatusNotFound, http.StatusInternalServerError},
		Responses: htmlResponses(),
	}, func(ctx context.Context, in *pluginListingInput) (*htmlOutput, error) {
		id, err := core.ParsePluginID(in.ID)
		if err != nil {
			// A malformed id cannot name a real plugin, and saying WHY it was rejected invites
			// probing for the ids that are merely absent. The same answer as an unknown one.
			return nil, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
		}

		listing, err := deps.Listings.Listing(ctx, id)
		switch {
		case errors.Is(err, ErrListingNotFound):
			return nil, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
		case err != nil:
			slog.ErrorContext(ctx, "load a listing for its page",
				"plugin_id", id.String(), "error", err)
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError,
				"the listing could not be read")
		}

		data := directoryData(ctx, deps, listing.Name)
		data.Listing = &listing
		return renderPage(ctx, "listing.html", data)
	})

	register(api, Public(), huma.Operation{
		OperationID: "getPublishGuidePage",
		Method:      http.MethodGet,
		Path:        PathPublish,
		Summary:     "How to publish a plugin",
		Description: "An HTML page: the path from the plugin template to a listing — claim an id, " +
			"mint a scoped token, store it as a repository secret, tag a release, and the " +
			"reusable workflow publishes. Public, because the reader it is written for does not " +
			"have an account yet.",
		Tags:      []string{tagDirectory},
		Errors:    []int{http.StatusInternalServerError},
		Responses: htmlResponses(),
	}, func(ctx context.Context, _ *struct{}) (*htmlOutput, error) {
		// No catalogue read at all: the page is prose and the header. It is registered alongside
		// the directory rather than on its own condition because an on-ramp on a build that cannot
		// list anything would be an invitation into a registry with no index behind it.
		return renderPage(ctx, "publish.html", directoryData(ctx, deps, "Publish a plugin"))
	})
}

// directoryInput is the search form's submission.
//
// One field, because the form has one field. It arrives in the QUERYSTRING and not in a POST body
// so that the result is a link: a search somebody can bookmark, paste into an issue, or reach
// again with the back button. A POST would answer the same question and produce a page nobody can
// refer to.
type directoryInput struct {
	// The parameter is `q`, spelled here in a struct tag and again in directory.html's `name`
	// attribute. A Go constant cannot be either of those, so the two literals are checked by
	// TestDirectory_Search_IsALinkableGetForm, which submits the one and reads the other.
	//
	// No maxLength tag, deliberately: Huma would answer 422 to an over-long query, and a search
	// box that refuses a pasted paragraph with an error document looks broken. The handler caps it
	// at maxQueryRunes and the page says it did.
	Query string `query:"q" doc:"Match against a plugin's id, name, description and author. Empty lists everything; text beyond 128 characters is ignored rather than refused."`
}

type pluginListingInput struct {
	// No `pattern` tag, for the reason pluginIndexInput gives: Huma would answer 422 naming the
	// pattern, where this answers 404, and a rejection that explains itself is an oracle for which
	// ids exist.
	ID string `path:"id" doc:"The plugin id, as declared in PluginMeta.id"`
}

// normaliseQuery trims and caps the search text, and reports whether it had to cut anything.
//
// Truncation is by RUNE and not by byte, so a cap can never split a multi-byte character and hand
// the database half of one. Case folding is NOT done here: it belongs next to the query that
// depends on it, in internal/plugin, because SQLite's lower() folds ASCII only and the two have to
// agree about that or the search quietly stops matching.
func normaliseQuery(raw string) (query string, truncated bool) {
	query = strings.TrimSpace(raw)
	if utf8.RuneCountInString(query) <= maxQueryRunes {
		return query, false
	}
	return string([]rune(query)[:maxQueryRunes]), true
}

// directoryData builds the parts of a public page that do not depend on which page it is: the
// header's sign-in link, the signed-in visitor's name, and the install URL.
//
// A public page may still be looked at by somebody signed in, and a header that pretended
// otherwise would tell a signed-in reader they were signed out.
func directoryData(ctx context.Context, deps DirectoryDeps, title string) pageData {
	data := pageData{
		Title:          title,
		IndexPath:      PathIndex,
		IndexURL:       deps.IndexURL,
		HasAccountPage: deps.AccountPage,
		CanClaim:       deps.ClaimForm,
	}
	if deps.Providers != nil {
		data.Providers = deps.Providers.Kinds()
	}

	p, ok := PrincipalFrom(ctx)
	if !ok || p.AccountID == "" {
		return data
	}
	data.Account = &p
	if deps.Sessions != nil {
		data.CSRFField, data.CSRFToken = auth.CSRFFieldName, deps.Sessions.CSRFToken(p)
	}
	if deps.Reviewers != nil {
		data.IsReviewer = isReviewer(ctx, WebDeps{Reviewers: deps.Reviewers}, p)
	}
	return data
}
