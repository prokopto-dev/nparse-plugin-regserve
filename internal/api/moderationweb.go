package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
)

// The moderation console: the reviewer surface for things that are not one release.
//
// The queue answers "what is waiting". These answer the two questions a reviewer had no way to
// ask. WHAT DOES THIS REGISTRY CARRY — every plugin, in every state, with its owners and their
// tiers, including the rows the public directory correctly declines to show. And THE TWO
// CAPABILITIES A REVIEWER HELD WITH NO CONTROL FOR THEM: setting an account's trust tier, which
// existed only as a JSON endpoint nobody could reach from a browser, and delisting, which did not
// exist at all.
//
// # Approving and trusting are two acts and stay two acts
//
// The trust control sits NEXT TO approve/reject on a release's page because that is where the
// judgement is made — a reviewer who has just read somebody's submission is the person best placed
// to say whether this registry should stop gating their version bumps. It is a SEPARATE FORM
// posting to a SEPARATE ROUTE, and that separation is load-bearing rather than tidy: an approve
// button that also raised trust would make every approval a decision about the publisher's future
// releases, silently, and trust is never raised as a side effect of anything. ADR-0007 says a
// human decides; this is what "decides" looks like.
//
// The tier a change would replace is shown wherever the change is offered. A control with no
// current value is a reviewer guessing, and the guess they would make is that everybody is `new`.
//
// # Trust is per-account and the pages say so
//
// ADR-0007 puts the tier on the ACCOUNT. It is offered against a submission and against an owner
// row because that is where a reviewer is standing when they form the judgement, never because it
// belongs to the plugin — so both surfaces name the account, show the same tier for the same
// person everywhere they appear, and say in prose that the change reaches all of their plugins. A
// UI that implied per-plugin trust would be the UI being wrong about the model, and the model is
// the part that is not negotiable.
//
// # Why the moderation routes are declared the way they are
//
// The two reads are `Floor("release.review").Reviewer()`, the same declaration the queue carries:
// seeing what a registry holds, including its delisted ids, is part of moderating it. The trust
// form is `Floor("trust.set").Reviewer()`, the same declaration the JSON endpoint carries, because
// it is the same act through a different door. Delisting is `Floor("plugin.moderate").Reviewer()`
// — a permission of its own, and internal/authz's catalogue entry argues why it is not
// `plugin.manage`.
//
// Every one of them is capability-floor, so no token reaches any of it however scoped, and every
// one is reviewer-only, so a signed-in account that is not a configured reviewer is refused. Both
// checks run in the middleware from the declaration itself.
const (
	// PathReviewCatalogue is every plugin, as a moderator sees it.
	//
	// Under /review rather than beside the public /plugins for the same reason the queue is: it is
	// part of the moderation surface, not a variant of the directory, and a path that made it look
	// like one would invite somebody to wonder why it answers 403.
	PathReviewCatalogue = "/review/plugins"

	// PathReviewPlugin is one plugin's moderation page.
	PathReviewPlugin = "/review/plugins/{id}"

	// PathReviewListing is the delist/relist form post. It is named for the thing it changes — the
	// LISTING — because that is precisely what delisting removes and what it leaves behind: the
	// claim, the releases and the owners are untouched, and a path called /delete would describe
	// an operation this service does not have and must never grow.
	PathReviewListing = "/review/plugins/{id}/listing"

	// PathReviewTrust is the browser form that sets an account's trust tier.
	//
	// A SECOND DOOR onto the same act as PUT /api/v1/accounts/{id}/trust, not a replacement for
	// it: both go through the same TrustService and the same Floor("trust.set").Reviewer()
	// declaration. The JSON endpoint is the contract; this is the form. What existed before was
	// only the first — a session-only operation with no session-shaped way to reach it, so the
	// answer to "how do I trust this publisher" was "send the PUT yourself", which is the same
	// dead end the claim form was built to remove.
	PathReviewTrust = "/review/accounts/{id}/trust"
)

// PluginModeration is what the moderation pages need. Consumer-declared, like every other
// dependency in this package.
type PluginModeration interface {
	// List returns every plugin, in every state, with its owners.
	List(ctx context.Context) ([]review.Listing, error)

	// Get returns one, or review.ErrNoSuchPlugin.
	Get(ctx context.Context, pluginID string) (review.Listing, error)

	// Delist removes a listing and keeps the claim. Relist puts it back.
	Delist(ctx context.Context, pluginID, reviewerID, reason string) error
	Relist(ctx context.Context, pluginID, reviewerID, reason string) error
}

type moderationPluginInput struct {
	ID      string `path:"id" doc:"The plugin's id."`
	Message string `query:"msg"`
}

type moderationFormInput struct {
	ID      string `path:"id"`
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

// registerModerationCatalogue wires the pages and the delist/relist form.
//
// Split from registerReviewPages so the dependencies can come apart: a build with a queue and no
// moderation service serves the queue rather than 500ing on a page it cannot render. Same
// principle as every other optional dependency here.
func registerModerationCatalogue(api huma.API, deps WebDeps) {
	register(api, reviewAccess(), huma.Operation{
		OperationID: "getModerationCataloguePage",
		Method:      http.MethodGet,
		Path:        PathReviewCatalogue,
		Summary:     "Every plugin this registry carries",
		Description: "An HTML page listing every plugin in every state — listed, claimed with " +
			"nothing published yet, and delisted — with its owners and the trust tier each of " +
			"them currently holds.\n\n" +
			"It is deliberately NOT the public directory. That page answers \"what is publicly " +
			"visible\" and correctly declines to show a delisted or unpublished id, counting it " +
			"so the shortfall is never silent. The rows it declines to show are the ones " +
			"moderation is about.\n\n" +
			"Session-only and reviewer-only: a personal access token cannot reach it however it " +
			"is scoped, and a signed-in account that is not a configured reviewer is refused.",
		Tags:      []string{tagReviewPages},
		Errors:    []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError},
		Responses: htmlResponses(),
	}, func(ctx context.Context, in *accountInput) (*htmlOutput, error) {
		p, err := requirePrincipal(ctx)
		if err != nil {
			return nil, err
		}

		listings, err := deps.Moderation.List(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "read the catalogue for moderation", "error", err)
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError,
				"the catalogue could not be read")
		}

		data := reviewPageData(deps, p, "Every plugin")
		data.Catalogue = listings
		// No TrustTiers: this page SHOWS each owner's tier and offers no control to change it.
		// The controls live one click away, on the plugin's own page, because a change of tier
		// needs a stated reason and a list of every plugin is the wrong place to be typing one.
		data.Notice, data.Problem = messageFor(in.Message)
		return renderPage(ctx, "catalogue.html", data)
	})

	register(api, reviewAccess(), huma.Operation{
		OperationID: "getModerationPluginPage",
		Method:      http.MethodGet,
		Path:        PathReviewPlugin,
		Summary:     "One plugin, and what a moderator may do to it",
		Description: "An HTML page showing a plugin's listing state, what it currently serves, " +
			"how many of its releases are waiting, and every account that holds it with that " +
			"account's trust tier.\n\n" +
			"It answers for a plugin in any state, including a delisted one: a moderator who has " +
			"just delisted something is sent back here to see what they did, and the id stays " +
			"claimed for ever whatever happens to the listing.",
		Tags: []string{tagReviewPages},
		Errors: []int{
			http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
			http.StatusInternalServerError,
		},
		Responses: htmlResponses(),
	}, func(ctx context.Context, in *moderationPluginInput) (*htmlOutput, error) {
		p, err := requirePrincipal(ctx)
		if err != nil {
			return nil, err
		}

		listing, err := moderationDetail(ctx, deps, in.ID)
		if err != nil {
			return nil, err
		}

		data := reviewPageData(deps, p, listing.ID)
		data.Moderated = &listing
		data.TrustTiers = trustTiers()
		data.Notice, data.Problem = messageFor(in.Message)
		return renderPage(ctx, "moderate.html", data)
	})

	register(api, Floor("plugin.moderate").Reviewer(), huma.Operation{
		OperationID:  "moderatePluginListing",
		MaxBodyBytes: maxFormBytes,
		Method:       http.MethodPost,
		Path:         PathReviewListing,
		Summary:      "Delist or relist a plugin as a moderator",
		Description: "An HTML form post. `action` is `delist` or `relist`, and both require a " +
			"reason.\n\n" +
			"**Delisting removes the listing and keeps the claim.** The plugin row, its releases " +
			"and its owners are untouched; what changes is that the id stops appearing in " +
			"`GET /index.json`. Ids are permanent and NEVER recycled — a delisted id is spoken " +
			"for for ever and by nobody else, because an id that could be handed on is how you " +
			"ship an update to another author's users. There is no operation here that deletes a " +
			"plugin, and a database trigger refuses one.\n\n" +
			"It carries `plugin.moderate` rather than `plugin.manage`: an owner removing their " +
			"own listing and a moderator removing somebody else's are different acts, the " +
			"second cannot be expressed by a permission bounded by ownership (ADR-0005), and the " +
			"audit row records which act it was.\n\n" +
			"A reason is required in BOTH directions. Relisting clears the stored reason, so " +
			"after it runs the append-only audit log is the only record that the plugin was ever " +
			"delisted or why it came back.",
		Tags: []string{tagReviewPages},
		Errors: []int{
			http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
			http.StatusNotFound, http.StatusInternalServerError,
		},
		Responses: redirectResponses("The plugin's moderation page."),
	}, func(ctx context.Context, in *moderationFormInput) (*redirectOutput, error) {
		form := parseForm(in.RawBody)
		p, err := requireFormPrincipal(ctx, deps, form.Get(auth.CSRFFieldName))
		if err != nil {
			return nil, err
		}

		// Parsed before it reaches a redirect target, for the reason the release form parses its
		// id: a Location assembled from unvalidated input is a header somebody else gets to write.
		id, err := core.ParsePluginID(in.ID)
		if err != nil {
			return nil, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
		}

		reason := form.Get("reason")
		var opErr error
		switch form.Get("action") {
		case "delist":
			opErr = deps.Moderation.Delist(ctx, id.String(), p.AccountID, reason)
		case "relist":
			opErr = deps.Moderation.Relist(ctx, id.String(), p.AccountID, reason)
		default:
			return nil, NewProblem(http.StatusBadRequest, CodeInvalidRequest,
				"that is not something this form does")
		}

		if errors.Is(opErr, review.ErrNoSuchPlugin) {
			return nil, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
		}
		return redirectTo(moderationPluginPath(id), moderationMessage(ctx, opErr)), nil
	})
}

// registerTrustForm wires the browser form that sets a trust tier.
//
// IT IS REGISTERED ON `Trust` ALONE, deliberately apart from the catalogue above, because the two
// dependencies come apart in a way a reader would otherwise trip over. The trust control is
// offered on the RELEASE page — which registerReviewPages serves — as well as on the moderation
// console. Folding this registration in with the console would mean a build with a queue and a
// trust service but no moderation service rendered a control on the release page posting to a
// route it does not serve, which is the dead end this whole surface exists to remove.
//
// The templates gate the control on the same fact through pageData.CanSetTrust, so "the page
// offers it" and "the route exists" are one condition rather than two.
func registerTrustForm(api huma.API, deps WebDeps) {
	register(api, Floor("trust.set").Reviewer(), huma.Operation{
		OperationID:  "setAccountTrustFromTheReviewPages",
		MaxBodyBytes: maxFormBytes,
		Method:       http.MethodPost,
		Path:         PathReviewTrust,
		Summary:      "Set an account's trust tier",
		Description: "An HTML form post carrying `level` and a required `note`. The same act as " +
			"`PUT /api/v1/accounts/{id}/trust`, through the same service — this is the door a " +
			"browser can use, and setting trust is capability-floor and therefore " +
			"browser-only.\n\n" +
			"**It is a separate form from approve/reject and always will be.** Approving a " +
			"release and trusting its publisher are two decisions: the first is about these " +
			"bytes, the second is about every version bump that account makes from now on. " +
			"Trust is never raised as a side effect of anything, and never automatically — " +
			"ADR-0007 has no publish counters and no thresholds, because a counter is something " +
			"an attacker can run up.\n\n" +
			"**The tier is a property of the ACCOUNT, not of a plugin.** It applies to every " +
			"plugin that account holds, and there is deliberately no per-plugin trust.\n\n" +
			"`trusted` lets a version bump of an ALREADY-APPROVED plugin publish without a " +
			"human, and only when the artifact was fetched and re-hashed clean and no quarantine " +
			"rule fired. It never lets a NEW plugin id skip review, whatever the tier, and it " +
			"never governs who may moderate — that is `REGSERVE_REVIEWERS` and nothing else.",
		Tags: []string{tagReviewPages},
		Errors: []int{
			http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
			http.StatusNotFound, http.StatusInternalServerError,
		},
		Responses: redirectResponses("Wherever the form was submitted from."),
	}, func(ctx context.Context, in *moderationFormInput) (*redirectOutput, error) {
		form := parseForm(in.RawBody)
		p, err := requireFormPrincipal(ctx, deps, form.Get(auth.CSRFFieldName))
		if err != nil {
			return nil, err
		}

		// The account id is a ULID and is validated as one before anything is done with it. The
		// service would refuse an unknown id anyway; this is what keeps an unparseable one out of
		// the redirect assembled below.
		account, err := core.ParseULID(in.ID)
		if err != nil {
			return nil, NewProblem(http.StatusNotFound, CodeNotFound, "no such account")
		}

		back := returnPath(form.Get("from"), form.Get("from_id"))

		level, err := release.ParseTrust(form.Get("level"))
		if err != nil {
			return redirectTo(back, msgTrustBadLevel), nil
		}

		opErr := deps.Trust.SetTrust(ctx, account.String(), level, p.AccountID, form.Get("note"))
		return redirectTo(back, trustMessage(ctx, opErr)), nil
	})
}

// returnPath decides where a trust form sends the reviewer back to.
//
// THE PATH IS BUILT HERE FROM A VALIDATED ID, NEVER TAKEN FROM THE FORM. The trust control is
// offered on two pages, so the form has to say which one it was on — and the obvious way to do
// that, a hidden field holding the URL, is an open redirect with a hidden field in front of it. So
// the form carries a KIND and an ID instead: the kind selects a code path, the id is parsed into
// the typed value that path expects, and the path is assembled from the result. Nothing the
// browser sent is concatenated into a Location header.
//
// An unrecognised kind, or an id that does not parse, falls back to the catalogue rather than
// failing the request: the trust change has already been made by the time this is read, and
// refusing to redirect would leave a reviewer looking at an error over a change that succeeded.
func returnPath(kind, id string) string {
	switch kind {
	case "release":
		if parsed, err := core.ParseULID(id); err == nil {
			return reviewReleasePath(parsed)
		}
	case "plugin":
		if parsed, err := core.ParsePluginID(id); err == nil {
			return moderationPluginPath(parsed)
		}
	}
	return PathReviewCatalogue
}

// moderationPluginPath is the one place this page's URL is assembled, so the route constant and
// the redirects cannot drift into two spellings of the same path.
func moderationPluginPath(id core.PluginID) string { return "/review/plugins/" + id.String() }

// moderationDetail reads one plugin, mapping a miss onto a 404.
func moderationDetail(ctx context.Context, deps WebDeps, rawID string) (review.Listing, error) {
	id, err := core.ParsePluginID(rawID)
	if err != nil {
		// An id that is not an id and an id that names nothing are the same answer, exactly as
		// they are for a release: anything else tells a caller which ids are well-formed.
		return review.Listing{}, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
	}

	listing, err := deps.Moderation.Get(ctx, id.String())
	switch {
	case errors.Is(err, review.ErrNoSuchPlugin):
		return review.Listing{}, NewProblem(http.StatusNotFound, CodeNotFound, "no such plugin")
	case err != nil:
		slog.ErrorContext(ctx, "read a plugin for moderation", "plugin_id", id.String(), "error", err)
		return review.Listing{}, NewProblem(http.StatusInternalServerError, CodeInternalError,
			"that plugin could not be read")
	}
	return listing, nil
}

// trustOption is one tier the form offers.
type trustOption struct {
	Level string

	// Summary is what choosing it does, in one sentence. It is rendered beside the control because
	// "new" and "trusted" do not say what they mean to somebody who has not read ADR-0007, and a
	// reviewer picking a tier from a bare list is picking a word.
	Summary string
}

// trustTiers is the vocabulary the form offers, built from the constants in internal/release
// rather than typed into a template.
//
// The three values are the ones account_trust's CHECK accepts, and they are ordered least to most
// permissive so that the control reads as a scale rather than as a list — `blocked` is BELOW the
// default and not the absence of one, which is the part that is easy to get wrong.
func trustTiers() []trustOption {
	return []trustOption{
		{
			Level: release.TrustBlocked.String(),
			Summary: "Refuse this account's publishes outright, before the artifact is even " +
				"fetched. An explicit refusal, below the default rather than the absence of one.",
		},
		{
			Level: release.TrustNew.String(),
			Summary: "The default. Everything this account publishes goes to human review. An " +
				"account with no tier set is already here.",
		},
		{
			Level: release.TrustTrusted.String(),
			Summary: "A version bump of an already-approved plugin publishes without a human, " +
				"provided the artifact re-hashes clean and no quarantine rule fires. A NEW " +
				"plugin id still always gets reviewed.",
		},
	}
}

// moderationMessage maps a delist/relist failure onto a message code.
//
// Every branch names a real outcome, and the default is the only one that hides anything — it logs
// what it hid, because a moderator told "that could not be done" with nothing in the log is a
// moderator who cannot escalate.
func moderationMessage(ctx context.Context, err error) string {
	switch {
	case err == nil:
		return msgListingChanged
	case errors.Is(err, review.ErrNoModerationReason):
		return msgModerationNoReason
	case errors.Is(err, review.ErrAlreadyDelisted):
		return msgAlreadyDelisted
	case errors.Is(err, review.ErrNotDelisted):
		return msgNotDelisted
	default:
		slog.ErrorContext(ctx, "moderate a plugin listing", "error", err)
		return msgModerationFailed
	}
}

// trustMessage maps a trust change onto a message code.
func trustMessage(ctx context.Context, err error) string {
	switch {
	case err == nil:
		return msgTrustSet
	case errors.Is(err, release.ErrNoTrustReason):
		return msgTrustNoReason
	case errors.Is(err, release.ErrNoSuchAccount):
		return msgTrustNoAccount
	case errors.Is(err, release.ErrBadTrustLevel):
		return msgTrustBadLevel
	default:
		slog.ErrorContext(ctx, "set a trust level from the review pages", "error", err)
		return msgTrustFailed
	}
}

// trustTarget is one rendering of the trust control: whose tier, what it is now, and where the
// reviewer should land afterwards.
//
// It exists because a template cannot build a value, and the control is offered on two pages about
// two different subjects — the account that SUBMITTED a release, and each account that HOLDS a
// plugin. Both are the same act on the same account, so both render the same template from this
// one shape rather than from two near-identical blocks of markup that would drift the first time
// one of them was edited.
type trustTarget struct {
	// Account is the account id the form posts against. It is a ULID; Name and Handle are what a
	// human recognises, and either may be empty for an account that has never signed in under a
	// provider handle.
	Account string
	Name    string
	Handle  string

	// Trust is the tier the account holds NOW. It is what the control is pre-selected to and what
	// the page states in prose, so a reviewer changing it can see what they are changing from.
	Trust string

	// From and FromID say which page the form was submitted from, as a KIND and an ID rather than
	// as a URL. See returnPath: the path is assembled by the handler from a parsed id, so nothing
	// the browser sent is concatenated into a Location header.
	From   string
	FromID string

	Tiers     []trustOption
	CSRFField string
	CSRFToken string
}

// TrustForSubmitter renders the control for the account that submitted the release on this page.
//
// A zero value when there is no release or no submitter — an imported release has none — and the
// template checks for that rather than offering to change the tier of an account that is not
// there. It is a METHOD on pageData because a template cannot construct a value, and building it
// here keeps the two call sites rendering one definition of the control.
func (d pageData) TrustForSubmitter() trustTarget {
	if d.Release == nil || d.Release.Submitter.AccountID == "" {
		return trustTarget{}
	}
	s := d.Release.Submitter
	return trustTarget{
		Account:   s.AccountID,
		Name:      s.DisplayName,
		Handle:    s.Handle,
		Trust:     s.Trust,
		From:      "release",
		FromID:    d.Release.ReleaseID,
		Tiers:     d.TrustTiers,
		CSRFField: d.CSRFField,
		CSRFToken: d.CSRFToken,
	}
}

// TrustForOwner renders the control for one account holding the plugin on this page.
//
// The tier it shows is the ACCOUNT's, which is why the same person shows the same tier against
// every plugin they hold — and why the control's own prose says the change reaches all of them.
// ADR-0007: there is no per-plugin trust, and a page that let the layout imply otherwise would be
// the page being wrong about the model.
func (d pageData) TrustForOwner(h review.Holder) trustTarget {
	target := trustTarget{
		Account:   h.AccountID,
		Name:      h.DisplayName,
		Handle:    h.Handle,
		Trust:     h.Trust,
		From:      "plugin",
		Tiers:     d.TrustTiers,
		CSRFField: d.CSRFField,
		CSRFToken: d.CSRFToken,
	}
	if d.Moderated != nil {
		target.FromID = d.Moderated.ID
	}
	return target
}
