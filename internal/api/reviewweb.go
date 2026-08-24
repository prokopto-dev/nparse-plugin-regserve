package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
)

// The review surface: the pages a reviewer works the queue from.
//
// The API side of moderation has existed since Phase 3 and nobody could reach it, which is the
// same hole the account surface filled in Phase 2 and for the same reason. Reviewing is
// capability-floor (canonical §5) — no personal access token may perform it, however scoped — so
// it is session-only, so it is browser-only, so without pages there is a queue that only a curl
// user with a session cookie can work.
//
// EVERY OPERATION HERE IS `Floor("release.review").Reviewer()`, the same declaration the JSON API
// carries, enforced by the same middleware reading the same value. Two things are true at once and
// both are needed: the floor says no token may moderate, and Reviewer says not every session may
// either. There is deliberately no row and no endpoint that grants moderation — reviewers are
// named in REGSERVE_REVIEWERS, so the authority comes from control of the deployment, exactly as
// it came from control of the repository when this was a merge button. internal/review argues the
// alternatives.
//
// These pages show a release's audit trail verbatim. That is safe by invariant rather than by
// inspection: `audit_log.detail` never carries a secret, which is what makes the table
// redaction-proof — and the trail is the only place the quarantine reasons and a mismatched
// submitted hash survive, because ADR-0008 discards the submitted value after comparing it.
const (
	PathReviewQueue   = "/review"
	PathReviewRelease = "/review/releases/{id}"
	PathReviewDecide  = "/review/releases/{id}/decide"
)

// tagReviewPages groups the moderation pages in the document, away from the JSON API's `review`
// tag: an SDK generated from this document should not grow methods that return HTML.
const tagReviewPages = "review-pages"

// reviewAccess is the one declaration these pages share. Built once so a page cannot be added with
// a slightly different one — the difference that matters here is a missing `.Reviewer()`, which
// would open moderation to every signed-in account.
func reviewAccess() Access { return Floor("release.review").Reviewer() }

type reviewReleaseInput struct {
	ID      string `path:"id" doc:"The release's id, from the queue."`
	Message string `query:"msg"`
}

type reviewDecideInput struct {
	ID      string `path:"id"`
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

func registerReviewPages(api huma.API, deps WebDeps) {
	register(api, reviewAccess(), huma.Operation{
		OperationID: "getReviewQueuePage",
		Method:      http.MethodGet,
		Path:        PathReviewQueue,
		Summary:     "The review queue",
		Description: "An HTML page listing every release waiting for a human, oldest first, at " +
			"most one per plugin. " +
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

		waiting, err := deps.Queue.List(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "read the review queue for the page", "error", err)
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError,
				"the review queue could not be read")
		}

		data := reviewPageData(deps, p, "The review queue")
		data.Queue = waiting
		data.QueueTrust = queueTrust(ctx, deps, waiting)
		data.Notice, data.Problem = messageFor(in.Message)
		return renderPage(ctx, "review.html", data)
	})

	register(api, reviewAccess(), huma.Operation{
		OperationID: "getReviewReleasePage",
		Method:      http.MethodGet,
		Path:        PathReviewRelease,
		Summary:     "One release, and why it is waiting",
		Description: "An HTML page showing a release, every quarantine rule that fired when it " +
			"was submitted, the hash THIS SERVER computed, the hash the submitter claimed when " +
			"the two disagree, and the release's audit trail.\n\n" +
			"It answers for a release in any state, not only a waiting one: a reviewer who has " +
			"just decided something is sent back here to see what they did.",
		Tags: []string{tagReviewPages},
		Errors: []int{
			http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
			http.StatusInternalServerError,
		},
		Responses: htmlResponses(),
	}, func(ctx context.Context, in *reviewReleaseInput) (*htmlOutput, error) {
		p, err := requirePrincipal(ctx)
		if err != nil {
			return nil, err
		}

		detail, err := reviewDetail(ctx, deps, in.ID)
		if err != nil {
			return nil, err
		}

		data := reviewPageData(deps, p, detail.PluginID+" "+detail.Version)
		data.Release = &detail
		data.SubmitterTrust = trustOf(ctx, deps, detail.SubmittedBy)
		data.Notice, data.Problem = messageFor(in.Message)
		return renderPage(ctx, "release.html", data)
	})

	register(api, reviewAccess(), huma.Operation{
		OperationID:  "decideReleaseFromTheReviewPage",
		MaxBodyBytes: maxFormBytes,
		Method:       http.MethodPost,
		Path:         PathReviewDecide,
		Summary:      "Approve, reject or re-verify a release",
		Description: "An HTML form post. `action` is `approve`, `reject` or `reverify`.\n\n" +
			"A rejection requires a reason: the author cannot see this queue and has no other " +
			"way to learn what to fix. Re-verification can only ever FILL IN A BLANK — a release " +
			"that already carries a hash is refused, because a path that could recompute one " +
			"could swap the bytes behind a listing without anybody reviewing the swap.",
		Tags: []string{tagReviewPages},
		Errors: []int{
			http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
			http.StatusNotFound, http.StatusInternalServerError,
		},
		Responses: redirectResponses("The release's review page."),
	}, func(ctx context.Context, in *reviewDecideInput) (*redirectOutput, error) {
		form := parseForm(in.RawBody)
		p, err := requireFormPrincipal(ctx, deps, form.Get(auth.CSRFFieldName))
		if err != nil {
			return nil, err
		}

		// The id is parsed before it is used in a redirect target. It arrives from a URL, and a
		// Location header assembled from unvalidated input is a header somebody else gets to
		// write; net/http would refuse the worst of it, and "the framework would probably catch
		// that" is not a reason to hand it the chance.
		id, err := core.ParseULID(in.ID)
		if err != nil {
			return nil, NewProblem(http.StatusNotFound, CodeNotFound, "no such release")
		}

		var opErr error
		switch form.Get("action") {
		case "approve":
			_, opErr = deps.Queue.Approve(ctx, id.String(), p.AccountID, form.Get("note"))
		case "reject":
			_, opErr = deps.Queue.Reject(ctx, id.String(), p.AccountID, form.Get("note"))
		case "reverify":
			var got review.Verification
			got, opErr = deps.Queue.Reverify(ctx, id.String(), p.AccountID)
			if opErr == nil && !got.Verified {
				// NOT a success, and not an error either. The artifact still could not be
				// fetched, the release is still pending, and the reason is on the row — so the
				// page says so rather than showing "re-verified" over a release that was not.
				return redirectTo(reviewReleasePath(id), msgReleaseStillUnverified), nil
			}
		default:
			return nil, NewProblem(http.StatusBadRequest, CodeInvalidRequest,
				"that is not something this form does")
		}

		if errors.Is(opErr, review.ErrNoSuchRelease) {
			return nil, NewProblem(http.StatusNotFound, CodeNotFound, "no such release")
		}
		return redirectTo(reviewReleasePath(id), decisionMessage(ctx, opErr)), nil
	})
}

// reviewReleasePath is the one place the release page's URL is assembled, so the route constant
// and the redirects cannot drift into two spellings of the same path.
func reviewReleasePath(id core.ULID) string { return "/review/releases/" + id.String() }

// reviewDetail reads one release, mapping a miss onto a 404.
func reviewDetail(ctx context.Context, deps WebDeps, rawID string) (review.Detail, error) {
	id, err := core.ParseULID(rawID)
	if err != nil {
		// An id that is not an id and an id that names nothing are the same answer. Anything else
		// would tell a caller which ULIDs are well-formed, which is not a secret and is also not a
		// distinction worth two code paths.
		return review.Detail{}, NewProblem(http.StatusNotFound, CodeNotFound, "no such release")
	}

	detail, err := deps.Queue.Detail(ctx, id.String())
	switch {
	case errors.Is(err, review.ErrNoSuchRelease):
		return review.Detail{}, NewProblem(http.StatusNotFound, CodeNotFound, "no such release")
	case err != nil:
		slog.ErrorContext(ctx, "read a release for review", "release_id", id.String(), "error", err)
		return review.Detail{}, NewProblem(http.StatusInternalServerError, CodeInternalError,
			"that release could not be read")
	}
	return detail, nil
}

// reviewPageData is the page header these pages share.
//
// IsReviewer is true by construction: the middleware refused everybody else before the handler
// ran. It is set so the layout can offer the queue link on every page a reviewer sees, including
// this one.
func reviewPageData(deps WebDeps, p auth.Principal, title string) pageData {
	return pageData{
		Title:      title,
		Account:    &p,
		CSRFField:  auth.CSRFFieldName,
		CSRFToken:  deps.Sessions.CSRFToken(p),
		IsReviewer: true,
		// The form is offered only where the route it posts to is registered. Both read
		// deps.Trust, so the control and the route cannot disagree — see registerWeb.
		CanSetTrust: deps.Trust != nil,
	}
}

// trustOf reads an account's tier for a page.
//
// A TIER THAT CANNOT BE READ IS EMPTY, and the pages render that as "unknown" or as nothing at
// all rather than as "new". Those are different statements and the difference is the whole point:
// `new` is a real tier meaning everything this account publishes goes to review, and printing it
// because a query failed would be this repository's stated failure mode -- a confident mistake --
// on the one field that decides whether publishing is automated.
func trustOf(ctx context.Context, deps WebDeps, accountID string) string {
	if deps.Trust == nil || accountID == "" {
		return ""
	}
	level, err := deps.Trust.TrustOf(ctx, accountID)
	if err != nil {
		slog.ErrorContext(ctx, "read a trust level for a review page",
			"account_id", accountID, "error", err)
		return ""
	}
	return level.String()
}

// queueTrust reads the tier of each DISTINCT submitter in the queue.
//
// It is on the queue and not only on the release page because the pattern is what a reviewer needs
// to see: five plugins waiting from one account, all of them clean version bumps, is not five
// decisions -- it is one, and it is about the account.
func queueTrust(ctx context.Context, deps WebDeps, waiting []review.Waiting) map[string]string {
	if deps.Trust == nil {
		return nil
	}
	tiers := make(map[string]string, len(waiting))
	for _, w := range waiting {
		if w.SubmittedBy == "" {
			continue
		}
		if _, seen := tiers[w.SubmittedBy]; seen {
			continue
		}
		tiers[w.SubmittedBy] = trustOf(ctx, deps, w.SubmittedBy)
	}
	return tiers
}

// decisionMessage maps a queue failure onto a message code.
//
// Every branch names a real outcome. The default is the only one that hides anything, and it logs
// what it hid: a reviewer told "that could not be done" with nothing in the log is a reviewer who
// cannot escalate.
func decisionMessage(ctx context.Context, err error) string {
	switch {
	case err == nil:
		return msgReleaseDecided
	case errors.Is(err, review.ErrNotPending):
		return msgReleaseNotPending
	case errors.Is(err, review.ErrNotVerified):
		return msgReleaseNotVerified
	case errors.Is(err, review.ErrAlreadyVerified):
		return msgReleaseAlreadyVerified
	case errors.Is(err, review.ErrNoReason):
		return msgReleaseNoReason
	default:
		slog.ErrorContext(ctx, "decide a release from the review page", "error", err)
		return msgReleaseFailed
	}
}
