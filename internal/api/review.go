package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
)

// The review queue's paths. Under the versioned product API: this is our shape and it may version.
//
// They are keyed on the RELEASE id rather than nested under the plugin. A reviewer works from the
// queue and has a release id in front of them; making them supply the plugin too would be asking
// for a fact the server already knows, and a route that took both would have to decide what to do
// when they disagreed.
const (
	PathPendingReleases = "/releases/pending"
	PathApproveRelease  = "/releases/{id}/approve"
	PathRejectRelease   = "/releases/{id}/reject"
	PathReverifyRelease = "/releases/{id}/reverify"
)

// tagReview groups moderation in the OpenAPI document and in the SDKs generated from it.
const tagReview = "review"

// ReviewQueue is what internal/api needs in order to serve moderation.
//
// Detail is used only by the review PAGES and not by the JSON API, and it is on this interface
// rather than on a second one because there is one service behind both surfaces. Two interfaces
// over one object would let a build wire the pages to a different queue from the endpoints, which
// is a shape worth making unrepresentable rather than documenting.
type ReviewQueue interface {
	List(ctx context.Context) ([]review.Waiting, error)
	Detail(ctx context.Context, releaseID string) (review.Detail, error)
	Approve(ctx context.Context, releaseID, reviewerID, note string) (review.Decision, error)
	Reject(ctx context.Context, releaseID, reviewerID, reason string) (review.Decision, error)
	Reverify(ctx context.Context, releaseID, reviewerID string) (review.Verification, error)
}

type pendingReleasesOutput struct {
	Body pendingReleases
}

type pendingReleases struct {
	// Count is rendered even when it equals the length of the list, because a client that pages
	// later should not have to change how it reads the total.
	Count    int              `json:"count" doc:"How many releases are waiting for review."`
	Releases []waitingRelease `json:"releases" doc:"Everything waiting, oldest submission first."`
}

type waitingRelease struct {
	ReleaseID   string `json:"release_id"`
	PluginID    string `json:"plugin_id"`
	PluginName  string `json:"plugin_name"`
	Version     string `json:"version"`
	ArtifactURL string `json:"artifact_url" doc:"The URL the artifact was fetched from. Transport only; the hash is the security boundary."`
	SHA256      string `json:"artifact_sha256,omitempty" doc:"The hash THIS SERVER computed. Absent when the artifact could not be fetched, and a release with no hash cannot be approved."`
	Bytes       *int64 `json:"artifact_bytes,omitempty"`
	Verified    bool   `json:"verified" doc:"Whether this server fetched the artifact and hashed it. False means it could not, and the release cannot be approved until a reverify succeeds."`

	// FirstRelease is the single most important flag in this document. ADR-0007: a new plugin id
	// always gets human review, and nothing bypasses that — not trust, not automation, not an
	// owner who has published fifty times before.
	FirstRelease bool `json:"first_release" doc:"True when this plugin has nothing approved yet, so this submission is the first appearance of the id. That is where impersonation is caught."`

	SubmittedBy string    `json:"submitted_by,omitempty" doc:"The account that submitted it."`
	SubmittedAt time.Time `json:"submitted_at"`
	Note        string    `json:"review_note,omitempty" doc:"Why this is waiting: a hash mismatch, an artifact that could not be fetched, or simply that nothing publishes without a human yet."`
}

type reviewDecisionInput struct {
	ReleaseID string `path:"id" doc:"The release's id, from the queue."`
	Body      struct {
		Note string `json:"note,omitempty" maxLength:"2048" doc:"Why. Optional when approving; REQUIRED when rejecting, because the author cannot see the queue and has no other way to learn what to fix."`
	}
}

type reviewDecisionOutput struct {
	Body reviewDecisionResult
}

type reviewDecisionResult struct {
	ReleaseID  string `json:"release_id"`
	PluginID   string `json:"plugin_id"`
	Version    string `json:"version"`
	State      string `json:"state" doc:"The release's new state."`
	Superseded string `json:"superseded_release_id,omitempty" doc:"The release this approval retired, when there was one. A listing changing with nothing saying so is indistinguishable from a bug."`
}

type reverifyInput struct {
	ReleaseID string `path:"id"`
}

type reverifyOutput struct {
	Body reverifyResult
}

type reverifyResult struct {
	ReleaseID string `json:"release_id"`
	Verified  bool   `json:"verified" doc:"Whether the artifact could be fetched and hashed THIS TIME. False is not an error: the release is still pending and the reason is recorded."`
	SHA256    string `json:"artifact_sha256,omitempty" doc:"The hash this server computed, when it managed to."`
	Bytes     *int64 `json:"artifact_bytes,omitempty"`
	Note      string `json:"review_note" doc:"What was recorded on the release."`
}

// registerReview wires the review queue.
func registerReview(api huma.API, queue ReviewQueue) {
	// Every operation here is Floor(...).Reviewer(): session-only, and only a reviewer's session.
	// The floor is what stops a leaked publish token from moderating; Reviewer is what stops any
	// signed-in account from doing it. Both are enforced by the middleware, from this declaration.
	access := Floor("release.review").Reviewer()

	register(api, access, huma.Operation{
		OperationID: "listPendingReleases",
		Method:      http.MethodGet,
		Path:        BasePath + PathPendingReleases,
		Summary:     "List releases waiting for review",
		Description: "Everything submitted and not yet decided, oldest first.\n\n" +
			"AT MOST ONE ENTRY PER PLUGIN, and it is the newest submission. A later release of " +
			"the same plugin supersedes an earlier one that is still waiting, because only one " +
			"of them can become the listing and approving them is not ordered (ADR-0014).\n\n" +
			"`first_release` marks a submission that is the first appearance of a plugin id. " +
			"Those always require a human, whatever the submitter's trust level.\n\n" +
			"`verified` false means this server could not fetch the artifact. Such a release " +
			"cannot be approved — the database refuses a listing with no hash — so it must be " +
			"reverified or rejected.",
		Tags:   []string{tagReview},
		Errors: []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusInternalServerError},
	}, func(ctx context.Context, _ *struct{}) (*pendingReleasesOutput, error) {
		waiting, err := queue.List(ctx)
		if err != nil {
			slog.ErrorContext(ctx, "read the review queue", "error", err)
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError, "")
		}

		out := pendingReleases{Count: len(waiting), Releases: make([]waitingRelease, 0, len(waiting))}
		for _, w := range waiting {
			out.Releases = append(out.Releases, waitingRelease{
				ReleaseID:    w.ReleaseID,
				PluginID:     w.PluginID,
				PluginName:   w.PluginName,
				Version:      w.Version,
				ArtifactURL:  w.ArtifactURL,
				SHA256:       w.SHA256,
				Bytes:        w.Bytes,
				Verified:     w.Verified,
				FirstRelease: w.FirstRelease,
				SubmittedBy:  w.SubmittedBy,
				SubmittedAt:  w.SubmittedAt,
				Note:         w.Note,
			})
		}
		return &pendingReleasesOutput{Body: out}, nil
	})

	register(api, access, huma.Operation{
		OperationID: "approveRelease",
		Method:      http.MethodPost,
		Path:        BasePath + PathApproveRelease,
		Summary:     "Approve a release",
		Description: "Makes the release the plugin's live one and retires whatever it replaces.\n\n" +
			"The retired release is not deleted: history is kept, because those rows are the " +
			"record of what was approved and by whom.\n\n" +
			"A release whose artifact this server never hashed cannot be approved.",
		Tags: []string{tagReview},
		Errors: []int{
			http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
			http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError,
		},
	}, func(ctx context.Context, in *reviewDecisionInput) (*reviewDecisionOutput, error) {
		reviewer, ok := PrincipalFrom(ctx)
		if !ok {
			slog.ErrorContext(ctx, "approve reached a handler with no principal")
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError, "")
		}

		decision, err := queue.Approve(ctx, in.ReleaseID, reviewer.AccountID, in.Body.Note)
		if err != nil {
			return nil, reviewProblem(ctx, in.ReleaseID, err)
		}
		return &reviewDecisionOutput{Body: reviewDecisionResult{
			ReleaseID:  decision.ReleaseID,
			PluginID:   decision.PluginID,
			Version:    decision.Version,
			State:      "approved",
			Superseded: decision.Superseded,
		}}, nil
	})

	register(api, access, huma.Operation{
		OperationID: "rejectRelease",
		Method:      http.MethodPost,
		Path:        BasePath + PathRejectRelease,
		Summary:     "Reject a release",
		Description: "Refuses the release. A reason is required: the author cannot see the queue " +
			"and has no other way to learn what to fix.\n\n" +
			"The row stays, and so does its claim on the version — a version is used once per " +
			"plugin, ever, so a rejected 1.0.0 does not free 1.0.0.",
		Tags: []string{tagReview},
		Errors: []int{
			http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
			http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError,
		},
	}, func(ctx context.Context, in *reviewDecisionInput) (*reviewDecisionOutput, error) {
		reviewer, ok := PrincipalFrom(ctx)
		if !ok {
			slog.ErrorContext(ctx, "reject reached a handler with no principal")
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError, "")
		}

		decision, err := queue.Reject(ctx, in.ReleaseID, reviewer.AccountID, in.Body.Note)
		if err != nil {
			return nil, reviewProblem(ctx, in.ReleaseID, err)
		}
		return &reviewDecisionOutput{Body: reviewDecisionResult{
			ReleaseID: decision.ReleaseID,
			PluginID:  decision.PluginID,
			Version:   decision.Version,
			State:     "rejected",
		}}, nil
	})

	register(api, access, huma.Operation{
		OperationID: "reverifyRelease",
		Method:      http.MethodPost,
		Path:        BasePath + PathReverifyRelease,
		Summary:     "Fetch and hash a release's artifact again",
		Description: "For a release this server could not verify at publish time — an upstream " +
			"outage, a slow morning.\n\n" +
			"It can only ever FILL IN A BLANK. A release that already carries a hash is refused, " +
			"because a path that could recompute one is a path that could swap the bytes behind " +
			"a listing without anybody reviewing the swap.\n\n" +
			"Without this, a thirty-second outage would permanently consume a version number: a " +
			"version is used once per plugin, ever, so the author's only remedy would be to " +
			"publish a different one.",
		Tags: []string{tagReview},
		Errors: []int{
			http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound,
			http.StatusConflict, http.StatusInternalServerError,
		},
	}, func(ctx context.Context, in *reverifyInput) (*reverifyOutput, error) {
		reviewer, ok := PrincipalFrom(ctx)
		if !ok {
			slog.ErrorContext(ctx, "reverify reached a handler with no principal")
			return nil, NewProblem(http.StatusInternalServerError, CodeInternalError, "")
		}

		got, err := queue.Reverify(ctx, in.ReleaseID, reviewer.AccountID)
		if err != nil {
			return nil, reviewProblem(ctx, in.ReleaseID, err)
		}
		return &reverifyOutput{Body: reverifyResult{
			ReleaseID: got.ReleaseID,
			Verified:  got.Verified,
			SHA256:    got.SHA256,
			Bytes:     got.Bytes,
			Note:      got.Note,
		}}, nil
	})
}

// reviewProblem maps a queue failure onto a problem document.
func reviewProblem(ctx context.Context, releaseID string, err error) error {
	switch {
	case errors.Is(err, review.ErrNoSuchRelease):
		return NewProblem(http.StatusNotFound, CodeNotFound, "no such release")

	case errors.Is(err, review.ErrNotPending):
		// 409 rather than 404: the release exists and its state moved. Two reviewers with the
		// queue open is the normal case, and this is what one of them needs told.
		return NewProblem(http.StatusConflict, CodeConflict,
			"that release is no longer waiting for review; somebody else may have decided it")

	case errors.Is(err, review.ErrNotVerified):
		return NewProblem(http.StatusConflict, CodeConflict,
			"that release cannot be approved: this server never managed to fetch and hash its "+
				"artifact, so there is no verified hash to publish. Reverify it, or reject it")

	case errors.Is(err, review.ErrAlreadyVerified):
		return NewProblem(http.StatusConflict, CodeConflict,
			"that release already carries a hash this server computed; reverification can only "+
				"fill in a blank, never replace a hash clients may already have seen")

	case errors.Is(err, review.ErrNoReason):
		return NewProblem(http.StatusBadRequest, CodeInvalidRequest,
			"a rejection must say why: the author cannot see the queue")
	}

	slog.ErrorContext(ctx, "decide a release", "release_id", releaseID, "error", err)
	return NewProblem(http.StatusInternalServerError, CodeInternalError, "")
}
