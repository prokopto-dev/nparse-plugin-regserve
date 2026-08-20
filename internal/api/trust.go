package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
)

// PathAccountTrust is where an account's trust tier is set. Keyed on the account id, which is what
// the review queue shows next to every submission.
const PathAccountTrust = "/accounts/{id}/trust"

// TrustService is what internal/api needs in order to set a trust tier.
type TrustService interface {
	SetTrust(ctx context.Context, accountID string, level release.Trust, reviewerID, note string) error
}

type setTrustInput struct {
	AccountID string `path:"id" doc:"The account's id, as shown against a submission in the review queue."`
	Body      struct {
		Level string `json:"level" enum:"blocked,new,trusted" doc:"The tier. trusted lets this account's version bumps of an already-approved plugin publish without a human; blocked refuses its publishes outright; new is the default and sends everything to review."`
		Note  string `json:"note" maxLength:"2048" doc:"Why. REQUIRED: a tier with no stated reason is one nobody can review later, and raising somebody to trusted is the decision that most needs to be explainable a year afterwards."`
	}
}

type setTrustOutput struct {
	Body setTrustResult
}

type setTrustResult struct {
	AccountID string `json:"account_id"`
	Level     string `json:"level"`
}

// registerTrust wires the trust endpoint.
func registerTrust(api huma.API, trust TrustService) {
	register(api,
		// Capability-floor AND reviewer-only, like the queue. Setting trust is listed in canonical
		// §5's floor because a token that could raise its own account's tier would be a token that
		// could publish without review — which is the definition of escalating itself.
		Floor("trust.set").Reviewer(),
		huma.Operation{
			OperationID: "setAccountTrust",
			Method:      http.MethodPut,
			Path:        BasePath + PathAccountTrust,
			Summary:     "Set an account's trust tier",
			Description: "Trust governs ONE thing: whether a version bump of an already-approved " +
				"plugin can publish without a human.\n\n" +
				"It never governs the first appearance of a plugin id — that always gets a " +
				"human, whatever the tier — and it never governs who may review, which is " +
				"configured in the deployment. A tier that did both would let a trusted " +
				"publisher approve their own submissions.\n\n" +
				"**It is never raised automatically.** A counter of successful publishes is a " +
				"counter an attacker can run up: publish four harmless releases, earn the tier, " +
				"publish the fifth.\n\n" +
				"PUT rather than POST because a tier is a property of the account, not an event. " +
				"The history is in the audit log, which nothing can edit.",
			Tags: []string{tagReview},
			Errors: []int{
				http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
				http.StatusNotFound, http.StatusInternalServerError,
			},
		},
		func(ctx context.Context, in *setTrustInput) (*setTrustOutput, error) {
			reviewer, ok := PrincipalFrom(ctx)
			if !ok {
				slog.ErrorContext(ctx, "set trust reached a handler with no principal")
				return nil, NewProblem(http.StatusInternalServerError, CodeInternalError, "")
			}

			level, err := release.ParseTrust(in.Body.Level)
			if err != nil {
				return nil, NewProblem(http.StatusBadRequest, CodeInvalidRequest, err.Error())
			}

			if err := trust.SetTrust(ctx, in.AccountID, level, reviewer.AccountID, in.Body.Note); err != nil {
				return nil, trustProblem(ctx, in.AccountID, err)
			}
			return &setTrustOutput{Body: setTrustResult{
				AccountID: in.AccountID,
				Level:     level.String(),
			}}, nil
		})
}

func trustProblem(ctx context.Context, accountID string, err error) error {
	switch {
	case errors.Is(err, release.ErrNoSuchAccount):
		return NewProblem(http.StatusNotFound, CodeNotFound, "no such account")
	case errors.Is(err, release.ErrNoTrustReason):
		return NewProblem(http.StatusBadRequest, CodeInvalidRequest,
			"a trust change must say why: a tier with no stated reason is one nobody can review later")
	case errors.Is(err, release.ErrBadTrustLevel):
		return NewProblem(http.StatusBadRequest, CodeInvalidRequest, err.Error())
	}

	slog.ErrorContext(ctx, "set a trust level", "account_id", accountID, "error", err)
	return NewProblem(http.StatusInternalServerError, CodeInternalError, "")
}
