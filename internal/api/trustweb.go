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
)

// The trust control: the form a reviewer sets an account's tier from.
//
// THIS IS THE HOLE THIS FILE FILLS. Setting a tier has had a JSON endpoint since Phase 3
// (trust.go) and no door a person could walk through. It is capability-floor, so no personal
// access token may perform it however scoped -- which makes it session-only, which makes it
// browser-only -- and there was no page. The only way to raise anybody was to copy a
// `__Host-regserve_session` cookie out of a browser into a hand-written `curl -X PUT`, so nobody
// ever did, so every account stayed at the floor, so EVERY release queued forever including a
// clean version bump of a plugin whose earlier release was approved. The mechanism was right and
// unreachable, which from the outside is indistinguishable from broken.
//
// It carries the SAME access declaration the JSON endpoint carries -- `Floor("trust.set").Reviewer()`
// -- enforced by the same middleware reading the same value. Two things are true at once and both
// are needed: the floor says no token may set a tier, and Reviewer says not every session may
// either. A tier a token could set would be a token that could raise its own account and publish
// without review, which is escalation with extra steps.
const PathReviewTrust = "/review/accounts/{id}/trust"

// setTrustFormInput is the form post. The account is the path parameter, as it is on the JSON
// endpoint, so both doors address an account the same way.
type setTrustFormInput struct {
	ID      string `path:"id"`
	RawBody []byte `contentType:"application/x-www-form-urlencoded"`
}

// registerTrustPage wires the form.
func registerTrustPage(api huma.API, deps WebDeps) {
	register(api, Floor("trust.set").Reviewer(), huma.Operation{
		OperationID:  "setAccountTrustFromTheReviewPage",
		MaxBodyBytes: maxFormBytes,
		Method:       http.MethodPost,
		Path:         PathReviewTrust,
		Summary:      "Set an account's trust tier",
		Description: "An HTML form post. `level` is `blocked`, `new` or `trusted`, and `note` " +
			"says why.\n\n" +
			"A tier is NEVER raised automatically: a counter of successful publishes is a " +
			"counter an attacker can run up. It governs one thing -- whether a version bump of " +
			"an already-approved plugin publishes without a human -- and never the first " +
			"appearance of a plugin id, which always gets a person.\n\n" +
			"The note is required. A tier with no stated reason is one nobody can review later, " +
			"and raising somebody to trusted is the decision that most needs to be explainable a " +
			"year afterwards.",
		Tags: []string{tagReviewPages},
		Errors: []int{
			http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
			http.StatusNotFound, http.StatusInternalServerError,
		},
		Responses: redirectResponses("The page the reviewer set the tier from."),
	}, func(ctx context.Context, in *setTrustFormInput) (*redirectOutput, error) {
		form := parseForm(in.RawBody)
		p, err := requireFormPrincipal(ctx, deps, form.Get(auth.CSRFFieldName))
		if err != nil {
			return nil, err
		}

		// Where to send them back to, decided BEFORE anything is changed and from a value that has
		// been through core.ParseULID. It arrives in the form, and a Location header assembled
		// from unvalidated input is a header somebody else gets to write.
		back := PathReviewQueue
		if raw := form.Get("release"); raw != "" {
			id, err := core.ParseULID(raw)
			if err != nil {
				return nil, NewProblem(http.StatusNotFound, CodeNotFound, "no such release")
			}
			back = reviewReleasePath(id)
		}

		level, err := release.ParseTrust(form.Get("level"))
		if err != nil {
			return redirectTo(back, msgTrustBadLevel), nil
		}

		return redirectTo(back, trustMessage(ctx,
			deps.Trust.SetTrust(ctx, in.ID, level, p.AccountID, form.Get("note")))), nil
	})
}

// trustMessage maps a trust change's outcome onto a message code.
//
// Every branch names a real outcome. The default is the only one that hides anything, and it logs
// what it hid: a reviewer told "that could not be done" with nothing in the log is a reviewer who
// cannot escalate.
func trustMessage(ctx context.Context, err error) string {
	switch {
	case err == nil:
		return msgTrustSet
	case errors.Is(err, release.ErrNoTrustReason):
		return msgTrustNoReason
	case errors.Is(err, release.ErrNoSuchAccount):
		return msgTrustUnknownAccount
	case errors.Is(err, release.ErrBadTrustLevel):
		return msgTrustBadLevel
	default:
		slog.ErrorContext(ctx, "set a trust level from the review page", "error", err)
		return msgTrustFailed
	}
}
