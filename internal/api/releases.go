package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
)

// PathPluginReleases is where a release is submitted. It is under the versioned product API, not
// beside the pinned index endpoints: this is our shape and it may version, where theirs may not.
const PathPluginReleases = "/plugins/{id}/releases"

// tagReleases groups publishing in the OpenAPI document and in the SDKs generated from it.
const tagReleases = "releases"

// idempotencyHeader is the header canonical §6 requires on every mutating POST that creates domain
// state. The spelling is the conventional one, so an SDK generator and a human both recognise it.
const idempotencyHeader = "Idempotency-Key"

// Publisher is what internal/api needs in order to accept a release.
//
// A consumer-declared interface, like Catalogue: this package says what it needs and the wiring
// supplies it. It keeps internal/plugin out of this package's import set, which is what lets
// internal/plugin depend on this one for the Catalogue interface without a cycle.
type Publisher interface {
	Publish(ctx context.Context, req release.Request) (release.Outcome, error)
}

// publishReleaseInput is the request. EVERY FIELD IS HOSTILE INPUT, including the ones that look
// structural — the domain layer validates all of them again in internal/release.
type publishReleaseInput struct {
	PluginID string `path:"id" doc:"The plugin's permanent id."`

	// IdempotencyKey is required by Huma, so a request without one is a 422 before any handler
	// runs. Canonical §6: the dominant caller is a release workflow, and workflows get re-run.
	IdempotencyKey string `header:"Idempotency-Key" required:"true" minLength:"1" maxLength:"255" doc:"An opaque key identifying this publish attempt. Re-running a workflow with the same key returns the original result instead of submitting a second release; reusing it with a different body is a 409."`

	Body publishReleaseBody
}

// publishReleaseBody is the JSON.
//
// THE FIELD NAMES ARE NOT THE INDEX DOCUMENT'S. `sdk_specifier` and `minimum_app_version` are the
// database's spelling, and the index calls the same two things something else. That is deliberate
// and mechanised: gate SCHEMA002 fails a wire-format field name in a string literal outside
// internal/registry, and a struct tag is a string literal. The deeper reason is canonical §1 — the
// index's names belong to a pydantic model in a released client that we cannot patch, and this
// request's names belong to us and version with /api/v1. Spelling them the same would put the
// client's vocabulary in a second package and invite somebody to keep the two "in sync", which is
// the moment the pinned format stops being pinned.
type publishReleaseBody struct {
	Version string `json:"version" maxLength:"64" doc:"The release's version. This registry carries it and compares it; the client evaluates version semantics."`

	ArtifactURL string `json:"artifact_url" maxLength:"2048" doc:"An https URL the artifact can be downloaded from. It is transport only: the server downloads it and computes the hash itself. A URL carrying credentials in its userinfo is refused, because this value is published in the index to every client."`

	ArtifactSHA256 string `json:"artifact_sha256" minLength:"64" maxLength:"64" doc:"The sha256 you computed for the artifact, as 64 hex characters. It is COMPARED against the hash this server computes from the bytes it downloads, and then discarded — the published hash is always the server's. A mismatch does not publish; it goes to review."`

	SDKSpecifier string `json:"sdk_specifier" maxLength:"128" doc:"The nParse+ SDK versions this release supports, as a PEP 440 specifier. Carried, not evaluated."`

	MinimumAppVersion *string `json:"minimum_app_version,omitempty" doc:"The lowest nParse+ version this release runs on, or null for no constraint. Null and empty are the same statement here and both mean no constraint."`

	Notes string `json:"notes,omitempty" maxLength:"2048" doc:"Plain-text patch notes for a human to read in the client. Not Markdown and not HTML (ADR-0013); at most 2048 bytes."`
}

// publishReleaseOutput is the answer.
type publishReleaseOutput struct {
	Status int
	Body   publishReleaseResult
}

// publishReleaseResult says what happened to the submission.
//
// IT NEVER REPORTS SUCCESS FOR AN ARTIFACT THAT WAS NOT CHECKED. `verified` and `state` are
// separate fields because they answer different questions — "did this server read and hash the
// bytes" and "is this release live" — and collapsing them into one boolean is how "we could not
// check" and "we checked and it was fine" become the same answer (ADR-0008).
type publishReleaseResult struct {
	ReleaseID string `json:"release_id" doc:"This release's permanent id."`

	State string `json:"state" doc:"Where the release is: pending while it waits for a human, approved once it is the plugin's live release. A new plugin id always gets human review, and trust never bypasses that."`

	Verified bool `json:"verified" doc:"Whether this server downloaded the artifact and computed its hash. FALSE MEANS THE BYTES WERE NOT CHECKED: the release is recorded and sent to review, and the review field says why. It is never a success."`

	SHA256 string `json:"artifact_sha256,omitempty" doc:"The sha256 THIS SERVER computed from the bytes it downloaded. This is the value that is published, and it is not necessarily the one you submitted. Absent when the artifact could not be fetched."`

	Bytes *int64 `json:"artifact_bytes,omitempty" doc:"The artifact's size in bytes, counted during the download. Absent when the artifact could not be fetched."`

	Review string `json:"review,omitempty" doc:"Why this release is waiting, in a sentence written for a human."`

	Replayed bool `json:"replayed" doc:"True when this idempotency key had been seen before and this is the original result rather than a new submission."`

	Superseded string `json:"superseded_release_id,omitempty" doc:"The release this one retired, when it published automatically."`

	// Reasons is what a publishing workflow prints so the author learns why their release is
	// waiting without opening a browser to find out.
	Reasons []string `json:"quarantine,omitempty" doc:"Every rule that sent this release to review. Absent when it went live. A new plugin id is always one of these: the first appearance of an id always gets a human, whatever the submitter's trust level."`
}

// registerReleases wires the publish endpoint.
//
// advice is what a refused publish says about claiming an id, already decided by claimAdvice from
// what this build serves. It is passed in rather than computed here because the answer depends on
// which OTHER routes exist, which is knowledge this file does not have and must not guess at.
func registerReleases(api huma.API, publisher Publisher, advice string) {
	register(api,
		// The permission is `plugin.publish`, SPELLED AS THE CATALOGUE SPELLS IT. It said
		// `release.publish` for one release: a permission that exists nowhere in
		// internal/authz, so authz.Satisfies could not find it and every scoped token was
		// answered 403 — publishing, the point of this service, was closed to CI. PERM001 now
		// fails a declaration that names a permission the catalogue does not define.
		//
		// A token needs `plugin:publish`, AND its pin is compared against the `id` path parameter
		// before the handler runs. OnPlugin is what makes the pin enforceable: ADR-0005's
		// containment argument is that a credential in one repository's CI can do exactly one
		// thing to exactly one plugin, and that is only true if something compares the two.
		// PERM001 fails a token-callable operation under /plugins/{...} that omits it.
		Requires("plugin.publish", "plugin:publish").OnPlugin("id"),
		huma.Operation{
			// NEVER RENAMED. It is the generated SDK's method name, so a rename breaks callers in
			// their language rather than ours (canonical §6, gate OAPI001).
			OperationID: "publishRelease",
			Method:      http.MethodPost,
			Path:        BasePath + PathPluginReleases,
			Summary:     "Publish a release",
			Description: "Submits a release of a plugin you hold.\n\n" +
				"**The server downloads the artifact and computes its sha256 itself.** The " +
				"`artifact_sha256` you send is compared against that value and then discarded; " +
				"the hash this registry publishes is always one it derived from bytes it read " +
				"(ADR-0008). If the two disagree, the release is not published: it is recorded " +
				"and sent to human review, with the mismatch noted.\n\n" +
				"**An artifact that could not be downloaded is not published either.** It goes " +
				"to review with the reason recorded and `verified` false. \"We could not check\" " +
				"and \"we checked and it was fine\" never produce the same answer.\n\n" +
				"`Idempotency-Key` is required. A re-run with the same key returns the original " +
				"result; the same key with a different body is a 409.",
			Tags: []string{tagReleases},
			Errors: []int{
				http.StatusBadRequest,
				http.StatusUnauthorized,
				http.StatusForbidden,
				http.StatusNotFound,
				http.StatusConflict,
				http.StatusInternalServerError,
			},
		},
		func(ctx context.Context, in *publishReleaseInput) (*publishReleaseOutput, error) {
			principal, ok := PrincipalFrom(ctx)
			if !ok {
				// Unreachable: the middleware answers 401 before a handler for an authenticated
				// operation runs. Refusing is the only safe reading of "we do not know who this is".
				slog.ErrorContext(ctx, "publish reached a handler with no principal")
				return nil, NewProblem(http.StatusInternalServerError, CodeInternalError, "")
			}

			submission, err := release.NewSubmission(release.RawSubmission{
				PluginID:          in.PluginID,
				Version:           in.Body.Version,
				ArtifactURL:       in.Body.ArtifactURL,
				ArtifactSHA256:    in.Body.ArtifactSHA256,
				SDKSpecifier:      in.Body.SDKSpecifier,
				MinimumAppVersion: in.Body.MinimumAppVersion,
				Notes:             in.Body.Notes,
			})
			if err != nil {
				return nil, badSubmission(err)
			}

			outcome, err := publisher.Publish(ctx, release.Request{
				Submission:     submission,
				AccountID:      principal.AccountID,
				IdempotencyKey: in.IdempotencyKey,
			})
			if err != nil {
				// The PARSED id, not the raw path parameter. It is the same string — the
				// submission above would have been refused otherwise — and passing the value that
				// has been through core.ParsePluginID is what makes "this detail cannot echo
				// something unvalidated" true by construction rather than by reading upwards.
				return nil, publishProblem(ctx, submission.PluginID.String(), advice, err)
			}

			return &publishReleaseOutput{
				// 201 whether it is pending or approved: a release resource was created either
				// way, and the body's `state` is what says whether it is live. A status that
				// varied with the state would change for existing callers the moment trust levels
				// land, which is a compatibility break dressed as a feature.
				Status: http.StatusCreated,
				Body: publishReleaseResult{
					ReleaseID:  outcome.ReleaseID,
					State:      outcome.State.String(),
					Verified:   outcome.Verified,
					SHA256:     outcome.SHA256,
					Bytes:      outcome.Bytes,
					Review:     outcome.Review,
					Replayed:   outcome.Replayed,
					Superseded: outcome.Superseded,
					Reasons:    outcome.Reasons,
				},
			}, nil
		})
}

// badSubmission maps a validation failure onto a problem document.
//
// Every branch is a 400 with the submitter's own error, because every one of them is a fact about
// what they sent and none of them says anything about what exists here. The messages come from the
// domain sentinels rather than being rewritten, so the answer names the field.
func badSubmission(err error) error {
	return NewProblem(http.StatusBadRequest, CodeInvalidRequest, err.Error())
}

// publishProblem maps a publish failure onto a problem document.
//
// advice is the claiming sentence claimAdvice produced for this build. pluginID reaches the LOG
// and never a refusal: a message that named the id back would be a message that varied with the
// id, which is the shape the case below exists to avoid.
func publishProblem(ctx context.Context, pluginID, advice string, err error) error {
	switch {
	case errors.Is(err, release.ErrNotPublishable):
		// ONE ANSWER FOR "the id does not exist" AND "it is not yours", and it must stay one.
		//
		// A refusal that varied between the two would let anybody holding an unpinned
		// `plugin:publish` token classify a wordlist: the specific answer would mean free, and
		// this general one would then PROVE the id is somebody else's — which is precisely the
		// set that must not be enumerable, since ids are permanent and never recycled. A draft of
		// this change did exactly that, on the reasoning that POST /api/v1/plugins already tells a
		// signed-in caller whether an id is taken. It does not usefully: its "not taken" answer is
		// a 201 that CLAIMS THE ID, permanently, with an audit row. That side effect is what makes
		// the claim endpoint useless as a probe, and it is why this one must not be a substitute.
		//
		// THE GUIDANCE BELOW IS UNCONDITIONAL, and that is what makes it safe. Every word of it is
		// true of the registry rather than of this id: claiming is a separate act, no token can
		// perform it, and here is where it is done. The author who could not publish did not need
		// to be told that HIS id was free — he needed to be told the step existed at all, and that
		// is the same sentence whoever asks and whichever id they ask about.
		//
		// Gate: TestPublishRelease_TheRefusal_CannotClassifyAnID compares the two responses byte
		// for byte over real HTTP, so a future branch that splits them again is a red test.
		return NewProblem(http.StatusNotFound, CodeNotFound,
			"no such plugin, or you do not hold it. "+advice)

	case errors.Is(err, release.ErrGitHubIdentityRequired):
		return NewProblem(http.StatusForbidden, CodeGitHubIdentityRequired,
			"publishing requires a linked github identity; sign in with GitHub and try again")

	case errors.Is(err, release.ErrVersionExists):
		return NewProblem(http.StatusConflict, CodeConflict,
			"that version has already been submitted for this plugin, and a version is used once "+
				"per plugin ever")

	case errors.Is(err, release.ErrIdempotencyKeyReused):
		return NewProblem(http.StatusConflict, CodeConflict,
			"that "+idempotencyHeader+" was used for a different request; use a new key for a new "+
				"release")

	case errors.Is(err, release.ErrAccountBlocked):
		// 403 and not 404. The account exists, it holds the plugin, and it has been refused by a
		// person — telling them so is what lets them ask why, and hiding it would look like a bug.
		return NewProblem(http.StatusForbidden, CodeForbidden,
			"this account may not publish: a reviewer has blocked it")

	case errors.Is(err, release.ErrLiveReleaseChanged):
		return NewProblem(http.StatusConflict, CodeConflict,
			"the plugin's live release changed while this artifact was being fetched, so the "+
				"checks this publish was judged against are no longer current; submit it again")

	case errors.Is(err, release.ErrNoIdempotencyKey):
		return NewProblem(http.StatusBadRequest, CodeInvalidRequest,
			"an "+idempotencyHeader+" header is required")

	case errors.Is(err, artifact.ErrBadArtifactURL), errors.Is(err, artifact.ErrInvalidDigest),
		errors.Is(err, core.ErrInvalidPluginID):
		return badSubmission(err)
	}

	// Anything else is ours. The cause goes to the log with the plugin id; the caller gets the
	// fixed sentence and the request id, because echoing a driver error to an authenticated
	// stranger is how a publish endpoint becomes an information-disclosure bug.
	slog.ErrorContext(ctx, "publish a release", "plugin_id", pluginID, "error", err)
	return NewProblem(http.StatusInternalServerError, CodeInternalError, "")
}

// claimAdvice is what a refused publish says about claiming an id, decided ONCE at registration
// from what this build actually serves.
//
// TWO SENTENCES AND NO THIRD, and neither of them mentions the id. That is what keeps the refusal
// unable to classify one: the advice varies with the DEPLOYMENT, which every caller can see
// anyway, and never with the plugin asked about. See publishProblem.
//
// The unavailable case is not a shrug. An instance with no sign-in has no door onto claiming at
// all — the browser form is unregistered and so is POST /api/v1/plugins — and ownership there is
// set by whoever runs the process. Saying "sign in at /account" to that caller would be sending
// them to a 404, which is the dead end this whole change removes.
func claimAdvice(claimable bool, publicURL string) string {
	if !claimable {
		return "Publishing never claims an id, and this registry has no way to claim one: it is " +
			"running without sign-in, so ownership is set by whoever operates it. Ask them to " +
			"grant you the id, then publish again."
	}
	return "Publishing never claims an id, and no token can claim one however scoped — claiming " +
		"is session-only. If you have not claimed this id, sign in at " + claimHere(publicURL) +
		" and claim it there, then publish again; if you have, check that you are still an owner."
}

// claimHere renders WHERE an id is claimed, from the public URL the operator configured.
//
// The absolute URL when this instance was told its own, and the PATH when it was not. Never a URL
// assembled from the request's Host header: that value is chosen by the caller, and this sentence
// is printed verbatim into somebody else's release pipeline by the reusable workflow. A registry
// that told an author to go and sign in at a host an attacker put in a header would be handing out
// a phishing link with a straight face. Same rule as indexURL, for the same reason.
func claimHere(publicURL string) string {
	base := strings.TrimSpace(publicURL)
	if base == "" {
		return PathAccountPage
	}
	return strings.TrimSuffix(base, "/") + PathAccountPage
}
