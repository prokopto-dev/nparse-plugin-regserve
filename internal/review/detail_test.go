package review_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
)

// Detail is read by the review pages, and its job is to answer WHY a release is waiting.
//
// The answer does not live in the release row. `review_note` holds a rendered sentence; the
// structured reasons and the hash the submitter claimed live in the audit row the publish wrote —
// the claimed hash only ever surviving there, because ADR-0008 compares it and discards it.
//
// SO THESE TESTS GO THROUGH THE REAL PUBLISH PATH, and that is the point rather than a convenience.
// internal/review spells the audit detail's keys a second time, next to a comment saying so; these
// tests are what makes that spelling checked instead of hoped for. Rename `quarantine` in
// internal/release without renaming it here and this file goes red — which is the difference
// between a coupling that is written down and one that silently empties a page.

// publishClaiming submits a release whose claimed sha256 is whatever the caller says, so a
// mismatch can be produced without reaching inside the publish path.
func publishClaiming(t *testing.T, w *world, version, claimed string) release.Outcome {
	t.Helper()

	sub, err := release.NewSubmission(release.RawSubmission{
		PluginID:       w.plugin,
		Version:        version,
		ArtifactURL:    w.srv.URL + "/" + version + ".whl",
		ArtifactSHA256: claimed,
		SDKSpecifier:   ">=1.0,<2",
		Notes:          "What changed: the price graph.",
	})
	require.NoError(t, err)

	out, err := w.pub.Publish(t.Context(), release.Request{
		Submission: sub, AccountID: w.owner, IdempotencyKey: "claim-" + version,
	})
	require.NoError(t, err)
	return out
}

// TestDetail_ShowsWhyAReleaseIsWaiting_IncludingTheHashThatDisagreed is the whole reason this
// exists.
//
// A reviewer looking at a release whose only visible problem is "awaiting human review" would
// approve it. The audit row says the submitted hash did not match the bytes this server
// downloaded, and a mismatch is unreadable without BOTH halves — so both are on the page.
func TestDetail_ShowsWhyAReleaseIsWaiting_IncludingTheHashThatDisagreed(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	const claimed = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	out := publishClaiming(t, w, "1.0.0", claimed)

	got, err := w.queue.Detail(t.Context(), out.ReleaseID)
	require.NoError(t, err)

	require.Equal(t, "pending", got.State)
	require.Equal(t, "merchant-mode", got.PluginID)
	require.Equal(t, "Merchant Mode", got.PluginName)
	require.Equal(t, "1.0.0", got.Version)
	require.Equal(t, "publish", got.Source)
	require.Equal(t, "What changed: the price graph.", got.Notes,
		"a reviewer must see the text that will be published to every client")

	require.NotEmpty(t, got.Quarantine,
		"the publish recorded why this release is waiting; if this is empty, the audit detail's "+
			"keys have been renamed on one side of the two places they are spelled")
	require.Contains(t, strings.Join(got.Quarantine, " | "), "sha256 does not match")
	require.Contains(t, strings.Join(got.Quarantine, " | "), "first release")

	require.Equal(t, claimed, got.SubmittedSHA256,
		"the claimed hash survives ONLY in the audit row, and only because it disagreed")
	require.NotEmpty(t, got.SHA256, "the server hashed the bytes it downloaded")
	require.NotEqual(t, got.SubmittedSHA256, got.SHA256,
		"the two hashes are the finding; if they are equal the test is not testing a mismatch")
	require.True(t, got.Verified, "the artifact was fetched; it was the CLAIM that was wrong")
}

// TestDetail_WithNoMismatch_ShowsNoSubmittedHash — the ordinary path stores nothing to show.
//
// ADR-0008 discards the submitted digest after comparing it, and the audit row records it only on
// a mismatch. A page that displayed one anyway would be displaying a value nobody kept.
func TestDetail_WithNoMismatch_ShowsNoSubmittedHash(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	out := w.publish(t, "1.0.0")

	got, err := w.queue.Detail(t.Context(), out.ReleaseID)
	require.NoError(t, err)

	require.Empty(t, got.SubmittedSHA256)
	require.NotEmpty(t, got.SHA256)
	require.Contains(t, strings.Join(got.Quarantine, " | "), "first release",
		"a new plugin id is always a reason, whatever else did or did not fire")
}

// TestDetail_AnArtifactNobodyCouldFetch_SaysSoRatherThanShowingAnEmptyHash.
func TestDetail_AnArtifactNobodyCouldFetch_SaysSoRatherThanShowingAnEmptyHash(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	w.available = false // the artifact host is having a morning
	out := w.publish(t, "1.0.0")

	got, err := w.queue.Detail(t.Context(), out.ReleaseID)
	require.NoError(t, err)

	require.False(t, got.Verified)
	require.Empty(t, got.SHA256, "there is nothing honest to put here")
	require.Contains(t, strings.Join(got.Quarantine, " | "), "could not be fetched")
}

// TestDetail_TheAuditTrail_IsEveryRowAboutThisRelease_InOrder.
//
// It spans two subjects: a publish is recorded against the PLUGIN (an incident review asks what
// happened to a plugin) and a decision against the RELEASE. A page that read only one of them
// would show a release that was approved by somebody with no record of how it got there.
func TestDetail_TheAuditTrail_IsEveryRowAboutThisRelease_InOrder(t *testing.T) {
	t.Parallel()

	w := newSteppingWorld(t)
	w.available = false
	out := w.publish(t, "1.0.0")

	// A failed re-verification. Recorded, because three failures in a row is a different story
	// from one, and a trail that kept only successes would hide exactly that.
	_, err := w.queue.Reverify(t.Context(), out.ReleaseID, w.reviewer)
	require.NoError(t, err)

	w.available = true
	_, err = w.queue.Reverify(t.Context(), out.ReleaseID, w.reviewer)
	require.NoError(t, err)

	_, err = w.queue.Approve(t.Context(), out.ReleaseID, w.reviewer, "looks fine")
	require.NoError(t, err)

	got, err := w.queue.Detail(t.Context(), out.ReleaseID)
	require.NoError(t, err)

	actions := make([]string, 0, len(got.Events))
	for _, e := range got.Events {
		actions = append(actions, e.Action)
	}
	require.Equal(t,
		[]string{"plugin.publish", "release.reverify", "release.reverify", "release.approve"},
		actions, "the trail is every row about this release, oldest first")

	for _, e := range got.Events {
		require.False(t, e.At.IsZero(), "%s has no timestamp", e.Action)
		require.NotEmpty(t, e.Detail, "%s recorded no detail", e.Action)
	}
	require.Equal(t, "themaintainer", got.Events[3].Actor,
		"a reviewer reads a name rather than a ULID")

	require.Equal(t, "approved", got.State)
	require.Equal(t, w.reviewer, got.ReviewedBy)
	require.False(t, got.ReviewedAt.IsZero())
}

// TestDetail_ShowsOnlyThisReleasesHistory — a plugin's other publishes are not this one's trail.
func TestDetail_ShowsOnlyThisReleasesHistory(t *testing.T) {
	t.Parallel()

	w := newSteppingWorld(t)
	first := w.publish(t, "1.0.0")
	_, err := w.queue.Approve(t.Context(), first.ReleaseID, w.reviewer, "")
	require.NoError(t, err)

	w.serving = []byte("PK\x03\x04 a newer artifact")
	second := w.publish(t, "1.1.0")

	got, err := w.queue.Detail(t.Context(), second.ReleaseID)
	require.NoError(t, err)

	require.Len(t, got.Events, 1,
		"only the second release's own publish belongs on its page; the first release's publish "+
			"and approval are a different release's history")
	require.Equal(t, "plugin.publish", got.Events[0].Action)

	require.Equal(t, "1.0.0", got.LiveVersion,
		"a reviewer needs to know what this would replace")
	require.False(t, got.FirstRelease,
		"the plugin has something live, so this is a version bump rather than a new id")
}

// TestDetail_AfterADecision_StillAnswers — the page a reviewer is redirected back to.
//
// Restricting this to pending releases would 404 the reviewer the instant they acted, leaving them
// unable to see what they had just done or to read the row recording it.
func TestDetail_AfterADecision_StillAnswers(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	out := w.publish(t, "1.0.0")
	_, err := w.queue.Reject(t.Context(), out.ReleaseID, w.reviewer, "the artifact is not a plugin")
	require.NoError(t, err)

	got, err := w.queue.Detail(t.Context(), out.ReleaseID)
	require.NoError(t, err)
	require.Equal(t, "rejected", got.State)
	require.Equal(t, "the artifact is not a plugin", got.Note)
	require.Empty(t, got.LiveVersion, "a rejection publishes nothing")
}

// TestDetail_AnUnknownRelease_IsNotFound.
func TestDetail_AnUnknownRelease_IsNotFound(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	_, err := w.queue.Detail(t.Context(), "01JZZZZZZZZZZZZZZZZZZZZZZZ")
	require.ErrorIs(t, err, review.ErrNoSuchRelease)
}
