package review_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
)

// TestApprove_MakesTheReleaseLive_AndIsTheOnlyWayAnythingReachesTheIndex.
//
// Before this package existed, a publish was durably recorded and went nowhere: the only writer of
// state='approved' in the whole tree was the seed importer. This is the assertion that the
// pipeline now has an exit, and it is made against what the INDEX would render rather than against
// a returned value.
func TestApprove_MakesTheReleaseLive_AndIsTheOnlyWayAnythingReachesTheIndex(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	out := w.publish(t, "1.0.0")

	require.Equal(t, "pending", w.state(t, out.ReleaseID))
	require.Empty(t, w.listed(t), "a published release reached the index without a human")

	decision, err := w.queue.Approve(t.Context(), out.ReleaseID, w.reviewer, "looks fine")
	require.NoError(t, err)
	require.Equal(t, out.ReleaseID, decision.ReleaseID)
	require.Empty(t, decision.Superseded, "the first release of a plugin supersedes nothing")

	require.Equal(t, "approved", w.state(t, out.ReleaseID))
	require.Equal(t, []string{"merchant-mode@1.0.0"}, w.listed(t))
}

// TestApprove_RetiresThePreviousLiveRelease_AndKeepsIt.
//
// ADR-0010: the wire format carries one release per plugin and the database carries all of them.
// The retired row is the record of what was approved and by whom, so superseding is a state change
// and never a delete.
func TestApprove_RetiresThePreviousLiveRelease_AndKeepsIt(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	first := w.publish(t, "1.0.0")
	_, err := w.queue.Approve(t.Context(), first.ReleaseID, w.reviewer, "")
	require.NoError(t, err)

	// A different artifact, so the second release is genuinely a different one.
	w.serving = []byte("PK\x03\x04 a newer artifact")
	second := w.publish(t, "1.1.0")

	decision, err := w.queue.Approve(t.Context(), second.ReleaseID, w.reviewer, "")
	require.NoError(t, err)
	require.Equal(t, first.ReleaseID, decision.Superseded,
		"the approval must say what it retired; a listing changing with nothing saying so is "+
			"indistinguishable from a bug")

	require.Equal(t, "superseded", w.state(t, first.ReleaseID))
	require.Equal(t, "approved", w.state(t, second.ReleaseID))
	require.Equal(t, []string{"merchant-mode@1.1.0"}, w.listed(t))

	// Both rows are still there. The partial unique index is what makes "the approved release"
	// singular; nothing here deletes history to achieve it.
	require.Equal(t, map[string]int{"approved": 1, "superseded": 1}, w.releaseStates(t))
}

// TestApprove_ARelease TheServerNeverHashed_IsRefused.
//
// The database refuses it too — release_approved_has_a_hash — and that is the mechanism. This
// asserts the service refuses it FIRST, with a sentence naming the way out, rather than letting a
// reviewer meet a constraint name.
func TestApprove_AReleaseTheServerNeverHashed_IsRefused(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	w.available = false // the artifact host is having a morning
	out := w.publish(t, "1.0.0")
	require.False(t, out.Verified)

	_, err := w.queue.Approve(t.Context(), out.ReleaseID, w.reviewer, "trust me")
	require.ErrorIs(t, err, review.ErrNotVerified)

	require.Equal(t, "pending", w.state(t, out.ReleaseID))
	require.Empty(t, w.listed(t),
		"a release whose bytes this server never read reached the index")
}

// TestReject_KeepsTheRowAndTheVersion.
//
// A version is used once per plugin, EVER, over a table nothing deletes from. A rejected 1.0.0
// does not free 1.0.0: the number is what a client may already have seen, and reusing it is how
// different bytes ship under a version somebody already installed.
func TestReject_KeepsTheRowAndTheVersion(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	out := w.publish(t, "1.0.0")

	_, err := w.queue.Reject(t.Context(), out.ReleaseID, w.reviewer, "the plugin id impersonates another")
	require.NoError(t, err)

	require.Equal(t, "rejected", w.state(t, out.ReleaseID))
	require.Empty(t, w.listed(t))
	require.Equal(t, map[string]int{"rejected": 1}, w.releaseStates(t))

	// The reason reaches the row, because it is the only way the author learns what to fix.
	row, err := w.db.Read().GetReleaseByID(t.Context(), out.ReleaseID)
	require.NoError(t, err)
	require.NotNil(t, row.ReviewNote)
	require.Equal(t, "the plugin id impersonates another", *row.ReviewNote)
	require.NotNil(t, row.ReviewedBy)
	require.Equal(t, w.reviewer, *row.ReviewedBy)
}

// TestReject_WithNoReason_IsRefused.
//
// Approvals may be silent. Refusals may not: the author cannot see the queue and has no other way
// to learn why, so a rejection with nothing written down is indistinguishable from a mistake.
func TestReject_WithNoReason_IsRefused(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	out := w.publish(t, "1.0.0")

	for _, reason := range []string{"", "   ", "\t\n"} {
		_, err := w.queue.Reject(t.Context(), out.ReleaseID, w.reviewer, reason)
		require.ErrorIs(t, err, review.ErrNoReason)
	}
	require.Equal(t, "pending", w.state(t, out.ReleaseID))
}

// TestDecide_ARaceBetweenTwoReviewers_ProducesOneDecision.
//
// Two reviewers with the queue open is the normal case. The second must be told rather than
// silently doing nothing — a reviewer who believes they rejected something that is now live is
// worse off than one who got an error.
func TestDecide_ARaceBetweenTwoReviewers_ProducesOneDecision(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	out := w.publish(t, "1.0.0")

	_, err := w.queue.Approve(t.Context(), out.ReleaseID, w.reviewer, "")
	require.NoError(t, err)

	// The second reviewer's decisions all meet a release that is no longer pending.
	_, err = w.queue.Approve(t.Context(), out.ReleaseID, w.reviewer, "")
	require.ErrorIs(t, err, review.ErrNotPending)

	_, err = w.queue.Reject(t.Context(), out.ReleaseID, w.reviewer, "actually no")
	require.ErrorIs(t, err, review.ErrNotPending)

	_, err = w.queue.Reverify(t.Context(), out.ReleaseID, w.reviewer)
	require.ErrorIs(t, err, review.ErrNotPending)

	require.Equal(t, "approved", w.state(t, out.ReleaseID))
}

// TestDecide_AnUnknownRelease_IsNotFound.
func TestDecide_AnUnknownRelease_IsNotFound(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	_, err := w.queue.Approve(t.Context(), "01ARZ3NDEKTSV4RRFFQ69G5FZZ", w.reviewer, "")
	require.ErrorIs(t, err, review.ErrNoSuchRelease)
}

// TestList_ShowsWhatAReviewerNeedsToDecide.
func TestList_ShowsWhatAReviewerNeedsToDecide(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	first := w.publish(t, "1.0.0")

	waiting, err := w.queue.List(t.Context())
	require.NoError(t, err)
	require.Len(t, waiting, 1)

	got := waiting[0]
	require.Equal(t, first.ReleaseID, got.ReleaseID)
	require.Equal(t, "merchant-mode", got.PluginID)
	require.Equal(t, "Merchant Mode", got.PluginName)
	require.Equal(t, "1.0.0", got.Version)
	require.True(t, got.Verified)
	require.NotEmpty(t, got.SHA256)
	require.Equal(t, w.owner, got.SubmittedBy)

	// THE FLAG THAT MATTERS. ADR-0007: a new plugin id always gets human review, and nothing
	// bypasses it. A queue that did not distinguish the first appearance of an id from a routine
	// version bump would be asking reviewers to work that out for themselves.
	require.True(t, got.FirstRelease, "the first release of a plugin is not marked as one")

	_, err = w.queue.Approve(t.Context(), first.ReleaseID, w.reviewer, "")
	require.NoError(t, err)

	w.serving = []byte("PK\x03\x04 a newer artifact")
	w.publish(t, "1.1.0")

	waiting, err = w.queue.List(t.Context())
	require.NoError(t, err)
	require.Len(t, waiting, 1)
	require.False(t, waiting[0].FirstRelease,
		"a version bump of an approved plugin is flagged as a first appearance")
}

// TestList_IsOldestFirst — a queue people work from the top of is a queue whose bottom is never
// reached, and the bottom is where a fortnight-old submission sits.
func TestList_IsOldestFirst(t *testing.T) {
	t.Parallel()

	// A clock that ADVANCES. Under a frozen one every release shares a submitted_at and the order
	// falls to the ULID tiebreaker, whose low bits are random -- so a fixed clock would be testing
	// that this queue cannot do something it does not need to do.
	w := newSteppingWorld(t)
	w.publish(t, "1.0.0")
	w.serving = []byte("PK\x03\x04 second")
	w.publish(t, "1.1.0")
	w.serving = []byte("PK\x03\x04 third")
	w.publish(t, "1.2.0")

	waiting, err := w.queue.List(t.Context())
	require.NoError(t, err)
	require.Len(t, waiting, 3)

	require.Equal(t, []string{"1.0.0", "1.1.0", "1.2.0"},
		[]string{waiting[0].Version, waiting[1].Version, waiting[2].Version},
		"the queue is not oldest-first; the fortnight-old submission is the one nobody reaches")

	// And the order is STABLE. A queue that shuffled between refreshes would have a reviewer
	// losing their place every time they looked away.
	again, err := w.queue.List(t.Context())
	require.NoError(t, err)
	require.Equal(t, waiting, again)

	n, err := w.queue.Pending(t.Context())
	require.NoError(t, err)
	require.Equal(t, int64(3), n)
}

// TestDecisions_AreRecordedInTheAuditLog.
//
// audit_log is append-only by trigger, so these rows are the permanent answer to "who approved
// these exact bytes, and when" — the question this whole service exists to be able to answer.
func TestDecisions_AreRecordedInTheAuditLog(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	approved := w.publish(t, "1.0.0")
	_, err := w.queue.Approve(t.Context(), approved.ReleaseID, w.reviewer, "checked the source")
	require.NoError(t, err)

	w.serving = []byte("PK\x03\x04 a second artifact")
	rejected := w.publish(t, "1.1.0")
	_, err = w.queue.Reject(t.Context(), rejected.ReleaseID, w.reviewer, "the homepage is a phishing page")
	require.NoError(t, err)

	approvals := w.auditDetails(t, "release.approve")
	require.Len(t, approvals, 1)
	require.Equal(t, "merchant-mode", approvals[0]["plugin"])
	require.Equal(t, "1.0.0", approvals[0]["version"])
	require.Equal(t, approved.SHA256, approvals[0]["sha256"],
		"the audit row must name the exact hash that went live")
	require.Equal(t, "checked the source", approvals[0]["note"])

	rejections := w.auditDetails(t, "release.reject")
	require.Len(t, rejections, 1)
	require.Equal(t, "1.1.0", rejections[0]["version"])
	require.Equal(t, "the homepage is a phishing page", rejections[0]["reason"])
}
