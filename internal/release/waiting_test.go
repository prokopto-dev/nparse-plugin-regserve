package release_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// A plugin has at most ONE release waiting for review, and it is the one submitted most recently.
//
// The defect these cover was reported from the review queue: approving a new plugin showed the same
// plugin id several times, each row badged "first release of this id". The cause was that nothing
// stopped a plugin accumulating pending rows -- release_plugin_version_key is (plugin_id, version),
// so a second submission is a second row -- and the queue faithfully showed what was there.
//
// The half that is not cosmetic is the reason these tests are in the PUBLISH package rather than in
// the review one: approving is not ordered. A 1.0.1 left waiting after 1.0.2 goes live can be
// approved afterwards, and SupersedeApprovedRelease will retire 1.0.2 to do it -- rolling the
// listing backwards past a version check that only ever runs at submission.

// TestPublish_ASecondSubmission_LeavesOneReleaseWaiting.
func TestPublish_ASecondSubmission_LeavesOneReleaseWaiting(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 version one"))

	first, err := w.publish(t, w.submit(t, nil), "key-1")
	require.NoError(t, err)
	require.Equal(t, release.StatePending, first.State)

	w.body = []byte("PK\x03\x04 version two")
	second, err := w.publish(t,
		w.submit(t, func(r *release.RawSubmission) { r.Version = "1.0.1"; r.ArtifactSHA256 = w.truth() }),
		"key-2")
	require.NoError(t, err)
	require.Equal(t, release.StatePending, second.State)

	require.Equal(t, "superseded", w.stateOf(t, first.ReleaseID),
		"the earlier submission is still waiting; the queue shows this plugin twice")
	require.Equal(t, "pending", w.stateOf(t, second.ReleaseID))

	// History is KEPT (ADR-0010). Superseding is a state change and never a delete -- a BEFORE
	// DELETE trigger would abort it, so this asserts the row is still there to be read.
	require.Equal(t, 2, w.releaseCount(t))

	// And the outcome SAYS so. A publishing workflow that quietly cancelled its author's own
	// earlier submission is the same class of invisible change as a listing that moved silently.
	require.Equal(t, []string{first.ReleaseID}, second.SupersededPending)
}

// TestPublish_ASupersededSubmission_KeepsWhyItWasWaiting.
//
// review_note is the only explanation the author ever gets for a release that did not go live, and
// audit_log is append-only -- so the retirement is recorded as a NEW ROW rather than by overwriting
// the reason. RecordReleaseVerification in db/queries/review.sql documents what it cost the last
// time a statement in this codebase rewrote that column.
func TestPublish_ASupersededSubmission_KeepsWhyItWasWaiting(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 version one"))

	first, err := w.publish(t, w.submit(t, nil), "key-1")
	require.NoError(t, err)
	require.NotEmpty(t, first.Review, "the fixture must produce a release that is waiting for a reason")

	w.body = []byte("PK\x03\x04 version two")
	_, err = w.publish(t,
		w.submit(t, func(r *release.RawSubmission) { r.Version = "1.0.1"; r.ArtifactSHA256 = w.truth() }),
		"key-2")
	require.NoError(t, err)

	notes := storetest.Column(t, w.db, `SELECT review_note FROM "release" WHERE id = ?`, first.ReleaseID)
	require.Equal(t, []string{first.Review}, notes,
		"superseding rewrote the quarantine reasons, which are all the author is ever told")

	details := w.auditDetails(t, "release.superseded")
	require.Len(t, details, 1)
	require.Equal(t, w.plugin, details[0]["plugin"])
	require.Equal(t, "1.0.0", details[0]["version"])
	require.Equal(t, "1.0.1", details[0]["superseded_by"])
	require.NotEmpty(t, details[0]["reason"])

	subjects := storetest.Column(t, w.db,
		`SELECT subject_id FROM audit_log WHERE action = 'release.superseded'`)
	require.Equal(t, []string{first.ReleaseID}, subjects,
		"the row is recorded against the plugin, so the retired release's own page never shows it")
}

// TestPublish_AnAutoPublishedRelease_RetiresTheOneStillWaiting.
//
// The same hole on the path with no human in it. A trusted owner's 1.0.2 goes live automatically
// while their 1.0.1 sits in the queue; approving the 1.0.1 afterwards would make it the listing.
func TestPublish_AnAutoPublishedRelease_RetiresTheOneStillWaiting(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 version one"))
	w.approvedFirstRelease(t, "1.0.0")

	// Submitted while the account is still untrusted, so it goes to review and waits there.
	w.body = []byte("PK\x03\x04 version two")
	waiting, err := w.publish(t,
		w.submit(t, func(r *release.RawSubmission) { r.Version = "1.0.1"; r.ArtifactSHA256 = w.truth() }),
		"key-waiting")
	require.NoError(t, err)
	require.Equal(t, release.StatePending, waiting.State)

	w.setTrust(t, w.owner, release.TrustTrusted)

	// The SAME LENGTH as what is live, so the size rule does not fire and this test is about the
	// thing it says it is about.
	w.body = []byte("PK\x03\x04 version six")
	live, err := w.publish(t,
		w.submit(t, func(r *release.RawSubmission) { r.Version = "1.0.2"; r.ArtifactSHA256 = w.truth() }),
		"key-live")
	require.NoError(t, err)
	require.Equal(t, release.StateApproved, live.State,
		"the fixture must auto-publish, or this test proves nothing about that path")

	require.Equal(t, "superseded", w.stateOf(t, waiting.ReleaseID),
		"a release left waiting behind a live one can still be approved, and would downgrade it")
	require.Equal(t, []string{waiting.ReleaseID}, live.SupersededPending)
	require.Equal(t, []string{w.plugin + "@1.0.2"}, w.listed(t))
}
