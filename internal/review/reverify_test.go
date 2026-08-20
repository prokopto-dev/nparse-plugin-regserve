package review_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
)

// TestReverify_RepairsAReleaseATransientOutageWouldOtherwiseHaveCost.
//
// This is the hole re-verification exists to close, and it is worth stating as a sequence:
// an artifact host is down for thirty seconds, the release is recorded pending with no hash
// (correctly — "we could not check" must stay visible), and a version is used once per plugin
// EVER. Without a repair, that thirty seconds permanently consumes 1.0.0 and the author's only
// remedy is to publish 1.0.1 — a version number burned by somebody else's bad afternoon, with
// their git tag and the registry now disagreeing.
func TestReverify_RepairsAReleaseATransientOutageWouldOtherwiseHaveCost(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	w.available = false
	out := w.publish(t, "1.0.0")
	require.False(t, out.Verified)
	require.Empty(t, out.SHA256)

	// It cannot be approved while unverified: the hash is the security boundary and there is none.
	_, err := w.queue.Approve(t.Context(), out.ReleaseID, w.reviewer, "")
	require.ErrorIs(t, err, review.ErrNotVerified)

	// The upstream comes back.
	w.available = true

	got, err := w.queue.Reverify(t.Context(), out.ReleaseID, w.reviewer)
	require.NoError(t, err)
	require.True(t, got.Verified)
	require.NotEmpty(t, got.SHA256)
	require.Equal(t, "1.0.0", got.Version, "the SAME version; that is the whole point")

	// The hash reached the row, with the record of when this server computed it. The database's
	// release_a_stored_hash_was_verified_or_imported CHECK is what ties those two together.
	row, err := w.db.Read().GetReleaseByID(t.Context(), out.ReleaseID)
	require.NoError(t, err)
	require.NotNil(t, row.ArtifactSha256)
	require.Equal(t, got.SHA256, *row.ArtifactSha256)
	require.NotNil(t, row.VerifiedAt)
	require.NotNil(t, row.ArtifactBytes)

	// And now it can be approved, under its original version.
	_, err = w.queue.Approve(t.Context(), out.ReleaseID, w.reviewer, "")
	require.NoError(t, err)
	require.Equal(t, []string{"merchant-mode@1.0.0"}, w.listed(t))
}

// TestReverify_CanOnlyEverFillInABlank.
//
// THE LOAD-BEARING REFUSAL. A stored hash is what every installed client verifies an artifact
// against before extracting it. A path that could RECOMPUTE one is a path that could swap the
// bytes behind a listing with nobody reviewing the swap — which is the single property this
// service exists to keep. The repair for a transient outage must not be the thing that breaks it.
//
// Refused in two places: here, and by `verified_at IS NULL` in the statement's own WHERE clause.
func TestReverify_CanOnlyEverFillInABlank(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	out := w.publish(t, "1.0.0")
	require.True(t, out.Verified)

	original := out.SHA256

	// The artifact at that URL is now different bytes — a re-uploaded release asset, which is
	// precisely the attack the recorded hash exists to stop.
	w.serving = []byte("PK\x03\x04 DIFFERENT bytes, swapped after the fact")

	_, err := w.queue.Reverify(t.Context(), out.ReleaseID, w.reviewer)
	require.ErrorIs(t, err, review.ErrAlreadyVerified)

	row, err := w.db.Read().GetReleaseByID(t.Context(), out.ReleaseID)
	require.NoError(t, err)
	require.Equal(t, original, *row.ArtifactSha256,
		"a stored hash was recomputed; the bytes behind a listing could be swapped without review")
}

// TestReverify_WhenTheArtifactIsStillUnreachable_IsNotASuccess.
//
// The same rule as the original publish, in a place it would be easy to forget: a repair that
// reported success because it ran is a confident mistake.
func TestReverify_WhenTheArtifactIsStillUnreachable_IsNotASuccess(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	w.available = false
	out := w.publish(t, "1.0.0")

	got, err := w.queue.Reverify(t.Context(), out.ReleaseID, w.reviewer)

	// NOT an error: the attempt happened and its outcome is a fact worth recording.
	require.NoError(t, err)
	require.False(t, got.Verified)
	require.Empty(t, got.SHA256)
	require.True(t, strings.HasPrefix(got.Note, "not verified: "),
		"a failed reverification does not say the artifact was not verified: %q", got.Note)

	row, err := w.db.Read().GetReleaseByID(t.Context(), out.ReleaseID)
	require.NoError(t, err)
	require.Nil(t, row.ArtifactSha256)
	require.Nil(t, row.VerifiedAt)
	require.Equal(t, "pending", w.state(t, out.ReleaseID))
}

// TestReverify_EveryAttempt_IsRecorded.
//
// Three failures in a row is a different story from one, and a queue that recorded only successes
// would hide exactly the pattern worth noticing. audit_log is append-only, so this is the
// permanent record of how many times this server tried and what it found.
func TestReverify_EveryAttempt_IsRecorded(t *testing.T) {
	t.Parallel()

	// An advancing clock, because this test's subject is the SEQUENCE. Under a frozen one every
	// audit row shares a recorded_at and the order falls to the ULID tiebreaker, whose low bits
	// are random -- so "two failures then a success" would be untestable rather than untrue.
	w := newSteppingWorld(t)

	w.available = false
	out := w.publish(t, "1.0.0")

	_, err := w.queue.Reverify(t.Context(), out.ReleaseID, w.reviewer)
	require.NoError(t, err)
	_, err = w.queue.Reverify(t.Context(), out.ReleaseID, w.reviewer)
	require.NoError(t, err)

	w.available = true
	_, err = w.queue.Reverify(t.Context(), out.ReleaseID, w.reviewer)
	require.NoError(t, err)

	attempts := w.auditDetails(t, "release.reverify")
	require.Len(t, attempts, 3, "a failed reverification was not recorded")
	require.Equal(t, false, attempts[0]["verified"])
	require.Equal(t, false, attempts[1]["verified"])
	require.Equal(t, true, attempts[2]["verified"])
	require.NotEmpty(t, attempts[2]["sha256"])
}

// TestReverify_AnUnknownOrDecidedRelease_IsRefused.
func TestReverify_AnUnknownOrDecidedRelease_IsRefused(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	_, err := w.queue.Reverify(t.Context(), "01ARZ3NDEKTSV4RRFFQ69G5FZZ", w.reviewer)
	require.ErrorIs(t, err, review.ErrNoSuchRelease)

	out := w.publish(t, "1.0.0")
	_, err = w.queue.Reject(t.Context(), out.ReleaseID, w.reviewer, "no")
	require.NoError(t, err)

	_, err = w.queue.Reverify(t.Context(), out.ReleaseID, w.reviewer)
	require.ErrorIs(t, err, review.ErrNotPending)
}
