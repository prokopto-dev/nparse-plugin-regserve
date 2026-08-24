package release_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
)

// TestTrustOf_AnAccountNobodyHasAssessed_IsAtTheFloor.
//
// No row means `new`, and inventing a row at first sign-in would make "never assessed" and
// "assessed and found ordinary" the same state — which is the difference between a default and a
// judgement.
func TestTrustOf_AnAccountNobodyHasAssessed_IsAtTheFloor(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("bytes"))

	got, err := w.pub.TrustOf(t.Context(), w.owner)
	require.NoError(t, err)
	require.Equal(t, release.TrustNew, got)
}

// TestSetTrust_RecordsBothTiersAndTheReason.
//
// account_trust is an upsert and therefore carries only the CURRENT tier. The history lives in
// audit_log, which nothing can edit, and "raised to trusted" and "lowered to trusted" are
// different events that the row has to distinguish without anybody reconstructing it from
// timestamps.
func TestSetTrust_RecordsBothTiersAndTheReason(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("bytes"))

	require.NoError(t, w.pub.SetTrust(t.Context(), w.maintainer, release.TrustTrusted,
		w.owner, "has published six releases and answered every review"))

	got, err := w.pub.TrustOf(t.Context(), w.maintainer)
	require.NoError(t, err)
	require.Equal(t, release.TrustTrusted, got)

	details := w.auditDetails(t, "trust.set")
	require.Len(t, details, 1)
	require.Equal(t, "new", details[0]["from"])
	require.Equal(t, "trusted", details[0]["to"])
	require.Equal(t, "has published six releases and answered every review", details[0]["reason"])

	// Lowering it again records the other direction.
	require.NoError(t, w.pub.SetTrust(t.Context(), w.maintainer, release.TrustBlocked,
		w.owner, "the account was compromised"))

	details = w.auditDetails(t, "trust.set")
	require.Len(t, details, 2)

	var lowered map[string]any
	for _, d := range details {
		if d["to"] == "blocked" {
			lowered = d
		}
	}
	require.NotNil(t, lowered)
	require.Equal(t, "trusted", lowered["from"],
		"the row must say what the tier was BEFORE, or a change reads as a first assessment")
}

// TestSetTrust_WithNoReason_IsRefused.
//
// A tier with no stated reason is one nobody can review later, and raising somebody to trusted is
// the decision that most needs to be explainable a year afterwards.
func TestSetTrust_WithNoReason_IsRefused(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("bytes"))

	for _, note := range []string{"", "   ", "\t\n"} {
		require.ErrorIs(t,
			w.pub.SetTrust(t.Context(), w.maintainer, release.TrustTrusted, w.owner, note),
			release.ErrNoTrustReason)
	}

	got, err := w.pub.TrustOf(t.Context(), w.maintainer)
	require.NoError(t, err)
	require.Equal(t, release.TrustNew, got, "a refused change altered the tier")
}

// TestSetTrust_AnUnknownAccount_IsNotFound — rather than a foreign-key message.
func TestSetTrust_AnUnknownAccount_IsNotFound(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("bytes"))

	require.ErrorIs(t,
		w.pub.SetTrust(t.Context(), "01ARZ3NDEKTSV4RRFFQ69G5FZZ", release.TrustTrusted, w.owner, "why"),
		release.ErrNoSuchAccount)
}

// TestParseTrust_TakesTheThreeTiersAndNothingElse.
func TestParseTrust_TakesTheThreeTiersAndNothingElse(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"blocked", "new", "trusted", " TRUSTED ", "Blocked"} {
		got, err := release.ParseTrust(in)
		require.NoError(t, err)
		require.True(t, got.Valid())
	}

	for _, in := range []string{"", "admin", "owner", "trustd", "super-trusted"} {
		_, err := release.ParseTrust(in)
		require.ErrorIs(t, err, release.ErrBadTrustLevel)
	}
}

// TestTrust_IsNeverRaisedAutomatically.
//
// ADR-0007: trust starts low for every new account and is never raised automatically, because a
// counter of successful publishes is a counter an attacker can run up — publish four harmless
// releases, earn the tier, publish the fifth.
//
// Asserted by publishing repeatedly and requiring the tier not to move. There is deliberately no
// code that would raise it; this is what notices if somebody adds some.
func TestTrust_IsNeverRaisedAutomatically(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 version one"))
	w.approvedFirstRelease(t, "1.0.0")

	for _, version := range []string{"1.1.0", "1.2.0", "1.3.0", "1.4.0"} {
		w.body = []byte("PK\x03\x04 version " + version)
		out, err := w.publish(t, w.submit(t, func(r *release.RawSubmission) { r.Version = version }), "k-"+version)
		require.NoError(t, err)
		require.Equal(t, release.StatePending, out.State)
		w.approve(t, out.ReleaseID)
	}

	got, err := w.pub.TrustOf(t.Context(), w.owner)
	require.NoError(t, err)
	require.Equal(t, release.TrustNew, got,
		"five approved releases raised the account's tier; trust must be a judgement a human makes")
}

// TestPublish_AnUntrustedAccountsCleanVersionBump_SaysTheTierIsWhy.
//
// THE BUG THIS PINS was reported as "every push waits for approval even after the id has been
// approved, like it thinks every time is the first time". Nothing was wrong: no quarantine rule
// fires on this submission, the plugin already has an approved release, and the account is simply
// at the floor -- which is the default for an account nobody has assessed. What made it look like
// a defect is that the row said only "awaiting human review", so the one fact that explains it
// appeared on no surface at all.
//
// The assertions are the two halves that were indistinguishable: the reason list is EMPTY, so this
// is not the first-release rule and not a quarantine rule, AND the note names the tier.
func TestPublish_AnUntrustedAccountsCleanVersionBump_SaysTheTierIsWhy(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 the first release"))

	first, err := w.publish(t, w.submit(t, nil), "untrusted-1")
	require.NoError(t, err)
	require.Equal(t, release.StatePending, first.State)
	require.Contains(t, first.Reasons, release.ReasonFirstRelease.String(),
		"the first appearance of an id always gets a human")
	w.approve(t, first.ReleaseID)

	// The second release. Same host, a version that advances, bytes that hash to what was
	// submitted, and a plugin that is already listed -- so the ONLY thing between it and the index
	// is that nobody has marked this account trusted.
	w.body = []byte("PK\x03\x04 the second release")

	second, err := w.publish(t, w.submit(t, func(raw *release.RawSubmission) {
		raw.Version = "1.1.0"
		raw.ArtifactSHA256 = w.truth()
	}), "untrusted-2")
	require.NoError(t, err)

	require.True(t, second.Verified, "the artifact was fetched and hashed")
	require.Equal(t, release.StatePending, second.State)
	require.Empty(t, second.Reasons,
		"no rule fired: this is not the first release and nothing about the change is unusual")
	require.Contains(t, second.Review, "has not marked the submitting account trusted",
		"the note names the tier, which is the only reason this release is waiting")

	// And the same sentence is on the row a reviewer and the author both read, not only in the
	// answer the publishing workflow happened to receive.
	row, err := w.db.Read().GetReleaseByID(t.Context(), second.ReleaseID)
	require.NoError(t, err)
	require.NotNil(t, row.ReviewNote)
	require.Equal(t, second.Review, *row.ReviewNote)
}

// TestPublish_ATrustedAccountsCleanVersionBump_DoesNotSayItIsWaiting.
//
// The other side of the same branch: the note on an automatic publish must not be the untrusted
// sentence, or a listing that went live would explain itself as one that did not.
func TestPublish_ATrustedAccountsCleanVersionBump_DoesNotSayItIsWaiting(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 the first release"))

	first, err := w.publish(t, w.submit(t, nil), "trusted-1")
	require.NoError(t, err)
	w.approve(t, first.ReleaseID)
	w.setTrust(t, w.owner, release.TrustTrusted)

	w.body = []byte("PK\x03\x04 the second release")
	second, err := w.publish(t, w.submit(t, func(raw *release.RawSubmission) {
		raw.Version = "1.1.0"
		raw.ArtifactSHA256 = w.truth()
	}), "trusted-2")
	require.NoError(t, err)

	require.Equal(t, release.StateApproved, second.State)
	require.NotContains(t, second.Review, "has not marked the submitting account trusted")
	require.Contains(t, second.Review, "published automatically")
}
