package release_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
)

// The quarantine rules and trust, tested THROUGH THE PUBLISH PATH against a real database.
//
// Testing evaluateQuarantine directly would be easier and would prove less: what matters is not
// that a pure function returns a list, but that a release which triggers a rule does not reach the
// index — and that one which triggers none, from a trusted owner, does.

// approvedFirstRelease gets a plugin into the state every rule below compares against: one
// approved release, so the plugin is no longer on its first appearance.
func (w *world) approvedFirstRelease(t *testing.T, version string) release.Outcome {
	t.Helper()

	out, err := w.publish(t, w.submit(t, func(r *release.RawSubmission) { r.Version = version }), "seed-"+version)
	require.NoError(t, err)

	w.approve(t, out.ReleaseID)
	return out
}

// TestPublish_ATrustedOwnersVersionBump_PublishesWithoutAHuman.
//
// The whole point of trust, and the one path to a listing that no person looks at. Everything else
// in this file is a reason that path must not be taken.
func TestPublish_ATrustedOwnersVersionBump_PublishesWithoutAHuman(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 version one"))
	first := w.approvedFirstRelease(t, "1.0.0")
	w.setTrust(t, w.owner, release.TrustTrusted)

	// The SAME LENGTH as the first release. The size rule fires on a change past half, and a
	// fixture that tripped it by accident would make this test pass for the wrong reason -- which
	// is exactly what the first draft of it did.
	w.body = []byte("PK\x03\x04 version two")

	out, err := w.publish(t, w.submit(t, func(r *release.RawSubmission) { r.Version = "1.1.0" }), "bump")
	require.NoError(t, err)

	require.Equal(t, release.StateApproved, out.State)
	require.True(t, out.Verified)
	require.Empty(t, out.Reasons)
	require.Equal(t, first.ReleaseID, out.Superseded,
		"an automatic publish must say what it retired")

	// It is in the index, and the release it replaced is kept.
	require.Equal(t, []string{"merchant-mode@1.1.0"}, w.listed(t))
	require.Equal(t, "superseded", w.stateOf(t, first.ReleaseID))

	// And the audit log says a machine did it. This is the row an incident review reads when the
	// question is "who approved these bytes" and the answer is "nobody did".
	detail := w.auditDetailFor(t, out.ReleaseID)
	require.Equal(t, true, detail["auto_published"])
	require.Equal(t, first.ReleaseID, detail["superseded"])
}

// TestPublish_EveryQuarantineRule_SendsAReleaseToAHumanDespiteTrust.
//
// Trust is a judgement about a PERSON; these are facts about a CHANGE. An owner who has published
// fifty good releases is exactly who an attacker wants to be when publishing the fifty-first, so
// every case below is run by a TRUSTED owner and must still be refused automation.
func TestPublish_EveryQuarantineRule_SendsAReleaseToAHumanDespiteTrust(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		arrange func(t *testing.T, w *world) release.Submission
		want    release.QuarantineReason
	}{
		{
			// The fetch ALSO fails here, and that is a limitation of the fixture rather than of
			// the rule: httptest's certificate covers 127.0.0.1, so a second hostname pointing at
			// the same server does not verify, and a hostname that both resolved and verified
			// would need a DNS server inside the test. What is asserted is that the host
			// difference is noticed; TestPublish_TheHostRuleReadsTheSubmittedURL covers the half
			// that matters most.
			name: "the artifact moved to a different host",
			arrange: func(t *testing.T, w *world) release.Submission {
				other := w.secondHost(t)
				return w.submit(t, func(r *release.RawSubmission) {
					r.Version = "1.1.0"
					r.ArtifactURL = other + "/merchant-mode.whl"
				})
			},
			want: release.ReasonHostChanged,
		},
		{
			name: "the artifact tripled in size",
			arrange: func(t *testing.T, w *world) release.Submission {
				w.body = []byte(repeat("PK\x03\x04 a much larger artifact ", 40))
				return w.submit(t, func(r *release.RawSubmission) { r.Version = "1.1.0" })
			},
			want: release.ReasonSizeDelta,
		},
		{
			name: "the artifact shrank by more than half",
			arrange: func(t *testing.T, w *world) release.Submission {
				w.body = []byte("PK")
				return w.submit(t, func(r *release.RawSubmission) { r.Version = "1.1.0" })
			},
			want: release.ReasonSizeDelta,
		},
		{
			name: "the version goes backwards",
			arrange: func(t *testing.T, w *world) release.Submission {
				w.body = []byte("PK\x03\x04 version two")
				return w.submit(t, func(r *release.RawSubmission) { r.Version = "0.9.0" })
			},
			want: release.ReasonVersionNotHigher,
		},
		{
			name: "the version cannot be ordered against the live one",
			arrange: func(t *testing.T, w *world) release.Submission {
				w.body = []byte("PK\x03\x04 version two")
				return w.submit(t, func(r *release.RawSubmission) { r.Version = "1.0.0rc2" })
			},
			want: release.ReasonVersionUncomparable,
		},
		{
			name: "the submitted hash does not match the bytes",
			arrange: func(t *testing.T, w *world) release.Submission {
				w.body = []byte("PK\x03\x04 version two")
				return w.submit(t, func(r *release.RawSubmission) {
					r.Version = "1.1.0"
					r.ArtifactSHA256 = flipOneHexDigit(w.truth())
				})
			},
			want: release.ReasonHashMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t, []byte("PK\x03\x04 version one"))
			w.approvedFirstRelease(t, "1.0.0")
			w.setTrust(t, w.owner, release.TrustTrusted)

			sub := tc.arrange(t, w)
			out, err := w.publish(t, sub, "quarantined")
			require.NoError(t, err)

			require.Equal(t, release.StatePending, out.State,
				"a trusted owner published automatically despite %s", tc.want)
			require.Contains(t, out.Reasons, tc.want.String())
			require.Contains(t, out.Review, tc.want.String())

			// The live release is untouched: 1.0.0 is still what the index serves.
			require.Equal(t, []string{"merchant-mode@1.0.0"}, w.listed(t))
		})
	}
}

// TestPublish_ANewPluginID_AlwaysGetsAHuman.
//
// ADR-0007's non-negotiable, asserted at the tier where it would be bypassed. The first appearance
// of an id is where impersonation is caught, and it is expressed as a quarantine REASON rather
// than as a branch in the trust arithmetic so that a later change to that arithmetic cannot
// forget it.
func TestPublish_ANewPluginID_AlwaysGetsAHuman(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 the very first release"))
	w.setTrust(t, w.owner, release.TrustTrusted)

	out, err := w.publish(t, w.submit(t, nil), "first")
	require.NoError(t, err)

	require.Equal(t, release.StatePending, out.State,
		"the first release of a plugin published without a human")
	require.Contains(t, out.Reasons, release.ReasonFirstRelease.String())
	require.True(t, out.Verified, "it was still fetched and hashed; it is just not listed")
	require.Empty(t, w.listed(t))
}

// TestPublish_AnUntrustedOwner_NeverPublishesAutomatically.
//
// The other half of the trust rule: a clean version bump with nothing wrong still waits, because
// the account has not been assessed. `new` is the floor and the default.
func TestPublish_AnUntrustedOwner_NeverPublishesAutomatically(t *testing.T) {
	t.Parallel()

	for _, tier := range []release.Trust{release.TrustNew, ""} {
		t.Run("tier "+string(tier), func(t *testing.T) {
			t.Parallel()

			w := newWorld(t, []byte("PK\x03\x04 version one"))
			w.approvedFirstRelease(t, "1.0.0")
			if tier != "" {
				w.setTrust(t, w.owner, tier)
			}

			w.body = []byte("PK\x03\x04 version two")
			out, err := w.publish(t, w.submit(t, func(r *release.RawSubmission) { r.Version = "1.1.0" }), "bump")
			require.NoError(t, err)

			require.Equal(t, release.StatePending, out.State)
			require.Empty(t, out.Reasons, "nothing was wrong with it; it simply is not trusted")
			require.Equal(t, []string{"merchant-mode@1.0.0"}, w.listed(t))
		})
	}
}

// TestPublish_ABlockedAccount_IsRefusedBeforeAnythingIsDownloaded.
//
// Not merely quarantined: refused. And refused BEFORE the fetch, so a blocked account cannot make
// this server spend forty-five seconds and fifty megabytes on their behalf — an endpoint that
// downloads a stranger's URL for a stranger it has already refused is a bandwidth amplifier with
// an authentication step in front of it.
func TestPublish_ABlockedAccount_IsRefusedBeforeAnythingIsDownloaded(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 bytes"))
	w.setTrust(t, w.owner, release.TrustBlocked)

	before := w.fetchCount()

	_, err := w.publish(t, w.submit(t, nil), "blocked")
	require.ErrorIs(t, err, release.ErrAccountBlocked)

	require.Zero(t, w.releaseCount(t), "a blocked account's publish wrote a row")
	require.Equal(t, before, w.fetchCount(),
		"the artifact was downloaded for an account that had already been refused")
}

// TestPublish_MultipleRules_AreAllReported.
//
// A release that changed host AND jumped in size AND went backwards is a different story from one
// that only changed host. A reviewer shown a single reason investigates a single thing.
func TestPublish_MultipleRules_AreAllReported(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 version one"))
	w.approvedFirstRelease(t, "1.0.0")
	w.setTrust(t, w.owner, release.TrustTrusted)

	// The same host, so the artifact still FETCHES: the size rule needs bytes to measure, and a
	// case where the fetch failed would be testing one reason wearing three coats.
	w.body = []byte("PK")

	out, err := w.publish(t, w.submit(t, func(r *release.RawSubmission) {
		r.Version = "0.9.0"
	}), "everything-wrong")
	require.NoError(t, err)

	require.Equal(t, release.StatePending, out.State)
	require.True(t, out.Verified, "the artifact was fetched; only the comparisons went wrong")
	require.ElementsMatch(t, []string{
		release.ReasonSizeDelta.String(),
		release.ReasonVersionNotHigher.String(),
	}, out.Reasons)

	// The note counts them, because a reviewer scanning a queue needs to know at a glance whether
	// a release has one problem or three.
	require.Contains(t, out.Review, "2 reasons:")

	detail := w.auditDetailFor(t, out.ReleaseID)
	require.Len(t, detail["quarantine"], 2)
}

func repeat(s string, n int) string {
	out := ""
	for range n {
		out += s
	}
	return out
}

// TestPublish_TheHostRuleReadsTheSubmittedURL_NotWhereTheRedirectLanded.
//
// A GitHub release asset redirects to a CDN whose hostname varies between requests. If the rule
// compared FINAL hosts it would fire on essentially every release, and a rule that fires every
// time is a rule reviewers learn to click past — which is worse than not having it, because it
// also hides the times it means something.
func TestPublish_TheHostRuleReadsTheSubmittedURL_NotWhereTheRedirectLanded(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 version one"))
	w.approvedFirstRelease(t, "1.0.0")
	w.setTrust(t, w.owner, release.TrustTrusted)

	// The artifact now arrives via a redirect, exactly as a real release asset does. The SUBMITTED
	// url is unchanged, so nothing about where the bytes ultimately came from should matter.
	w.redirectTo = "/actual/merchant-mode.whl"
	w.body = []byte("PK\x03\x04 version two")

	out, err := w.publish(t, w.submit(t, func(r *release.RawSubmission) { r.Version = "1.1.0" }), "redirected")
	require.NoError(t, err)

	require.True(t, out.Verified)
	require.Empty(t, out.Reasons,
		"a redirect changed where the bytes came from and the host rule noticed; it must read the "+
			"submitted url, which is the author's stable statement of where the artifact lives")
	require.Equal(t, release.StateApproved, out.State)
}
