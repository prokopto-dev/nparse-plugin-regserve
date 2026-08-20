package release_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// THE WHOLE PIPELINE, END TO END, for the first time.
//
// Every other test in this repository exercises one link: the fetcher hashes bytes, the publisher
// records a release, the queue approves one. Each of those can be right while the chain is broken
// — a claim that grants the wrong role, a publish that cannot find the plugin it just claimed, an
// approval that does not reach the index.
//
// This walks it: claim an id, publish to it, watch it wait for a human because it is a first
// release, approve it, and see it in what the index would render. Then bump the version as a
// trusted owner and watch the second one go live on its own.
func TestLifecycle_ClaimPublishReviewList(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 the first release of a brand new plugin"))
	owners := ownership.New(w.db, clock.Fixed{T: now})

	const id = "brand-new-plugin"

	// --- claim -------------------------------------------------------------------------------
	//
	// Session-only in the API; here, the service behind it. Before this, an unclaimed id was a 404
	// on the publish endpoint and onboarding needed a maintainer at the database.
	pluginID, err := core.ParsePluginID(id)
	require.NoError(t, err)
	require.NoError(t, owners.ClaimID(t.Context(), ownership.Claim{
		PluginID: pluginID,
		Name:     "Brand New Plugin",
		Homepage: "https://github.com/somebody/brand-new-plugin",
	}, w.owner))

	// It is claimed and held, and it is NOT in the index: a claim gets you a row and an owner
	// grant, never a listing.
	require.Empty(t, w.listedAll(t))

	// --- publish -----------------------------------------------------------------------------
	//
	// As a TRUSTED owner, so that the review below is not happening merely because nobody trusts
	// them. It is the first appearance of the id, and nothing bypasses that.
	w.setTrust(t, w.owner, release.TrustTrusted)

	first, err := w.pub.Publish(t.Context(), release.Request{
		Submission:     w.submitFor(t, id, "1.0.0"),
		AccountID:      w.owner,
		IdempotencyKey: "lifecycle-1",
	})
	require.NoError(t, err)

	require.True(t, first.Verified, "the artifact was fetched and hashed")
	require.Equal(t, release.StatePending, first.State)
	require.Contains(t, first.Reasons, release.ReasonFirstRelease.String(),
		"a trusted owner's FIRST release of an id published without a human")
	require.Empty(t, w.listedAll(t))

	// --- review ------------------------------------------------------------------------------
	w.approveOn(t, id, first.ReleaseID)
	require.Equal(t, []string{id + "@1.0.0"}, w.listedAll(t))

	// --- the second release ------------------------------------------------------------------
	//
	// Now the id has an approved release, the owner is trusted, and nothing about the change is
	// unusual — so this is the one case in the whole design that reaches users without a human
	// reading it, and it is the one the trust model calls the price of the automation.
	w.body = []byte("PK\x03\x04 the second release of that same plugin")

	second, err := w.pub.Publish(t.Context(), release.Request{
		Submission:     w.submitFor(t, id, "1.1.0"),
		AccountID:      w.owner,
		IdempotencyKey: "lifecycle-2",
	})
	require.NoError(t, err)

	require.Equal(t, release.StateApproved, second.State)
	require.Empty(t, second.Reasons)
	require.Equal(t, first.ReleaseID, second.Superseded)
	require.Equal(t, []string{id + "@1.1.0"}, w.listedAll(t))

	// The hash in the index is the one THIS SERVER computed, which is where the whole phase
	// started.
	rows, err := w.db.Read().ListListings(t.Context())
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.NotNil(t, rows[0].ArtifactSha256)
	require.Equal(t, second.SHA256, *rows[0].ArtifactSha256)

	// And the first release is kept, superseded rather than deleted.
	require.Equal(t, "superseded", w.stateOf(t, first.ReleaseID))
}

// submitFor builds a valid submission for an arbitrary plugin id.
func (w *world) submitFor(t *testing.T, pluginID, version string) release.Submission {
	t.Helper()

	sub, err := release.NewSubmission(release.RawSubmission{
		PluginID:       pluginID,
		Version:        version,
		ArtifactURL:    w.srv.URL + "/" + pluginID + "-" + version + ".whl",
		ArtifactSHA256: w.truth(),
		SDKSpecifier:   ">=1.0,<2",
	})
	require.NoError(t, err)
	return sub
}

// approveOn approves a release of any plugin, the way a reviewer would.
func (w *world) approveOn(t *testing.T, pluginID, releaseID string) {
	t.Helper()

	require.NoError(t, w.db.Tx(t.Context(), func(q *sqlitegen.Queries) error {
		if _, err := q.SupersedeApprovedRelease(t.Context(), pluginID); err != nil {
			return err
		}
		changed, err := q.ApproveRelease(t.Context(), sqlitegen.ApproveReleaseParams{
			ReviewedAt: ptr(core.MicrosFromTime(now).Int64()),
			ID:         releaseID,
		})
		if err != nil {
			return err
		}
		require.Equal(t, int64(1), changed)
		return nil
	}))
}

// listedAll is every plugin the index would render, not just the fixture's own.
func (w *world) listedAll(t *testing.T) []string {
	t.Helper()

	rows, err := w.db.Read().ListListings(t.Context())
	require.NoError(t, err)

	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ID+"@"+r.Version)
	}
	return out
}
