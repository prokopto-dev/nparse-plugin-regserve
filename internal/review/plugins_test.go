package review_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// The moderation console, against a real database whose rows arrived through the real publish
// path — the same rule world_test.go states and for the same reason: a hand-inserted fixture can
// describe states publishing cannot produce, and assertions about those states say nothing.
//
// The subject of most of these is what delisting DOES NOT do. Removing a listing is easy to get
// right and easy to get catastrophically wrong in one direction: an id that stops being claimed is
// an id somebody else can take, and taking it means shipping an update to another author's users.
// So the tests read the claim, the owners and the release history back afterwards rather than
// trusting that a statement which said UPDATE did not do anything else.

// moderation builds the service under test against the shared fixture.
func moderation(w *world) *review.Plugins { return review.NewPlugins(w.db, fixedClock()) }

// TestPlugins_Delist_RemovesTheListingAndKeepsTheClaim is the invariant, read back from the
// database rather than inferred from the call returning nil.
func TestPlugins_Delist_RemovesTheListingAndKeepsTheClaim(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	mod := moderation(w)

	out := w.publish(t, "1.0.0")
	_, err := w.queue.Approve(t.Context(), out.ReleaseID, w.reviewer, "looks fine")
	require.NoError(t, err)
	require.Equal(t, []string{"merchant-mode@1.0.0"}, w.listed(t), "the fixture must start listed")

	require.NoError(t, mod.Delist(t.Context(), w.plugin, w.reviewer, "impersonates another plugin"))

	// GONE FROM THE INDEX, which is the whole point of the act.
	require.Empty(t, w.listed(t), "a delisted plugin must not render into the index")

	// AND STILL CLAIMED. Every one of these is a separate way the id could have been freed, and
	// each is checked rather than assumed: the row itself, the ownership grant, and the release
	// history that records what was approved and by whom.
	rows := storetest.Column(t, w.db, `SELECT count(*) FROM plugin WHERE id = ?`, w.plugin)
	require.Equal(t, []string{"1"}, rows, "the plugin row IS the claim and must survive delisting")

	owners := storetest.Column(t, w.db,
		`SELECT count(*) FROM plugin_owner WHERE plugin_id = ?`, w.plugin)
	require.Equal(t, []string{"1"}, owners, "delisting must not touch who holds the plugin")

	require.Equal(t, map[string]int{"approved": 1}, w.releaseStates(t),
		"delisting removes the listing, not the release history (ADR-0010)")

	// The listing state, as the console reads it back.
	got, err := mod.Get(t.Context(), w.plugin)
	require.NoError(t, err)
	require.True(t, got.Delisted)
	require.False(t, got.Listed(), "a delisted plugin is not listed")
	require.Equal(t, "impersonates another plugin", got.DelistedReason)
	require.Equal(t, "1.0.0", got.LiveVersion,
		"the release stays approved: the LISTING is what was removed, and that is what would come back")
}

// TestPlugins_Delist_RecordsThatItWasModerationAndNotAnOwner is the audit half.
//
// The `acted_as` key is the one a later incident review cannot reconstruct: an owner delisting
// their own plugin and a moderator delisting somebody else's write the same column, grants change
// afterwards, and the schema keeps no answer to "did they hold this plugin at the time".
func TestPlugins_Delist_RecordsThatItWasModerationAndNotAnOwner(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	mod := moderation(w)

	require.NoError(t, mod.Delist(t.Context(), w.plugin, w.reviewer, "malware in the wheel"))

	details := w.auditDetails(t, "plugin.delist")
	require.Len(t, details, 1, "delisting writes exactly one audit row")

	want := map[string]any{
		"acted_as":         "reviewer",
		"permission":       "plugin.moderate",
		"reason":           "malware in the wheel",
		"delisted_version": "",
	}
	require.Empty(t, cmp.Diff(want, details[0]))

	// And it names the account. The whole-value comparison above is on the detail object; the
	// actor is a column, and an audit row that did not name the reviewer would be the one thing
	// this table exists for going missing.
	actors := storetest.Column(t, w.db,
		`SELECT actor_kind || ':' || actor_account_id FROM audit_log WHERE action = 'plugin.delist'`)
	require.Equal(t, []string{"account:" + w.reviewer}, actors)
}

// TestPlugins_Delist_WithNoReason_IsRefused — a listing that vanishes unexplained looks like a bug.
func TestPlugins_Delist_WithNoReason_IsRefused(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	mod := moderation(w)

	for _, reason := range []string{"", "   ", "\t\n"} {
		require.ErrorIs(t, mod.Delist(t.Context(), w.plugin, w.reviewer, reason),
			review.ErrNoModerationReason, "whitespace is not a reason")
	}

	got, err := mod.Get(t.Context(), w.plugin)
	require.NoError(t, err)
	require.False(t, got.Delisted, "a refused delisting must not have delisted anything")
	require.Empty(t, w.auditDetails(t, "plugin.delist"), "and must not have written a row")
}

// TestPlugins_Delist_Twice_ReportsTheRace — two moderators with the page open is the normal case.
func TestPlugins_Delist_Twice_ReportsTheRace(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	mod := moderation(w)

	require.NoError(t, mod.Delist(t.Context(), w.plugin, w.reviewer, "the first reason"))
	require.ErrorIs(t, mod.Delist(t.Context(), w.plugin, w.owner, "the second reason"),
		review.ErrAlreadyDelisted)

	// The FIRST reason is the one on the row. A second delisting that quietly overwrote it would
	// leave a moderator believing the sentence there was theirs.
	got, err := mod.Get(t.Context(), w.plugin)
	require.NoError(t, err)
	require.Equal(t, "the first reason", got.DelistedReason)
	require.Len(t, w.auditDetails(t, "plugin.delist"), 1, "the refused attempt writes no row")
}

// TestPlugins_Relist_RestoresTheListingAndCarriesTheReasonIntoTheAudit.
//
// Relisting clears delisted_reason, so the audit row is the only surviving record of why the
// plugin was ever delisted. That is asserted here rather than assumed, because it is the sentence
// somebody will be looking for a year later.
func TestPlugins_Relist_RestoresTheListingAndCarriesTheReasonIntoTheAudit(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	mod := moderation(w)

	out := w.publish(t, "1.0.0")
	_, err := w.queue.Approve(t.Context(), out.ReleaseID, w.reviewer, "")
	require.NoError(t, err)

	require.NoError(t, mod.Delist(t.Context(), w.plugin, w.reviewer, "reported by a user"))
	require.Empty(t, w.listed(t))

	require.NoError(t, mod.Relist(t.Context(), w.plugin, w.reviewer, "the report was mistaken"))

	require.Equal(t, []string{"merchant-mode@1.0.0"}, w.listed(t),
		"relisting puts the still-approved release back in front of clients")

	got, err := mod.Get(t.Context(), w.plugin)
	require.NoError(t, err)
	require.False(t, got.Delisted)
	require.Empty(t, got.DelistedReason, "the stored reason is cleared with the timestamp")

	details := w.auditDetails(t, "plugin.relist")
	require.Len(t, details, 1)
	want := map[string]any{
		"acted_as":             "reviewer",
		"permission":           "plugin.moderate",
		"reason":               "the report was mistaken",
		"was_delisted_because": "reported by a user",
	}
	require.Empty(t, cmp.Diff(want, details[0]),
		"the delisting reason must survive into the row that undoes it: the column holding it is gone")
}

// TestPlugins_Relist_Refusals — a reason is required in this direction too, and there is nothing
// to put back for a plugin that was never delisted.
func TestPlugins_Relist_Refusals(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	mod := moderation(w)

	require.ErrorIs(t, mod.Relist(t.Context(), w.plugin, w.reviewer, "because"),
		review.ErrNotDelisted, "a listed plugin has no listing to restore")

	require.NoError(t, mod.Delist(t.Context(), w.plugin, w.reviewer, "a reason"))
	require.ErrorIs(t, mod.Relist(t.Context(), w.plugin, w.reviewer, "  "),
		review.ErrNoModerationReason)

	got, err := mod.Get(t.Context(), w.plugin)
	require.NoError(t, err)
	require.True(t, got.Delisted, "a refused relisting must not have relisted anything")
}

// TestPlugins_UnknownID_IsNotAModerationTarget.
func TestPlugins_UnknownID_IsNotAModerationTarget(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	mod := moderation(w)

	_, err := mod.Get(t.Context(), "no-such-plugin")
	require.ErrorIs(t, err, review.ErrNoSuchPlugin)
	require.ErrorIs(t, mod.Delist(t.Context(), "no-such-plugin", w.reviewer, "why"),
		review.ErrNoSuchPlugin)
	require.ErrorIs(t, mod.Relist(t.Context(), "no-such-plugin", w.reviewer, "why"),
		review.ErrNoSuchPlugin)
}

// TestPlugins_List_ShowsEveryStateIncludingTheOnesTheDirectoryHides.
//
// This is the reason the page exists. The public directory answers "what is publicly visible" and
// correctly drops a delisted id and an id with nothing approved, counting them so the shortfall is
// honest. A moderator needs the rows themselves, because those are the ones moderation is about.
func TestPlugins_List_ShowsEveryStateIncludingTheOnesTheDirectoryHides(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	mod := moderation(w)

	// Three plugins, one in each state a plugin can be in.
	out := w.publish(t, "1.0.0")
	_, err := w.queue.Approve(t.Context(), out.ReleaseID, w.reviewer, "")
	require.NoError(t, err)

	w.claim(t, "awaiting-plugin", "Never Published")

	w.claim(t, "gone-plugin", "Removed")
	goneOut := w.publishFor(t, "gone-plugin", "2.0.0")
	_, err = w.queue.Approve(t.Context(), goneOut.ReleaseID, w.reviewer, "")
	require.NoError(t, err)
	require.NoError(t, mod.Delist(t.Context(), "gone-plugin", w.reviewer, "withdrawn"))

	// The directory sees one. The console sees all three.
	require.Equal(t, []string{"merchant-mode@1.0.0"}, w.listed(t))

	got, err := mod.List(t.Context())
	require.NoError(t, err)

	type row struct {
		ID       string
		Listed   bool
		Delisted bool
		Live     string
	}
	summary := make([]row, 0, len(got))
	for _, l := range got {
		summary = append(summary, row{ID: l.ID, Listed: l.Listed(), Delisted: l.Delisted, Live: l.LiveVersion})
	}

	want := []row{
		{ID: "awaiting-plugin", Listed: false, Delisted: false, Live: ""},
		{ID: "gone-plugin", Listed: false, Delisted: true, Live: "2.0.0"},
		{ID: "merchant-mode", Listed: true, Delisted: false, Live: "1.0.0"},
	}
	require.Empty(t, cmp.Diff(want, summary),
		"every plugin, in id order, with its state told apart from the other two")
}

// TestPlugins_List_CarriesOwnersAndTheirTiers — what a moderator opens the page to find out.
func TestPlugins_List_CarriesOwnersAndTheirTiers(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	mod := moderation(w)

	got, err := mod.Get(t.Context(), w.plugin)
	require.NoError(t, err)
	require.Len(t, got.Owners, 1)
	require.Equal(t, w.owner, got.Owners[0].AccountID)
	require.Equal(t, "prokopto-dev", got.Owners[0].Handle)
	require.Equal(t, "owner", got.Owners[0].Role)
	require.Equal(t, review.TrustFloor, got.Owners[0].Trust,
		"an account nobody has assessed reads as the floor, never as blank")
}

// TestPlugins_TrustTier_AgreesWithTheServiceThatWritesIt is the gate on the one string this
// package borrows from internal/release.
//
// internal/review deliberately does not import internal/release — the two are kept apart so that
// "how much this registry trusts somebody's releases" and "who may approve them" cannot become one
// dependency. The cost is that the floor tier is spelled in both places. This is what makes that
// safe: the tier is set through the REAL service and read back through this one, so a rename on
// either side is a red test rather than a reviewer page quietly showing the wrong tier beside a
// control that changes it.
func TestPlugins_TrustTier_AgreesWithTheServiceThatWritesIt(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	mod := moderation(w)

	// The floor, with no row at all, is what release.TrustOf answers for an unassessed account.
	tier, err := w.pub.TrustOf(t.Context(), w.owner)
	require.NoError(t, err)
	require.Equal(t, review.TrustFloor, tier.String(),
		"review.TrustFloor and release's default for an account with no row must be one value")

	// And every tier the real service will write is read back unchanged.
	for _, want := range []release.Trust{release.TrustBlocked, release.TrustNew, release.TrustTrusted} {
		require.NoError(t, w.pub.SetTrust(t.Context(), w.owner, want, w.reviewer, "under test"))

		got, err := mod.Get(t.Context(), w.plugin)
		require.NoError(t, err)
		require.Len(t, got.Owners, 1)
		require.Equal(t, want.String(), got.Owners[0].Trust,
			"the console must show the tier the publish path will act on")
	}
}

// TestPlugins_SubmitterTier_ReachesTheQueueAndTheReleasePage.
//
// The same agreement, one surface further on: the tier a reviewer sees beside a submission is the
// one the publish path reads, and it is carried by the queue read rather than fetched separately —
// so the two cannot come from different moments.
func TestPlugins_SubmitterTier_ReachesTheQueueAndTheReleasePage(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	out := w.publish(t, "1.0.0")

	waiting, err := w.queue.List(t.Context())
	require.NoError(t, err)
	require.Len(t, waiting, 1)
	require.Equal(t, w.owner, waiting[0].Submitter.AccountID)
	require.Equal(t, "prokopto-dev", waiting[0].Submitter.Handle)
	require.Equal(t, review.TrustFloor, waiting[0].Submitter.Trust)

	require.NoError(t, w.pub.SetTrust(t.Context(), w.owner, release.TrustTrusted, w.reviewer, "vouched"))

	waiting, err = w.queue.List(t.Context())
	require.NoError(t, err)
	require.Len(t, waiting, 1)
	require.Equal(t, release.TrustTrusted.String(), waiting[0].Submitter.Trust)

	detail, err := w.queue.Detail(t.Context(), out.ReleaseID)
	require.NoError(t, err)
	require.Equal(t, release.TrustTrusted.String(), detail.Submitter.Trust,
		"the release page and the queue must agree about the submitter's tier")
	require.Equal(t, "prokopto-dev", detail.Submitter.Handle)
}

// TestPlugins_Approving_DoesNotChangeTrust is the separation, asserted rather than described.
//
// Approving a release and trusting its publisher are two decisions, and the second must never
// happen as a side effect of the first: an approve button that also raised trust would silently
// make every approval a judgement about every future release that account makes. ADR-0007 says a
// human decides, and a side effect is not a decision.
func TestPlugins_Approving_DoesNotChangeTrust(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	out := w.publish(t, "1.0.0")
	_, err := w.queue.Approve(t.Context(), out.ReleaseID, w.reviewer, "fine")
	require.NoError(t, err)

	tier, err := w.pub.TrustOf(t.Context(), w.owner)
	require.NoError(t, err)
	require.Equal(t, release.TrustNew, tier, "approving a release must not raise its publisher's tier")

	rows := storetest.Column(t, w.db, `SELECT count(*) FROM account_trust`)
	require.Equal(t, []string{"0"}, rows,
		"and must not write a trust row at all: 'never assessed' and 'assessed and found ordinary' "+
			"are different states")
	require.Empty(t, w.auditDetails(t, "trust.set"), "nor record a trust decision nobody made")
}
