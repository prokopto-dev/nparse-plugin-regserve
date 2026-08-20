package ownership_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// claimOf builds a valid claim for an id, which each test then perturbs.
func claimOf(t *testing.T, id string) ownership.Claim {
	t.Helper()

	parsed, err := core.ParsePluginID(id)
	require.NoError(t, err)
	return ownership.Claim{PluginID: parsed, Name: "A Plugin"}
}

// TestClaimID_RegistersTheIDAndMakesTheClaimantItsOwner.
//
// The owner role rather than maintainer: they must be able to hand the plugin on, and a plugin
// whose only holder cannot manage owners is one that can never be transferred.
func TestClaimID_RegistersTheIDAndMakesTheClaimantItsOwner(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	require.NoError(t, w.svc.ClaimID(t.Context(), claimOf(t, "brand-new-plugin"), w.other))

	role, held, err := w.svc.RoleOf(t.Context(), "brand-new-plugin", w.other)
	require.NoError(t, err)
	require.True(t, held)
	require.Equal(t, ownership.RoleOwner, role)
	require.True(t, role.CanManageOwners(),
		"a claimant who cannot manage owners holds a plugin they can never transfer")

	// It appears on their account page immediately, with nothing approved behind it — which is the
	// normal state of a new claim and is shown rather than hidden.
	mine, err := w.svc.Mine(t.Context(), w.other)
	require.NoError(t, err)
	require.Len(t, mine, 1)
	require.Equal(t, "brand-new-plugin", mine[0].ID)
	require.True(t, mine[0].Listed, "a claimed plugin is not delisted; it simply has no release")
	require.False(t, mine[0].HasApprovedRelease)
}

// TestClaimID_IsFirstComeAndSaysNothingAboutWhoHoldsIt.
//
// Ids are first-come, and the second claimant gets the same answer whoever the first was —
// including when the first was themselves. What the refusal deliberately does NOT say is who holds
// it: the list of LISTED ids is public because the index serves it, but which account holds an
// unlisted id is not, and answering that would make this endpoint a way to map ids to people.
func TestClaimID_IsFirstComeAndSaysNothingAboutWhoHoldsIt(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	require.NoError(t, w.svc.ClaimID(t.Context(), claimOf(t, "contested"), w.owner))

	err := w.svc.ClaimID(t.Context(), claimOf(t, "contested"), w.other)
	require.ErrorIs(t, err, ownership.ErrAlreadyClaimed)
	require.NotContains(t, err.Error(), w.owner, "the refusal named the account that holds the id")

	// The same answer for the holder themselves, so a caller cannot use the difference to work out
	// whether an id is theirs.
	require.ErrorIs(t,
		w.svc.ClaimID(t.Context(), claimOf(t, "contested"), w.owner),
		ownership.ErrAlreadyClaimed)

	// And the first claimant still holds it: a refused second claim changed nothing.
	role, held, err := w.svc.RoleOf(t.Context(), "contested", w.owner)
	require.NoError(t, err)
	require.True(t, held)
	require.Equal(t, ownership.RoleOwner, role)
}

// TestClaimID_AnIDThisRegistryAlreadyCarries_IsRefused.
//
// The seed importer creates plugin rows with no owners — ownership is imported separately — so
// there are claimed ids nobody holds. They are still CLAIMED, and letting somebody register one
// would hand them a plugin whose users are already installing releases.
func TestClaimID_AnIDThisRegistryAlreadyCarries_IsRefused(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	// w.plugin exists from the fixture with an owner grant; strip the grant so the row is a
	// claimed id with nobody holding it, which is exactly the imported shape.
	storetest.Exec(t, w.db, `DELETE FROM plugin_owner WHERE plugin_id = ?`, w.plugin)

	require.ErrorIs(t,
		w.svc.ClaimID(t.Context(), claimOf(t, w.plugin), w.other),
		ownership.ErrAlreadyClaimed,
		"an id with no owner was claimable; ids are never recycled, and an ownerless one is not free")
}

// TestClaimID_ADelistedID_IsStillClaimed.
//
// Delisting clears the LISTING and keeps the CLAIM. An id that became available again after a
// delisting would be the most direct route there is to shipping an update to somebody else's
// users — they already have the plugin installed under that id.
func TestClaimID_ADelistedID_IsStillClaimed(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	require.NoError(t, w.svc.ClaimID(t.Context(), claimOf(t, "retired-plugin"), w.owner))

	storetest.Exec(t, w.db,
		`UPDATE plugin SET delisted_at = ?, delisted_reason = ? WHERE id = ?`,
		1, "the author retired it", "retired-plugin")

	require.ErrorIs(t,
		w.svc.ClaimID(t.Context(), claimOf(t, "retired-plugin"), w.other),
		ownership.ErrAlreadyClaimed)
}

// TestClaimID_RefusesListingDetailsAListingCannotCarry.
//
// Every one of these is rendered in a desktop application and served to every client through the
// index, so each is hostile input even though none of it looks structural.
func TestClaimID_RefusesListingDetailsAListingCannotCarry(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*ownership.Claim)
	}{
		{"no name", func(c *ownership.Claim) { c.Name = "" }},
		{"a name that is only whitespace", func(c *ownership.Claim) { c.Name = "   \t " }},
		{
			"a name with an escape sequence",
			func(c *ownership.Claim) { c.Name = "Plugin\x1b[31m" },
		},
		{
			"a description with a control character",
			func(c *ownership.Claim) { c.Description = "does things\x00" },
		},
		{
			"a name over the cap",
			func(c *ownership.Claim) { c.Name = strings.Repeat("a", ownership.MaxPluginNameBytes+1) },
		},
		{
			"a description over the cap",
			func(c *ownership.Claim) {
				c.Description = strings.Repeat("a", ownership.MaxPluginDescriptionBytes+1)
			},
		},
		{
			// Not a homepage. It is an instruction to whatever renders the link, and this registry
			// has no way to know what a given client version does with one.
			"a javascript homepage",
			func(c *ownership.Claim) { c.Homepage = "javascript:alert(1)" },
		},
		{"a data homepage", func(c *ownership.Claim) { c.Homepage = "data:text/html,<script>x</script>" }},
		{"a file homepage", func(c *ownership.Claim) { c.Homepage = "file:///etc/passwd" }},
		{"an http homepage", func(c *ownership.Claim) { c.Homepage = "http://example.com" }},
		{"a homepage naming no host", func(c *ownership.Claim) { c.Homepage = "https://" }},
		{
			// Published to every client, cached, unrecallable — the same reason artifact_url
			// refuses them.
			"a homepage carrying credentials",
			func(c *ownership.Claim) { c.Homepage = "https://tok@example.com" },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t)
			claim := claimOf(t, "some-plugin")
			tc.mutate(&claim)

			require.ErrorIs(t, w.svc.ClaimID(t.Context(), claim, w.other), ownership.ErrBadListing)

			// Nothing was claimed, so the id is still available to whoever gets it right.
			_, held, err := w.svc.RoleOf(t.Context(), "some-plugin", w.other)
			require.NoError(t, err)
			require.False(t, held)
		})
	}
}

// TestClaimID_AcceptsWhatARealPluginLooksLike — the floor is not a wall.
func TestClaimID_AcceptsWhatARealPluginLooksLike(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	claim := ownership.Claim{
		PluginID:    mustID(t, "merchant-mode-2"),
		Name:        "Merchant Mode",
		Description: "Tracks bazaar prices and flags underpriced listings.",
		Author:      "prokopto-dev",
		Homepage:    "https://github.com/prokopto-dev/nparseplus-plugin-merchant-mode",
	}
	require.NoError(t, w.svc.ClaimID(t.Context(), claim, w.owner))

	// An empty homepage is fine and is what the column defaults to.
	require.NoError(t, w.svc.ClaimID(t.Context(),
		ownership.Claim{PluginID: mustID(t, "no-homepage"), Name: "No Homepage"}, w.owner))
}

func mustID(t *testing.T, s string) core.PluginID {
	t.Helper()

	id, err := core.ParsePluginID(s)
	require.NoError(t, err)
	return id
}

// TestClaimID_IsRecordedInTheAuditLog — the permanent record of who took which id and when.
func TestClaimID_IsRecordedInTheAuditLog(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	require.NoError(t, w.svc.ClaimID(t.Context(), claimOf(t, "audited-plugin"), w.other))

	rows := storetest.Column(t, w.db,
		`SELECT actor_account_id FROM audit_log WHERE action = ? AND subject_id = ?`,
		"plugin.claim", "audited-plugin")
	require.Equal(t, []string{w.other}, rows)
}
