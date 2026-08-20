package ownership_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
)

// TRANSFERRING A PLUGIN IS TWO STEPS, and there is deliberately no endpoint for it.
//
// ADR-0005 records why, in the consequences it accepted rather than in the decision it made:
//
//	Bad, because a token dies when its owner loses ownership, which is correct and will still
//	surprise someone mid-handover. Transfers need to be documented as a two-step: add the new
//	owner, let them mint their own token, then remove the old one.
//
// A one-shot transfer would have to either move the token with the plugin — which is handing
// somebody else's credential to a new person — or break the outgoing owner's pipeline at the
// moment of the change, with no window in which the incoming owner can get their own working.
// Neither is a thing to do silently, so the operation is two calls a human makes in an order they
// can see.
//
// This file is the executable version of that documentation. If the sequence ever stops working,
// the failure is here rather than in somebody's handover.

// TestTransfer_IsAddThenRemove_AndWorksInThatOrder.
func TestTransfer_IsAddThenRemove_AndWorksInThatOrder(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	// STEP ONE: the outgoing owner adds the incoming one, as an owner rather than a maintainer —
	// they are going to be left holding it alone, and a plugin whose only holder cannot manage
	// owners can never be transferred again.
	require.NoError(t, w.svc.Add(t.Context(), w.plugin, w.owner, "octocat", ownership.RoleOwner))

	// BOTH HOLD IT NOW. This is the window ADR-0005 exists to create: the incoming owner can mint
	// their own token and prove their pipeline works before the outgoing one goes away.
	owners, err := w.svc.Owners(t.Context(), w.plugin, w.owner)
	require.NoError(t, err)
	require.Len(t, owners, 2)

	// STEP TWO: the outgoing owner removes themselves.
	require.NoError(t, w.svc.Remove(t.Context(), w.plugin, w.owner, w.owner))

	owners, err = w.svc.Owners(t.Context(), w.plugin, w.other)
	require.NoError(t, err)
	require.Len(t, owners, 1)
	require.Equal(t, w.other, owners[0].AccountID)
	require.Equal(t, ownership.RoleOwner, owners[0].Role)

	// The outgoing owner has nothing here any more, and gets the answer somebody with no grant
	// gets — not a different one that would confirm the plugin exists.
	_, held, err := w.svc.RoleOf(t.Context(), w.plugin, w.owner)
	require.NoError(t, err)
	require.False(t, held)

	_, err = w.svc.Owners(t.Context(), w.plugin, w.owner)
	require.ErrorIs(t, err, ownership.ErrNotAnOwner)
}

// TestTransfer_TheOtherOrder_IsRefused.
//
// Remove-then-add would leave the plugin with nobody in between, and `ErrLastOwner` refuses it.
// That refusal is what makes the two-step an ORDER rather than a suggestion: a handover that went
// the other way round would, for the moment between the two calls, produce a plugin nobody can
// update or delist — and since ids are never recycled, the only repair is a maintainer writing SQL
// against production.
func TestTransfer_TheOtherOrder_IsRefused(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	require.ErrorIs(t,
		w.svc.Remove(t.Context(), w.plugin, w.owner, w.owner),
		ownership.ErrLastOwner)

	// Still theirs, so a refused removal changed nothing.
	role, held, err := w.svc.RoleOf(t.Context(), w.plugin, w.owner)
	require.NoError(t, err)
	require.True(t, held)
	require.Equal(t, ownership.RoleOwner, role)
}

// TestTransfer_AMaintainerCannotPerformOne.
//
// The half that makes "may publish" not a path to taking somebody's plugin. A maintainer added so
// they can release cannot add an account they control and then remove the owner — which would be a
// full takeover, and an irreversible one, because ids are permanent.
func TestTransfer_AMaintainerCannotPerformOne(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	require.NoError(t, w.svc.Add(t.Context(), w.plugin, w.owner, "octocat", ownership.RoleMaintainer))

	// They can READ the owner list — a co-maintainer publishing to a plugin needs to know who else
	// holds it — and they cannot change it.
	owners, err := w.svc.Owners(t.Context(), w.plugin, w.other)
	require.NoError(t, err)
	require.Len(t, owners, 2)

	require.ErrorIs(t,
		w.svc.Add(t.Context(), w.plugin, w.other, "prokopto-dev", ownership.RoleOwner),
		ownership.ErrRoleCannotManageOwners)

	require.ErrorIs(t,
		w.svc.Remove(t.Context(), w.plugin, w.other, w.owner),
		ownership.ErrRoleCannotManageOwners)
}

// TestTransfer_ANewlyClaimedPluginCanBeHandedOn.
//
// The two paths meeting: an id claimed through the API, then transferred. A claimant granted
// anything less than owner would hold a plugin they could never pass on, and because ids are
// permanent that would be for ever.
func TestTransfer_ANewlyClaimedPluginCanBeHandedOn(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	require.NoError(t, w.svc.ClaimID(t.Context(), claimOf(t, "handed-on"), w.owner))

	require.NoError(t, w.svc.Add(t.Context(), "handed-on", w.owner, "octocat", ownership.RoleOwner))
	require.NoError(t, w.svc.Remove(t.Context(), "handed-on", w.owner, w.owner))

	owners, err := w.svc.Owners(t.Context(), "handed-on", w.other)
	require.NoError(t, err)
	require.Len(t, owners, 1)
	require.Equal(t, w.other, owners[0].AccountID)
}
