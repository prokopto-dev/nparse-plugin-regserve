package ownership_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

func TestMain(m *testing.M) { storetest.Main(m) }

var now = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

// world is a database with two accounts and one plugin, held by the first.
type world struct {
	db      *store.DB
	svc     *ownership.Service
	owner   string
	other   string
	plugin  string
	handles map[string]string
}

func newWorld(t *testing.T) world {
	t.Helper()

	db := storetest.New(t)
	w := world{
		db:      db,
		svc:     ownership.New(db, clock.Fixed{T: now}),
		plugin:  "merchant-mode",
		handles: map[string]string{},
	}

	w.owner = w.account(t, "prokopto-dev")
	w.other = w.account(t, "octocat")

	require.NoError(t, db.Tx(t.Context(), func(q *store.Queries) error {
		if err := q.InsertPlugin(t.Context(), sqlitegen.InsertPluginParams{
			ID:        w.plugin,
			Name:      "Merchant Mode",
			ClaimedAt: core.MicrosFromTime(now).Int64(),
			UpdatedAt: core.MicrosFromTime(now).Int64(),
		}); err != nil {
			return err
		}
		return q.InsertPluginOwner(t.Context(), sqlitegen.InsertPluginOwnerParams{
			PluginID:  w.plugin,
			AccountID: w.owner,
			Role:      ownership.RoleOwner.String(),
			GrantedAt: core.MicrosFromTime(now).Int64(),
		})
	}))
	return w
}

// account creates an account with one GitHub identity, and returns its id.
func (w *world) account(t *testing.T, handle string) string {
	t.Helper()

	id, err := core.NewULID(now)
	require.NoError(t, err)
	identityID, err := core.NewULID(now)
	require.NoError(t, err)

	require.NoError(t, w.db.Tx(t.Context(), func(q *store.Queries) error {
		if err := q.InsertAccount(t.Context(), sqlitegen.InsertAccountParams{
			ID:          id.String(),
			DisplayName: handle,
			CreatedAt:   core.MicrosFromTime(now).Int64(),
			UpdatedAt:   core.MicrosFromTime(now).Int64(),
		}); err != nil {
			return err
		}
		return q.InsertIdentity(t.Context(), sqlitegen.InsertIdentityParams{
			ID:           identityID.String(),
			AccountID:    id.String(),
			ProviderKind: "github",
			Subject:      "sub-" + handle,
			Handle:       handle,
			LinkedAt:     core.MicrosFromTime(now).Int64(),
			RefreshedAt:  core.MicrosFromTime(now).Int64(),
		})
	}))

	w.handles[handle] = id.String()
	return id.String()
}

func TestMine_ReturnsTheAccountsPluginsAndTheirState(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	mine, err := w.svc.Mine(t.Context(), w.owner)
	require.NoError(t, err)
	require.Len(t, mine, 1)
	require.Equal(t, w.plugin, mine[0].ID)
	require.Equal(t, ownership.RoleOwner, mine[0].Role)
	require.True(t, mine[0].Listed)
	// A claimed id with nothing approved behind it is the normal state of a new submission, and it
	// is also what a stuck review looks like. Shown rather than inferred from an absence.
	require.False(t, mine[0].HasApprovedRelease)

	theirs, err := w.svc.Mine(t.Context(), w.other)
	require.NoError(t, err)
	require.Empty(t, theirs)
}

// TestMine_ShowsADelistedPlugin — the id is still claimed and the owner still owns it.
//
// Hiding it would be telling somebody their plugin was gone, when what happened is that the
// listing was cleared and the claim kept.
func TestMine_ShowsADelistedPlugin(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	storetest.Exec(t, w.db,
		`UPDATE plugin SET delisted_at = ?, delisted_reason = ? WHERE id = ?`,
		core.MicrosFromTime(now).Int64(), "at the author's request", w.plugin)

	mine, err := w.svc.Mine(t.Context(), w.owner)
	require.NoError(t, err)
	require.Len(t, mine, 1)
	require.False(t, mine[0].Listed)
}

func TestOwners_RequiresTheCallerToHoldThePlugin(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	owners, err := w.svc.Owners(t.Context(), w.plugin, w.owner)
	require.NoError(t, err)
	require.Len(t, owners, 1)
	require.Equal(t, "prokopto-dev", owners[0].Handle)
	require.Equal(t, ownership.RoleOwner, owners[0].Role)

	_, err = w.svc.Owners(t.Context(), w.plugin, w.other)
	require.ErrorIs(t, err, ownership.ErrNotAnOwner,
		"the list of accounts holding a plugin is a list of people to target")
}

func TestAdd_ResolvesAHandleToAnAccountThatHasSignedIn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		handle string
	}{
		{name: "exactly", handle: "octocat"},
		// GitHub compares handles case-insensitively, and so did the static registry's owners.json.
		{name: "in a different case", handle: "OctoCat"},
		{name: "with a leading at-sign, as people type it", handle: "@octocat"},
		{name: "with surrounding space", handle: "  octocat  "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t)
			require.NoError(t,
				w.svc.Add(t.Context(), w.plugin, w.owner, tt.handle, ownership.RoleMaintainer))

			owners, err := w.svc.Owners(t.Context(), w.plugin, w.owner)
			require.NoError(t, err)
			require.Len(t, owners, 2)

			held, err := w.svc.IsOwner(t.Context(), w.plugin, w.other)
			require.NoError(t, err)
			require.True(t, held)
		})
	}
}

// TestAdd_RefusesAHandleNobodyHasSignedInWith — no grant by name.
//
// A row naming a handle nobody has proved they hold is a row that hands the plugin to whoever
// registers that name next, which is the failure the whole identity model exists to prevent.
func TestAdd_RefusesAHandleNobodyHasSignedInWith(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	for _, handle := range []string{"nobody-here", "", "   ", "@"} {
		err := w.svc.Add(t.Context(), w.plugin, w.owner, handle, ownership.RoleMaintainer)
		require.ErrorIs(t, err, ownership.ErrNoSuchAccount, "handle %q", handle)
	}

	owners, err := w.svc.Owners(t.Context(), w.plugin, w.owner)
	require.NoError(t, err)
	require.Len(t, owners, 1)
}

func TestAdd_RefusesWhatWouldBeWrong(t *testing.T) {
	t.Parallel()

	t.Run("a caller who does not hold the plugin", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		err := w.svc.Add(t.Context(), w.plugin, w.other, "octocat", ownership.RoleMaintainer)
		require.ErrorIs(t, err, ownership.ErrNotAnOwner)
	})

	t.Run("somebody who already holds it", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		err := w.svc.Add(t.Context(), w.plugin, w.owner, "prokopto-dev", ownership.RoleOwner)
		require.ErrorIs(t, err, ownership.ErrAlreadyAnOwner)
	})

	t.Run("a disabled account", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		storetest.Exec(t, w.db, `UPDATE account SET disabled_at = ? WHERE id = ?`,
			core.MicrosFromTime(now).Int64(), w.other)

		err := w.svc.Add(t.Context(), w.plugin, w.owner, "octocat", ownership.RoleMaintainer)
		require.ErrorIs(t, err, ownership.ErrAccountDisabled)
	})

	t.Run("a role that is not one", func(t *testing.T) {
		t.Parallel()

		w := newWorld(t)
		err := w.svc.Add(t.Context(), w.plugin, w.owner, "octocat", "administrator")
		require.Error(t, err)
	})
}

// TestRemove_RefusesToLeaveAPluginWithNoOwners — the one that cannot be undone.
//
// Ids are never recycled, so an ownerless plugin is not a plugin somebody else can take over: it
// is a listing nobody can update or delist, for ever, and the only repair is a maintainer writing
// SQL against production.
func TestRemove_RefusesToLeaveAPluginWithNoOwners(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	err := w.svc.Remove(t.Context(), w.plugin, w.owner, w.owner)
	require.ErrorIs(t, err, ownership.ErrLastOwner)

	held, err := w.svc.IsOwner(t.Context(), w.plugin, w.owner)
	require.NoError(t, err)
	require.True(t, held, "the refusal must not have removed them anyway")
}

// TestRemove_ATransferIsTwoSteps — add, then remove, and never the other way round.
func TestRemove_ATransferIsTwoSteps(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	require.NoError(t, w.svc.Add(t.Context(), w.plugin, w.owner, "octocat", ownership.RoleOwner))
	require.NoError(t, w.svc.Remove(t.Context(), w.plugin, w.owner, w.owner))

	held, err := w.svc.IsOwner(t.Context(), w.plugin, w.owner)
	require.NoError(t, err)
	require.False(t, held)

	owners, err := w.svc.Owners(t.Context(), w.plugin, w.other)
	require.NoError(t, err)
	require.Len(t, owners, 1)
	require.Equal(t, "octocat", owners[0].Handle)
}

func TestRemove_RefusesACallerWhoDoesNotHoldThePlugin(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	require.NoError(t, w.svc.Add(t.Context(), w.plugin, w.owner, "octocat", ownership.RoleMaintainer))

	third := w.account(t, "stranger")
	err := w.svc.Remove(t.Context(), w.plugin, third, w.other)
	require.ErrorIs(t, err, ownership.ErrNotAnOwner)

	held, err := w.svc.IsOwner(t.Context(), w.plugin, w.other)
	require.NoError(t, err)
	require.True(t, held)
}

func TestRemove_SomebodyWhoDoesNotHoldIt_IsRefused(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	require.NoError(t, w.svc.Add(t.Context(), w.plugin, w.owner, "octocat", ownership.RoleMaintainer))

	third := w.account(t, "stranger")
	err := w.svc.Remove(t.Context(), w.plugin, w.owner, third)
	require.ErrorIs(t, err, ownership.ErrNotAnOwner)
}

// TestOwnershipChanges_AreRecorded — a disputed handover has to be answerable years later.
func TestOwnershipChanges_AreRecorded(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	require.NoError(t, w.svc.Add(t.Context(), w.plugin, w.owner, "octocat", ownership.RoleOwner))
	require.NoError(t, w.svc.Remove(t.Context(), w.plugin, w.owner, w.owner))

	// ElementsMatch rather than Equal: the clock is frozen, so both rows carry the same
	// recorded_at, and two ULIDs minted in one millisecond differ only in their random bits. Order
	// is a real property in production, where the clock moves; it is not one this fixture can
	// assert, and a test that pretended otherwise would be flaky rather than strict.
	actions := storetest.Column(t, w.db,
		`SELECT action FROM audit_log WHERE subject_kind = 'plugin'`)
	require.ElementsMatch(t, []string{"owner.add", "owner.remove"}, actions)

	// Who did it, and to whom. `granted_by` on the surviving row is only half the story: the row
	// it names is gone.
	detail := storetest.Column(t, w.db,
		`SELECT detail FROM audit_log WHERE action = 'owner.add'`)
	require.Len(t, detail, 1)
	require.Contains(t, detail[0], "octocat")
	require.Contains(t, detail[0], w.other)

	actors := storetest.Column(t, w.db,
		`SELECT actor_account_id FROM audit_log WHERE subject_kind = 'plugin'`)
	for _, actor := range actors {
		require.Equal(t, w.owner, actor, "the actor is the caller, never the subject")
	}
}

// TestARefusedChange_WritesNothing — including the audit row.
//
// audit_log cannot be corrected by deletion, so a row recording a change that was refused is a row
// that misleads for ever.
func TestARefusedChange_WritesNothing(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	require.Error(t, w.svc.Add(t.Context(), w.plugin, w.other, "octocat", ownership.RoleMaintainer))
	require.Error(t, w.svc.Remove(t.Context(), w.plugin, w.owner, w.owner))

	require.Empty(t, storetest.Column(t, w.db,
		`SELECT action FROM audit_log WHERE subject_kind = 'plugin'`))
}

func TestIsOwner_IsTheCheckThatRunsPerRequest(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	held, err := w.svc.IsOwner(t.Context(), w.plugin, w.owner)
	require.NoError(t, err)
	require.True(t, held)

	held, err = w.svc.IsOwner(t.Context(), w.plugin, w.other)
	require.NoError(t, err)
	require.False(t, held)

	held, err = w.svc.IsOwner(t.Context(), "no-such-plugin", w.owner)
	require.NoError(t, err)
	require.False(t, held)
}

func TestRole_Valid(t *testing.T) {
	t.Parallel()

	require.True(t, ownership.RoleOwner.Valid())
	require.True(t, ownership.RoleMaintainer.Valid())
	require.False(t, ownership.Role("").Valid())
	require.False(t, ownership.Role("admin").Valid())
	require.False(t, ownership.Role("Owner").Valid(), "the database CHECK is case-sensitive")
}
