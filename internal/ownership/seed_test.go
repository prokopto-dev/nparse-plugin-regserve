package ownership_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// Importing owners.json.
//
// The property this whole exercise exists for: the static registry recorded ownership as GitHub
// HANDLES, compared case-insensitively, and a handle is something its owner can change. The import
// resolves each to the immutable numeric id ONCE and records both, so that from then on a rename
// is a decoration refresh rather than a lost claim.

// fakeResolver answers handle lookups from a table.
type fakeResolver struct {
	subjects map[string]string
	err      error
	calls    []string
}

func (f *fakeResolver) LookupHandle(_ context.Context, handle string) (identity.Identity, error) {
	f.calls = append(f.calls, handle)
	if f.err != nil {
		return identity.Identity{}, f.err
	}

	key := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(handle), "@"))
	subject, ok := f.subjects[key]
	if !ok {
		return identity.Identity{}, identity.ErrNoSubject
	}
	return identity.Identity{
		Provider: identity.KindGitHub,
		Subject:  subject,
		// GitHub's spelling, which is not necessarily what owners.json wrote.
		Handle: key,
	}, nil
}

// seedWorld is a database holding two plugins and nothing else.
type seedWorld struct {
	db       *store.DB
	resolver *fakeResolver
}

func newSeedWorld(t *testing.T, plugins ...string) seedWorld {
	t.Helper()

	db := storetest.New(t)
	for _, id := range plugins {
		require.NoError(t, db.Tx(t.Context(), func(q *store.Queries) error {
			return q.InsertPlugin(t.Context(), sqlitegen.InsertPluginParams{
				ID:        id,
				Name:      id,
				ClaimedAt: core.MicrosFromTime(now).Int64(),
				UpdatedAt: core.MicrosFromTime(now).Int64(),
			})
		}))
	}

	return seedWorld{
		db: db,
		resolver: &fakeResolver{subjects: map[string]string{
			"prokopto-dev": "12345",
			"octocat":      "583231",
		}},
	}
}

func (w seedWorld) seed(t *testing.T, owners map[string][]string) (ownership.SeedOutcome, error) {
	t.Helper()
	return ownership.SeedOwners(t.Context(), w.db, clock.Fixed{T: now}, w.resolver, owners)
}

// TestSeedOwners_ResolvesEachHandleToItsNumericIdAndRecordsBoth — the whole point (ADR-0003).
func TestSeedOwners_ResolvesEachHandleToItsNumericIdAndRecordsBoth(t *testing.T) {
	t.Parallel()

	w := newSeedWorld(t, "merchant-mode")
	out, err := w.seed(t, map[string][]string{"merchant-mode": {"prokopto-dev"}})
	require.NoError(t, err)

	require.Equal(t, 1, out.Granted)
	require.Equal(t, 1, out.AccountsCreated)
	require.Empty(t, out.UnknownPlugins)
	require.Empty(t, out.UnresolvedHandles)

	// The SUBJECT is the identity and the handle is beside it. A row storing the handle as the
	// subject would be the static registry's model wearing this one's schema.
	require.Equal(t, []string{"github|12345|prokopto-dev"},
		storetest.Column(t, w.db,
			`SELECT provider_kind || '|' || subject || '|' || handle FROM identity`))

	// The grant is `owner`, not `maintainer`: owners.json recorded who may change a listing, and
	// downgrading somebody the static registry trusted would be this migration taking something
	// away without saying so.
	require.Equal(t, []string{"merchant-mode|owner"},
		storetest.Column(t, w.db, `SELECT plugin_id || '|' || role FROM plugin_owner`))

	// granted_by is NULL because no account did this. The audit row says the system did.
	require.Equal(t, []string{""},
		storetest.Column(t, w.db, `SELECT coalesce(granted_by, '') FROM plugin_owner`))
	require.Equal(t, []string{"system"},
		storetest.Column(t, w.db,
			`SELECT DISTINCT actor_kind FROM audit_log WHERE action LIKE '%.import'`))
}

// TestSeedOwners_TheImportedAccountIsTheOneTheyLandOnWhenTheySignIn — the migration's promise.
//
// An account created here has never signed in. When the person does, the OAuth flow looks up
// (provider, subject) — the same numeric id — and must find THIS account, or they arrive at an
// empty one and their plugins appear to be gone.
func TestSeedOwners_TheImportedAccountIsTheOneTheyLandOnWhenTheySignIn(t *testing.T) {
	t.Parallel()

	w := newSeedWorld(t, "merchant-mode")
	_, err := w.seed(t, map[string][]string{"merchant-mode": {"prokopto-dev"}})
	require.NoError(t, err)

	imported := storetest.Column(t, w.db, `SELECT id FROM account`)
	require.Len(t, imported, 1)

	var found sqlitegen.GetAccountByIdentityRow
	require.NoError(t, w.db.Tx(t.Context(), func(q *store.Queries) error {
		var lookupErr error
		found, lookupErr = q.GetAccountByIdentity(t.Context(),
			sqlitegen.GetAccountByIdentityParams{ProviderKind: "github", Subject: "12345"})
		return lookupErr
	}))
	require.Equal(t, imported[0], found.ID,
		"signing in with the same GitHub id must land on the imported account")
}

// TestSeedOwners_IsIdempotentAndAdditive — safe to re-run, and never a reconciliation.
//
// Once ownership can also be changed through the account surface, a re-run that reconciled against
// the file would silently undo a transfer somebody made deliberately.
func TestSeedOwners_IsIdempotentAndAdditive(t *testing.T) {
	t.Parallel()

	w := newSeedWorld(t, "merchant-mode", "raid-tools")
	owners := map[string][]string{
		"merchant-mode": {"prokopto-dev"},
		"raid-tools":    {"octocat"},
	}

	first, err := w.seed(t, owners)
	require.NoError(t, err)
	require.Equal(t, 2, first.Granted)
	require.Equal(t, 2, first.AccountsCreated)

	second, err := w.seed(t, owners)
	require.NoError(t, err)
	require.Zero(t, second.Granted)
	require.Zero(t, second.AccountsCreated)
	require.Equal(t, 2, second.AlreadyHeld)

	require.Len(t, storetest.Column(t, w.db, `SELECT plugin_id FROM plugin_owner`), 2)
	require.Len(t, storetest.Column(t, w.db, `SELECT id FROM account`), 2)

	// A grant made AFTER the import must survive a re-run: this is the transfer case, and a
	// reconciling import would silently undo it.
	svc := ownership.New(w.db, clock.Fixed{T: now})
	prokopto := storetest.Column(t, w.db,
		`SELECT account_id FROM identity WHERE handle = 'prokopto-dev'`)[0]
	require.NoError(t, svc.Add(t.Context(), "merchant-mode", prokopto, "octocat",
		ownership.RoleMaintainer))

	third, err := w.seed(t, owners)
	require.NoError(t, err)
	require.Zero(t, third.Granted)
	require.Len(t, storetest.Column(t, w.db, `SELECT plugin_id FROM plugin_owner`), 3,
		"a re-run must not remove a grant the file does not mention")
}

// TestSeedOwners_ResolvesEachHandleOnce — one lookup per handle, however many plugins it holds.
//
// GitHub's unauthenticated rate limit is the practical reason. The correctness reason is that the
// same handle must not resolve to two accounts within one import.
func TestSeedOwners_ResolvesEachHandleOnce(t *testing.T) {
	t.Parallel()

	w := newSeedWorld(t, "merchant-mode", "raid-tools")
	out, err := w.seed(t, map[string][]string{
		"merchant-mode": {"prokopto-dev"},
		"raid-tools":    {"prokopto-dev", "octocat"},
	})
	require.NoError(t, err)

	require.Equal(t, 3, out.Granted)
	require.Equal(t, 2, out.AccountsCreated)
	require.Len(t, w.resolver.calls, 2, "prokopto-dev holds two plugins and is looked up once")
	require.Len(t, storetest.Column(t, w.db, `SELECT id FROM account`), 2)
}

// TestSeedOwners_ComparesHandlesCaseInsensitively — as owners.json did.
func TestSeedOwners_ComparesHandlesCaseInsensitively(t *testing.T) {
	t.Parallel()

	w := newSeedWorld(t, "merchant-mode", "raid-tools")
	out, err := w.seed(t, map[string][]string{
		"merchant-mode": {"Prokopto-Dev"},
		"raid-tools":    {"@prokopto-dev"},
	})
	require.NoError(t, err)

	require.Equal(t, 2, out.Granted)
	require.Equal(t, 1, out.AccountsCreated, "two spellings of one handle are one person")
	require.Equal(t, []string{"prokopto-dev"},
		storetest.Column(t, w.db, `SELECT handle FROM identity`),
		"what is stored is GitHub's spelling, not the file's")
}

// TestSeedOwners_DoesNotInventAPluginItDoesNotCarry — the id-squatting rule.
//
// A claim on an id this registry does not have is a claim nobody can check. Creating the row would
// make it real, and plugin ids are permanent and never recycled.
func TestSeedOwners_DoesNotInventAPluginItDoesNotCarry(t *testing.T) {
	t.Parallel()

	w := newSeedWorld(t, "merchant-mode")
	out, err := w.seed(t, map[string][]string{
		"merchant-mode":  {"prokopto-dev"},
		"never-heard-of": {"octocat"},
	})
	require.NoError(t, err)

	require.Equal(t, 1, out.Granted)
	require.Equal(t, []string{"never-heard-of"}, out.UnknownPlugins,
		"it is NAMED, not counted: somebody has to go and look at it")
	require.Equal(t, []string{"merchant-mode"},
		storetest.Column(t, w.db, `SELECT id FROM plugin`))
}

// TestSeedOwners_AHandleGitHubDoesNotKnow_IsNamedAndSkipped.
func TestSeedOwners_AHandleGitHubDoesNotKnow_IsNamedAndSkipped(t *testing.T) {
	t.Parallel()

	w := newSeedWorld(t, "merchant-mode")
	out, err := w.seed(t, map[string][]string{"merchant-mode": {"prokopto-dev", "ghost-account"}})
	require.NoError(t, err)

	require.Equal(t, 1, out.Granted)
	require.Equal(t, []string{"ghost-account"}, out.UnresolvedHandles)
	require.Len(t, storetest.Column(t, w.db, `SELECT plugin_id FROM plugin_owner`), 1)
}

// TestSeedOwners_AnUnreachableProvider_IsFatal — a partial import must not report success.
//
// A rate limit part-way through would otherwise produce a run that granted the first ten owners,
// dropped the rest, and exited 0. That is the confident mistake this repository designs against.
func TestSeedOwners_AnUnreachableProvider_IsFatal(t *testing.T) {
	t.Parallel()

	w := newSeedWorld(t, "merchant-mode")
	w.resolver.err = identity.ErrProviderUnavailable

	_, err := w.seed(t, map[string][]string{"merchant-mode": {"prokopto-dev"}})
	require.ErrorIs(t, err, identity.ErrProviderUnavailable)
	require.Empty(t, storetest.Column(t, w.db, `SELECT plugin_id FROM plugin_owner`))
}

func TestLoadOwners_RefusesADocumentItCannotTrust(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		ok   bool
	}{
		{
			name: "the real shape, with the documentation keys it ignores",
			body: `{"_readme": ["ignored"], "_example": {"x": ["y"]},
			        "owners": {"merchant-mode": ["prokopto-dev"]}}`,
			ok: true,
		},
		{name: "not json", body: `{`},
		// An empty document is refused rather than read as "nothing to do": a truncated or
		// wrong-shaped file would otherwise import successfully and silently.
		{name: "no owners key", body: `{"_readme": ["only documentation"]}`},
		{name: "an empty owners map", body: `{"owners": {}}`},
		{name: "a plugin with no owners", body: `{"owners": {"merchant-mode": []}}`},
		{name: "an id that is not a plugin id", body: `{"owners": {"NOT VALID": ["x"]}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "owners.json")
			require.NoError(t, os.WriteFile(path, []byte(tt.body), 0o600))

			owners, err := ownership.LoadOwners(path)
			if tt.ok {
				require.NoError(t, err)
				require.Equal(t, map[string][]string{"merchant-mode": {"prokopto-dev"}}, owners)
				return
			}
			require.Error(t, err)
		})
	}
}

func TestLoadOwners_AMissingFile_IsAnError(t *testing.T) {
	t.Parallel()

	_, err := ownership.LoadOwners(filepath.Join(t.TempDir(), "nope.json"))
	require.Error(t, err)
}
