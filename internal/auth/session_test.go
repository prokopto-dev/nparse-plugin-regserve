package auth_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// now is the instant every test in this package is placed at. A fixed clock, injected, because the
// interesting cases here are all boundaries: a session that has just expired and one that has not.
var now = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

const testPepper = "a pepper that is not the production one"

// fixture is a migrated database, a frozen clock and an account to hang sessions off.
type fixture struct {
	db        *store.DB
	clk       *movableClock
	accountID string
}

// movableClock is clock.Clock with a settable instant. testing/synctest is the house tool for
// time-dependent tests, but nothing here waits on time passing — it stores an instant and compares
// it later — so moving the clock by hand tests the boundary directly rather than through a sleep.
type movableClock struct{ t time.Time }

func (c *movableClock) Now() time.Time { return c.t.UTC() }

func newFixture(t *testing.T) fixture {
	t.Helper()

	db := storetest.New(t)
	clk := &movableClock{t: now}

	id, err := core.NewULID(now)
	require.NoError(t, err)

	require.NoError(t, db.Tx(t.Context(), func(q *store.Queries) error {
		return q.InsertAccount(t.Context(), sqlitegen.InsertAccountParams{
			ID:          id.String(),
			DisplayName: "prokopto-dev",
			CreatedAt:   core.MicrosFromTime(now).Int64(),
			UpdatedAt:   core.MicrosFromTime(now).Int64(),
		})
	}))

	return fixture{db: db, clk: clk, accountID: id.String()}
}

func (f fixture) sessions(t *testing.T) *auth.Sessions {
	t.Helper()

	s, err := auth.NewSessions(f.db, f.clk, core.NewSecret(testPepper))
	require.NoError(t, err)
	return s
}

func TestNewSessions_WithoutAPepper_IsRefusedAtConstruction(t *testing.T) {
	t.Parallel()

	// A zero pepper would key every hash on nothing, and the whole argument for storing hashes
	// rather than secrets would quietly be false. It fails here rather than at the first login,
	// where it would look like a database problem.
	_, err := auth.NewSessions(storetest.New(t), clock.Fixed{T: now}, core.Secret{})
	require.ErrorIs(t, err, auth.ErrNoPepper)
}

func TestSessions_Create_ThenResolve_ReturnsTheAccount(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	sessions := f.sessions(t)

	created, err := sessions.Create(t.Context(), f.accountID)
	require.NoError(t, err)
	require.NotEmpty(t, created.Secret)
	require.Equal(t, now.Add(auth.SessionTTL), created.ExpiresAt.UTC())

	p, err := sessions.Resolve(t.Context(), created.Secret)
	require.NoError(t, err)
	require.Equal(t, f.accountID, p.AccountID)
	require.Equal(t, "prokopto-dev", p.DisplayName)
	require.NotEmpty(t, p.SessionID)
	require.False(t, p.ViaToken(), "a cookie is not a token; the capability floor turns on this")
	require.False(t, p.IsZero())
}

// TestSessions_Create_StoresAKeyedHashAndNeverTheSecret — canonical §10, asserted against the row.
//
// The pepper lives in the environment and the rows live on a disk, so a stolen database is not a
// stolen credential — but only if the secret is genuinely absent from it. This reads the column
// back rather than trusting the code that wrote it.
func TestSessions_Create_StoresAKeyedHashAndNeverTheSecret(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	created, err := f.sessions(t).Create(t.Context(), f.accountID)
	require.NoError(t, err)

	rows := f.dumpSessions(t)
	require.Len(t, rows, 1)

	require.NotEqual(t, created.Secret, rows[0],
		"the cookie secret must never be what is stored")
	require.Len(t, rows[0], 64, "the stored value is a hex sha256 digest")
	require.NotContains(t, rows[0], created.Secret)
}

// TestSessions_Resolve_UnderADifferentPepper_Fails — the pepper is doing work.
//
// If the stored value were a plain digest this would pass, and the difference between a keyed hash
// and an unkeyed one would be a comment rather than a property.
func TestSessions_Resolve_UnderADifferentPepper_Fails(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	created, err := f.sessions(t).Create(t.Context(), f.accountID)
	require.NoError(t, err)

	other, err := auth.NewSessions(f.db, f.clk, core.NewSecret("a different pepper"))
	require.NoError(t, err)

	_, err = other.Resolve(t.Context(), created.Secret)
	require.ErrorIs(t, err, auth.ErrCredentialRejected)
}

func TestSessions_Resolve_RefusesEveryUnusableSession(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		arrange func(t *testing.T, f fixture, s *auth.Sessions, secret string)
		want    error
	}{
		{
			name:    "no cookie at all",
			arrange: func(_ *testing.T, _ fixture, _ *auth.Sessions, _ string) {},
			want:    auth.ErrNoCredential,
		},
		{
			name:    "a secret that was never issued",
			arrange: func(_ *testing.T, _ fixture, _ *auth.Sessions, _ string) {},
			want:    auth.ErrCredentialRejected,
		},
		{
			name: "one second past the expiry",
			arrange: func(_ *testing.T, f fixture, _ *auth.Sessions, _ string) {
				f.clk.t = now.Add(auth.SessionTTL).Add(time.Second)
			},
			want: auth.ErrCredentialRejected,
		},
		{
			name: "revoked",
			arrange: func(t *testing.T, _ fixture, s *auth.Sessions, secret string) {
				p, err := s.Resolve(t.Context(), secret)
				require.NoError(t, err)
				require.NoError(t, s.Revoke(t.Context(), p))
			},
			want: auth.ErrCredentialRejected,
		},
		{
			name: "the account was disabled",
			arrange: func(t *testing.T, f fixture, _ *auth.Sessions, _ string) {
				f.disableAccount(t)
			},
			want: auth.ErrCredentialRejected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			sessions := f.sessions(t)

			created, err := sessions.Create(t.Context(), f.accountID)
			require.NoError(t, err)

			present := created.Secret
			switch tt.name {
			case "no cookie at all":
				present = ""
			case "a secret that was never issued":
				present = "not-a-secret-anybody-issued"
			}
			tt.arrange(t, f, sessions, created.Secret)

			_, err = sessions.Resolve(t.Context(), present)
			require.ErrorIs(t, err, tt.want)
		})
	}
}

// TestSessions_Resolve_JustInsideTheExpiry_StillWorks — the other side of the boundary.
//
// Without this, an off-by-one that expired every session immediately would pass the table above,
// which only ever asserts refusals.
func TestSessions_Resolve_JustInsideTheExpiry_StillWorks(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	sessions := f.sessions(t)

	created, err := sessions.Create(t.Context(), f.accountID)
	require.NoError(t, err)

	f.clk.t = now.Add(auth.SessionTTL).Add(-time.Second)
	p, err := sessions.Resolve(t.Context(), created.Secret)
	require.NoError(t, err)
	require.Equal(t, f.accountID, p.AccountID)
}

// TestSessions_Revoke_IsRecordedAndIsIdempotent — a session that ended and one that never existed
// are different answers to the question somebody asks after an account is misused.
func TestSessions_Revoke_IsRecordedAndIsIdempotent(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	sessions := f.sessions(t)

	created, err := sessions.Create(t.Context(), f.accountID)
	require.NoError(t, err)
	p, err := sessions.Resolve(t.Context(), created.Secret)
	require.NoError(t, err)

	require.NoError(t, sessions.Revoke(t.Context(), p))
	// Twice: the WHERE clause records the first time, not the second, and a second logout must not
	// be an error a browser sees.
	require.NoError(t, sessions.Revoke(t.Context(), p))

	rows, err := sessions.List(t.Context(), f.accountID)
	require.NoError(t, err)
	require.Len(t, rows, 1, "a revoked session keeps its row")
	require.NotNil(t, rows[0].RevokedAt)

	require.Equal(t, []string{"session.end", "session.start"}, f.auditActions(t))
}

func TestSessions_Revoke_WithoutASession_IsNotACredentialToRevoke(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	// A principal from a personal access token has no session id. Revoking one must not silently
	// succeed, or "sign out" would report success having done nothing.
	err := f.sessions(t).Revoke(t.Context(), auth.Principal{AccountID: f.accountID, TokenID: "tok"})
	require.ErrorIs(t, err, auth.ErrNoCredential)
}

// TestSessions_Create_SweepsExpiredSessions — the sweep runs where the service is certainly writing.
//
// There is no background goroutine doing this, on purpose: a sweeper is a goroutine to leak, and a
// login is the one moment this service is awake and holding the write lock anyway.
func TestSessions_Create_SweepsExpiredSessions(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	sessions := f.sessions(t)

	_, err := sessions.Create(t.Context(), f.accountID)
	require.NoError(t, err)
	require.Len(t, f.dumpSessions(t), 1)

	f.clk.t = now.Add(auth.SessionTTL).Add(time.Hour)
	_, err = sessions.Create(t.Context(), f.accountID)
	require.NoError(t, err)

	require.Len(t, f.dumpSessions(t), 1,
		"the expired session is swept when the next one is issued")
}

// TestSessions_Resolve_DoesNotWriteOnEveryRequest — one writer, and it is not session bookkeeping.
//
// last_seen_at is refreshed at most once per touch interval. A write per authenticated request
// would put this in the write queue ahead of every publish, for a column nothing decides on.
func TestSessions_Resolve_DoesNotWriteOnEveryRequest(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	sessions := f.sessions(t)

	created, err := sessions.Create(t.Context(), f.accountID)
	require.NoError(t, err)

	f.clk.t = now.Add(time.Minute)
	_, err = sessions.Resolve(t.Context(), created.Secret)
	require.NoError(t, err)
	require.Equal(t, core.MicrosFromTime(now).Int64(), f.lastSeen(t),
		"a resolve a minute later must not have written")

	f.clk.t = now.Add(2 * time.Hour)
	_, err = sessions.Resolve(t.Context(), created.Secret)
	require.NoError(t, err)
	require.Equal(t, core.MicrosFromTime(f.clk.t).Int64(), f.lastSeen(t),
		"a resolve past the touch interval refreshes it")
}

// --- fixture helpers ---------------------------------------------------------------------------
//
// These read the database directly rather than through the service, because what is being asserted
// is what the service WROTE — a helper that went back through the same code could not tell a
// correct row from a consistent misunderstanding, and `token_hash` is a column nothing in
// production has any reason to select.

func (f fixture) dumpSessions(t *testing.T) []string {
	t.Helper()
	return storetest.Column(t, f.db, `SELECT token_hash FROM session ORDER BY created_at`)
}

func (f fixture) auditActions(t *testing.T) []string {
	t.Helper()
	return storetest.Column(t, f.db, `SELECT action FROM audit_log ORDER BY action`)
}

func (f fixture) lastSeen(t *testing.T) int64 {
	t.Helper()

	rows, err := f.sessions(t).List(t.Context(), f.accountID)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	return rows[0].LastSeenAt
}

// disableAccount is the one state the service cannot put itself into: nothing in this phase
// disables an account, and the rule that a disabled account's sessions stop working still has to
// be true before the thing that will do it is written.
func (f fixture) disableAccount(t *testing.T) {
	t.Helper()

	storetest.Exec(t, f.db, `UPDATE account SET disabled_at = ? WHERE id = ?`,
		core.MicrosFromTime(f.clk.t).Int64(), f.accountID)
}
