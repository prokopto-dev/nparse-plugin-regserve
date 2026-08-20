package auth_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
)

// The form token. A session cookie plus a form post is the classic hole, and SameSite=Lax is a
// browser behaviour we neither control nor can test here — this is the half we can.

func TestCSRFToken_IsBoundToTheSession(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	sessions := f.sessions(t)

	mine := auth.Principal{AccountID: f.accountID, SessionID: "session-one"}
	theirs := auth.Principal{AccountID: f.accountID, SessionID: "session-two"}

	token := sessions.CSRFToken(mine)
	require.NotEmpty(t, token)
	require.Len(t, token, 64)
	require.NotContains(t, token, mine.SessionID,
		"the session id must not be recoverable from the form; canonical §10 forbids logging one")

	require.True(t, sessions.CheckCSRF(mine, token))
	require.False(t, sessions.CheckCSRF(theirs, token),
		"a token from another session must not be accepted; that is the whole binding")
}

func TestCheckCSRF_RefusesEveryUnusableToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	sessions := f.sessions(t)
	p := auth.Principal{AccountID: f.accountID, SessionID: "session-one"}
	valid := sessions.CSRFToken(p)

	tests := []struct {
		name      string
		principal auth.Principal
		presented string
	}{
		{name: "nothing presented", principal: p},
		{name: "a wrong value", principal: p, presented: "not-a-token"},
		{name: "the token truncated", principal: p, presented: valid[:32]},
		{name: "the session id itself", principal: p, presented: "session-one"},
		// A personal access token holds no session. Every account-surface route is
		// capability-floor and refuses a token outright, but a CSRF check that passed for a
		// credential kind it was not designed for is a hole waiting for the first route that
		// forgets.
		{name: "a principal with no session", principal: auth.Principal{AccountID: f.accountID, TokenID: "tok"}, presented: valid},
		{name: "no session and no token", principal: auth.Principal{}, presented: valid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.False(t, sessions.CheckCSRF(tt.principal, tt.presented))
		})
	}
}

// TestCSRFToken_UnderADifferentPepper_DoesNotVerify — the key is doing work.
func TestCSRFToken_UnderADifferentPepper_DoesNotVerify(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	p := auth.Principal{AccountID: f.accountID, SessionID: "session-one"}
	token := f.sessions(t).CSRFToken(p)

	other, err := auth.NewSessions(f.db, f.clk, core.NewSecret("a different pepper"))
	require.NoError(t, err)
	require.False(t, other.CheckCSRF(p, token))
}

// TestCSRFToken_IsNotAStoredCredentialHash — domain separation between two uses of one key.
//
// The pepper keys credential hashes, whose inputs are 32 random bytes, and CSRF tokens, whose input
// is a session id. Prefixing the message keeps the two spaces apart: a CSRF token must never be a
// value that could also be a stored hash of something.
func TestCSRFToken_IsNotAStoredCredentialHash(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	sessions := f.sessions(t)

	created, err := sessions.Create(t.Context(), f.accountID)
	require.NoError(t, err)
	p, err := sessions.Resolve(t.Context(), created.Secret)
	require.NoError(t, err)

	stored := f.dumpSessions(t)
	require.Len(t, stored, 1)
	require.NotEqual(t, stored[0], sessions.CSRFToken(p),
		"a form token must never equal the hash the session is looked up by")
}
