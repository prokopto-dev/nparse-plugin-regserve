package api_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// The capability floor, end to end: a REAL token, minted through the real service, refused by the
// real middleware over real HTTP.
//
// internal/api's other auth tests use a fake authenticator, which is right for testing which
// failure becomes which status — but a fake principal that says `ViaToken` is a test asserting
// that a struct field is set. This one mints a token that carries every scope in the catalogue and
// watches the server refuse it anyway, which is the property canonical §5 actually promises:
// there is no scope that reaches the floor, and no admin:*.

func TestCapabilityFloor_ARealTokenWithEveryScope_IsStillRefused(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	clk := stoppedClock{t: fixedNow}
	db := storetest.New(t)

	accountID, err := core.NewULID(fixedNow)
	require.NoError(t, err)
	require.NoError(t, db.Tx(t.Context(), func(q *store.Queries) error {
		return q.InsertAccount(t.Context(), sqlitegen.InsertAccountParams{
			ID:          accountID.String(),
			DisplayName: "prokopto-dev",
			CreatedAt:   core.MicrosFromTime(fixedNow).Int64(),
			UpdatedAt:   core.MicrosFromTime(fixedNow).Int64(),
		})
	}))

	pepper := core.NewSecret("a pepper that is not the production one")
	sessions, err := auth.NewSessions(db, clk, pepper)
	require.NoError(t, err)
	tokens, err := auth.NewTokens(db, clk, pepper)
	require.NoError(t, err)
	login, err := auth.NewOAuth(db, clk, pepper, identity.NewRegistry(stubProvider{}))
	require.NoError(t, err)

	srv := httptest.NewServer(api.New(api.Config{
		Authn:     auth.NewAuthenticator(sessions, tokens),
		Login:     login,
		Sessions:  sessions,
		Providers: identity.NewRegistry(stubProvider{}),
		Tokens:    tokens,
	}))
	t.Cleanup(srv.Close)

	minted, err := tokens.Mint(t.Context(), auth.MintRequest{
		AccountID: accountID.String(),
		Name:      "a token holding everything there is to hold",
		Scopes:    authz.Scopes(),
	})
	require.NoError(t, err)

	logout := func(t *testing.T, header, value string) response {
		t.Helper()

		req, rerr := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/auth/logout", nil)
		require.NoError(t, rerr)
		req.Header.Set(header, value)

		client := &http.Client{
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
		resp, rerr := client.Do(req)
		require.NoError(t, rerr)
		defer func() { require.NoError(t, resp.Body.Close()) }()

		body, rderr := io.ReadAll(resp.Body)
		require.NoError(t, rderr)
		return response{status: resp.StatusCode, header: resp.Header.Clone(), body: body}
	}

	t.Run("the token authenticates", func(t *testing.T) {
		// Proving the refusal is about the FLOOR and not about the token being unusable. Without
		// this, a token the server simply could not resolve would produce the same 403 and the
		// test would pass while checking nothing.
		p, rerr := tokens.Resolve(t.Context(), minted.Secret)
		require.NoError(t, rerr)
		require.True(t, p.ViaToken())
		require.ElementsMatch(t, authz.Scopes(), p.Scopes)
	})

	t.Run("and is refused at the floor anyway", func(t *testing.T) {
		resp := logout(t, "Authorization", "Bearer "+minted.Secret)

		require.Equal(t, http.StatusForbidden, resp.status)
		p := problemOf(t, resp)
		require.Equal(t, api.CodeForbidden, p.Code)
		require.Contains(t, p.Detail, "session-only")
	})

	t.Run("while a session reaches it", func(t *testing.T) {
		// The other side of the boundary. A middleware that refused everything would pass the case
		// above, and the floor is meant to be reachable by exactly one credential.
		session, serr := sessions.Create(t.Context(), accountID.String())
		require.NoError(t, serr)

		resp := logout(t, "Cookie", auth.SessionCookieName+"="+session.Secret)
		require.Equal(t, http.StatusSeeOther, resp.status)
	})
}

// stoppedClock is a clock.Clock frozen at one instant.
type stoppedClock struct{ t time.Time }

func (c stoppedClock) Now() time.Time { return c.t.UTC() }
