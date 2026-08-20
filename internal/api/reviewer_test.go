package api_test

import (
	"context"
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
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// Who may moderate, end to end: real sessions, a real token, the real middleware, over real HTTP.
//
// Moderation is the largest power in this service — it decides what every installed client
// downloads — so the assertions here are made against a running server rather than against a
// struct field. Three things have to be true at once, and each would be a serious hole alone:
//
//  1. A signed-in account that is not a configured reviewer cannot moderate. Without this, anyone
//     who can complete an OAuth flow could approve their own submissions.
//  2. No personal access token can moderate, however scoped. Reviewing is capability-floor, so a
//     token that could would be moderation delegated to whatever CI job it was minted for.
//  3. A configured reviewer's SESSION can. A middleware that refused everybody would pass the
//     first two and be indistinguishable from a broken deployment.

func TestReviewerOnly_OnlyAConfiguredReviewersSessionMayModerate(t *testing.T) {
	t.Parallel()

	fixedNow := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	clk := stoppedClock{t: fixedNow}
	db := storetest.New(t)

	reviewerID := seedAccountWithHandle(t, db, fixedNow, "themaintainer")
	strangerID := seedAccountWithHandle(t, db, fixedNow, "somebodyelse")

	pepper := core.NewSecret("a pepper that is not the production one")
	sessions, err := auth.NewSessions(db, clk, pepper)
	require.NoError(t, err)
	tokens, err := auth.NewTokens(db, clk, pepper)
	require.NoError(t, err)

	srv := httptest.NewServer(api.New(api.Config{
		Authn:     auth.NewAuthenticator(sessions, tokens),
		Sessions:  sessions,
		Tokens:    tokens,
		Providers: identity.NewRegistry(stubProvider{}),
		Queue:     emptyQueue{},
		// The real resolver, against the real identity rows: "themaintainer" is a handle somebody
		// has proved they hold, and the check goes through `identity` to find that out.
		Reviewers: review.NewReviewers(db, []string{"themaintainer"}),
	}))
	t.Cleanup(srv.Close)

	get := func(t *testing.T, header, value string) response {
		t.Helper()

		req, rerr := http.NewRequestWithContext(t.Context(), http.MethodGet,
			srv.URL+api.BasePath+api.PathPendingReleases, nil)
		require.NoError(t, rerr)
		if header != "" {
			req.Header.Set(header, value)
		}

		resp, rerr := srv.Client().Do(req)
		require.NoError(t, rerr)
		defer func() { require.NoError(t, resp.Body.Close()) }()

		body, rderr := io.ReadAll(resp.Body)
		require.NoError(t, rderr)
		return response{status: resp.StatusCode, header: resp.Header.Clone(), body: body}
	}

	t.Run("no credential at all is refused", func(t *testing.T) {
		resp := get(t, "", "")
		require.Equal(t, http.StatusUnauthorized, resp.status)
	})

	t.Run("a token carrying every scope is refused at the floor", func(t *testing.T) {
		// Not "not a reviewer" — refused BEFORE that question is asked, because no token may
		// moderate however it is scoped. The message says session-only, which is the honest
		// reason: minting a better-scoped token would be advice to do something impossible.
		minted, merr := tokens.Mint(t.Context(), auth.MintRequest{
			AccountID: reviewerID,
			Name:      "a reviewer's own token, holding everything",
			Scopes:    authz.Scopes(),
		})
		require.NoError(t, merr)

		resp := get(t, "Authorization", "Bearer "+minted.Secret)
		require.Equal(t, http.StatusForbidden, resp.status)

		p := problemOf(t, resp)
		require.Equal(t, api.CodeForbidden, p.Code)
		require.Contains(t, p.Detail, "session-only",
			"a reviewer's token was refused for the wrong reason; the floor must be what stops it")
	})

	t.Run("a signed-in account that is not a reviewer is refused", func(t *testing.T) {
		session, serr := sessions.Create(t.Context(), strangerID)
		require.NoError(t, serr)

		resp := get(t, "Cookie", auth.SessionCookieName+"="+session.Secret)
		require.Equal(t, http.StatusForbidden, resp.status)

		p := problemOf(t, resp)
		require.Equal(t, api.CodeForbidden, p.Code)
		require.Contains(t, p.Detail, "operates the deployment")
	})

	t.Run("a configured reviewer's session reaches it", func(t *testing.T) {
		// The other side of the boundary. Without this, a middleware that refused everything would
		// pass every case above.
		session, serr := sessions.Create(t.Context(), reviewerID)
		require.NoError(t, serr)

		resp := get(t, "Cookie", auth.SessionCookieName+"="+session.Secret)
		require.Equal(t, http.StatusOK, resp.status)
	})
}

// seedAccountWithHandle creates an account with one proven GitHub identity.
func seedAccountWithHandle(t *testing.T, db *store.DB, at time.Time, handle string) string {
	t.Helper()

	accountID, err := core.NewULID(at)
	require.NoError(t, err)
	identityID, err := core.NewULID(at)
	require.NoError(t, err)

	require.NoError(t, db.Tx(t.Context(), func(q *store.Queries) error {
		if err := q.InsertAccount(t.Context(), sqlitegen.InsertAccountParams{
			ID:          accountID.String(),
			DisplayName: handle,
			CreatedAt:   core.MicrosFromTime(at).Int64(),
			UpdatedAt:   core.MicrosFromTime(at).Int64(),
		}); err != nil {
			return err
		}
		return q.InsertIdentity(t.Context(), sqlitegen.InsertIdentityParams{
			ID:           identityID.String(),
			AccountID:    accountID.String(),
			ProviderKind: "github",
			Subject:      "sub-" + handle,
			Handle:       handle,
			LinkedAt:     core.MicrosFromTime(at).Int64(),
			RefreshedAt:  core.MicrosFromTime(at).Int64(),
		})
	}))
	return accountID.String()
}

// emptyQueue answers an empty queue. The subject of these tests is who may REACH the route, so the
// queue's own behaviour is tested in internal/review against a real database.
type emptyQueue struct{}

func (emptyQueue) List(context.Context) ([]review.Waiting, error) { return nil, nil }

func (emptyQueue) Approve(context.Context, string, string, string) (review.Decision, error) {
	return review.Decision{}, nil
}

func (emptyQueue) Reject(context.Context, string, string, string) (review.Decision, error) {
	return review.Decision{}, nil
}

func (emptyQueue) Reverify(context.Context, string, string) (review.Verification, error) {
	return review.Verification{}, nil
}
