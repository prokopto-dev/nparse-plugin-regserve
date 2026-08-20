package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// fakeProvider stands in for GitHub.
//
// The real provider is tested against a real socket in internal/identity/github; what these tests
// are about is everything AROUND the exchange — the state binding, the single-use flow row, and
// what the resulting identity does to the account tables. A fake keeps those failures legible
// instead of mixed in with HTTP ones.
type fakeProvider struct {
	identity identity.Identity
	err      error

	// sawVerifier records what Exchange was handed, so a test can check it against the challenge
	// that went to the browser. A PKCE verifier that does not match its challenge is PKCE in name.
	sawVerifier string
	calls       int
}

func (f *fakeProvider) Kind() identity.Kind { return identity.KindGitHub }

func (f *fakeProvider) AuthorizeURL(state, challenge string) string {
	return "https://github.example/login/oauth/authorize?state=" + url.QueryEscape(state) +
		"&code_challenge=" + url.QueryEscape(challenge)
}

func (f *fakeProvider) Exchange(_ context.Context, _, verifier string) (identity.Identity, error) {
	f.calls++
	f.sawVerifier = verifier
	if f.err != nil {
		return identity.Identity{}, f.err
	}
	return f.identity, nil
}

func githubIdentity() identity.Identity {
	return identity.Identity{
		Provider:    identity.KindGitHub,
		Subject:     "12345",
		Handle:      "prokopto-dev",
		DisplayName: "Courtney Caldwell",
	}
}

// oauthFixture is a migrated database, a movable clock and a provider that answers on demand. It
// deliberately does NOT pre-create an account: the first login is supposed to make one.
type oauthFixture struct {
	fixture
	provider *fakeProvider
	oauth    *auth.OAuth
}

func newOAuthFixture(t *testing.T) oauthFixture {
	t.Helper()

	f := fixture{db: storetest.New(t), clk: &movableClock{t: now}}
	provider := &fakeProvider{identity: githubIdentity()}

	o, err := auth.NewOAuth(f.db, f.clk, core.NewSecret(testPepper),
		identity.NewRegistry(provider))
	require.NoError(t, err)

	return oauthFixture{fixture: f, provider: provider, oauth: o}
}

// begin starts a flow and returns the state the browser would carry back.
func (f oauthFixture) begin(t *testing.T, next string) auth.Begun {
	t.Helper()

	begun, err := f.oauth.Begin(t.Context(), identity.KindGitHub, next)
	require.NoError(t, err)
	require.NotEmpty(t, begun.State)
	return begun
}

func TestNewOAuth_WithoutAPepper_IsRefusedAtConstruction(t *testing.T) {
	t.Parallel()

	_, err := auth.NewOAuth(storetest.New(t), &movableClock{t: now}, core.Secret{},
		identity.NewRegistry())
	require.ErrorIs(t, err, auth.ErrNoPepper)
}

func TestBegin_UnknownProvider_IsRefused(t *testing.T) {
	t.Parallel()

	f := newOAuthFixture(t)
	_, err := f.oauth.Begin(t.Context(), "discord", "")
	require.ErrorIs(t, err, identity.ErrUnknownProvider,
		"github is the only provider (ADR-0011); a login URL naming another must not start a flow")
}

// TestBegin_StoresAKeyedHashOfTheState_AndACorrectPKCEChallenge — what is on each side of the flow.
//
// The browser holds the state; this side holds only HMAC(pepper, state), so a database dump cannot
// complete somebody else's login. And the challenge in the authorize URL must be the S256 of the
// verifier that will be sent to the provider, or PKCE is a query parameter and nothing more.
func TestBegin_StoresAKeyedHashOfTheState_AndACorrectPKCEChallenge(t *testing.T) {
	t.Parallel()

	f := newOAuthFixture(t)
	begun := f.begin(t, "")

	stored := storetest.Column(t, f.db, `SELECT state_hash FROM oauth_flow`)
	require.Len(t, stored, 1)
	require.NotEqual(t, begun.State, stored[0], "the state itself must never be stored")
	require.Len(t, stored[0], 64)

	u, err := url.Parse(begun.AuthorizeURL)
	require.NoError(t, err)
	require.Equal(t, begun.State, u.Query().Get("state"))

	verifiers := storetest.Column(t, f.db, `SELECT code_verifier FROM oauth_flow`)
	require.Len(t, verifiers, 1)
	sum := sha256.Sum256([]byte(verifiers[0]))
	require.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]),
		u.Query().Get("code_challenge"),
		"the challenge must be S256 of the verifier this flow will present")

	require.Equal(t, now.Add(auth.FlowTTL), begun.ExpiresAt.UTC())
}

// TestComplete_FirstLogin_CreatesAnAccountAndAnIdentity — the (provider, subject) model, in rows.
func TestComplete_FirstLogin_CreatesAnAccountAndAnIdentity(t *testing.T) {
	t.Parallel()

	f := newOAuthFixture(t)
	begun := f.begin(t, "/account/tokens")

	done, err := f.oauth.Complete(t.Context(), identity.KindGitHub, begun.State, begun.State, "code")
	require.NoError(t, err)

	require.True(t, done.NewAccount)
	require.NotEmpty(t, done.AccountID)
	require.Equal(t, "Courtney Caldwell", done.DisplayName)
	require.Equal(t, "prokopto-dev", done.Handle)
	require.Equal(t, "/account/tokens", done.RedirectTo)

	// The subject is the immutable numeric id and the handle is decoration beside it. Storing the
	// handle as the subject is the mistake the whole account/identity split exists to prevent.
	require.Equal(t, []string{"github|12345|prokopto-dev"},
		storetest.Column(t, f.db,
			`SELECT provider_kind || '|' || subject || '|' || handle FROM identity`))
	require.Equal(t, []string{"account.create"}, f.auditActions(t))
	require.NotEmpty(t, f.provider.sawVerifier, "the stored verifier must reach the provider")
}

// TestComplete_SecondLoginBySameSubject_ReusesTheAccount — a rename is a refresh, not a new account.
//
// This is the property ADR-0003 is built on. If the lookup were on the handle, a GitHub rename
// would mint a second account holding none of the person's plugins — and the first they would know
// of it is an empty account page.
func TestComplete_SecondLoginBySameSubject_ReusesTheAccount(t *testing.T) {
	t.Parallel()

	f := newOAuthFixture(t)

	first := f.begin(t, "")
	one, err := f.oauth.Complete(t.Context(), identity.KindGitHub, first.State, first.State, "code")
	require.NoError(t, err)

	// Same numeric id, different handle and name: exactly what a rename looks like.
	f.provider.identity = identity.Identity{
		Provider:    identity.KindGitHub,
		Subject:     "12345",
		Handle:      "renamed-dev",
		DisplayName: "Someone Else",
	}
	f.clk.t = now.Add(time.Hour)

	second := f.begin(t, "")
	two, err := f.oauth.Complete(t.Context(), identity.KindGitHub, second.State, second.State, "code")
	require.NoError(t, err)

	require.Equal(t, one.AccountID, two.AccountID, "a rename must not mint a second account")
	require.False(t, two.NewAccount)

	require.Equal(t, []string{"github|12345|renamed-dev"},
		storetest.Column(t, f.db,
			`SELECT provider_kind || '|' || subject || '|' || handle FROM identity`),
		"the cached handle is refreshed at each login")
	require.Equal(t, []string{"Someone Else"},
		storetest.Column(t, f.db, `SELECT display_name FROM account`))
	require.Len(t, f.auditActions(t), 1, "only the first login creates an account")
}

func TestComplete_DisplayNameFallsBackToTheHandle(t *testing.T) {
	t.Parallel()

	f := newOAuthFixture(t)
	// A GitHub account with no profile name is common, and an account page headed by an empty
	// string is a page that looks broken.
	f.provider.identity = identity.Identity{
		Provider: identity.KindGitHub, Subject: "999", Handle: "no-name-set",
	}

	begun := f.begin(t, "")
	done, err := f.oauth.Complete(t.Context(), identity.KindGitHub, begun.State, begun.State, "code")
	require.NoError(t, err)
	require.Equal(t, "no-name-set", done.DisplayName)
}

// TestComplete_RefusesACallbackThatDidNotStartInThisBrowser — login CSRF.
//
// `state` in the URL is a nonce anyone can supply. Requiring the same value in a `__Host-` cookie
// the browser only returns to this origin is what turns it into a binding — otherwise an attacker
// can hand a victim's browser an authorization code of their own, and the victim ends up signed in
// as the attacker and publishing under it.
func TestComplete_RefusesACallbackThatDidNotStartInThisBrowser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		state  func(begun auth.Begun) string
		cookie func(begun auth.Begun) string
		code   string
		want   error
	}{
		{
			name:   "no cookie at all",
			state:  func(b auth.Begun) string { return b.State },
			cookie: func(auth.Begun) string { return "" },
			code:   "code",
			want:   auth.ErrStateMismatch,
		},
		{
			name:   "a cookie from a different flow",
			state:  func(b auth.Begun) string { return b.State },
			cookie: func(auth.Begun) string { return "some-other-state" },
			code:   "code",
			want:   auth.ErrStateMismatch,
		},
		{
			name:   "no state parameter",
			state:  func(auth.Begun) string { return "" },
			cookie: func(b auth.Begun) string { return b.State },
			code:   "code",
			want:   auth.ErrFlowUnknown,
		},
		{
			name:   "no code",
			state:  func(b auth.Begun) string { return b.State },
			cookie: func(b auth.Begun) string { return b.State },
			want:   auth.ErrFlowUnknown,
		},
		{
			name:   "a state nobody issued, matching a cookie the attacker also set",
			state:  func(auth.Begun) string { return "invented" },
			cookie: func(auth.Begun) string { return "invented" },
			code:   "code",
			want:   auth.ErrFlowUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newOAuthFixture(t)
			begun := f.begin(t, "")

			_, err := f.oauth.Complete(t.Context(), identity.KindGitHub,
				tt.state(begun), tt.cookie(begun), tt.code)
			require.ErrorIs(t, err, tt.want)

			require.Zero(t, f.provider.calls,
				"the state is checked BEFORE the code is exchanged, so a forged callback never "+
					"causes an outbound request")
		})
	}
}

// TestComplete_AFlowIsSingleUse — a replayed callback finds nothing.
//
// This is why the flow is a row and not a signed cookie: a cookie can be replayed, and a row that
// is deleted in the same transaction it is read cannot be.
func TestComplete_AFlowIsSingleUse(t *testing.T) {
	t.Parallel()

	f := newOAuthFixture(t)
	begun := f.begin(t, "")

	_, err := f.oauth.Complete(t.Context(), identity.KindGitHub, begun.State, begun.State, "code")
	require.NoError(t, err)
	require.Empty(t, storetest.Column(t, f.db, `SELECT state_hash FROM oauth_flow`),
		"a redeemed flow row is gone")

	_, err = f.oauth.Complete(t.Context(), identity.KindGitHub, begun.State, begun.State, "code")
	require.ErrorIs(t, err, auth.ErrFlowUnknown)
	require.Equal(t, 1, f.provider.calls, "the replay must not reach the provider")
}

// TestComplete_AnExpiredFlow_IsConsumedAsWellAsRefused — an expired row cannot be probed.
//
// It is deleted even though it is refused. A row that survives its own rejection is a row an
// attacker can keep trying against, and there is nothing to gain by keeping it.
func TestComplete_AnExpiredFlow_IsConsumedAsWellAsRefused(t *testing.T) {
	t.Parallel()

	f := newOAuthFixture(t)
	begun := f.begin(t, "")

	f.clk.t = now.Add(auth.FlowTTL).Add(time.Second)
	_, err := f.oauth.Complete(t.Context(), identity.KindGitHub, begun.State, begun.State, "code")
	require.ErrorIs(t, err, auth.ErrFlowUnknown)

	require.Empty(t, storetest.Column(t, f.db, `SELECT state_hash FROM oauth_flow`))
	require.Zero(t, f.provider.calls)
}

func TestComplete_ADisabledAccount_CannotSignIn(t *testing.T) {
	t.Parallel()

	f := newOAuthFixture(t)
	first := f.begin(t, "")
	done, err := f.oauth.Complete(t.Context(), identity.KindGitHub, first.State, first.State, "code")
	require.NoError(t, err)

	storetest.Exec(t, f.db, `UPDATE account SET disabled_at = ? WHERE id = ?`,
		core.MicrosFromTime(now).Int64(), done.AccountID)

	second := f.begin(t, "")
	_, err = f.oauth.Complete(t.Context(), identity.KindGitHub, second.State, second.State, "code")
	require.ErrorIs(t, err, auth.ErrAccountDisabled,
		"a disabled account is a different answer from a rejected credential: the login worked "+
			"and the account is off, and telling somebody to sign in again cannot help")
}

func TestComplete_ProviderFailure_IsReportedAsItsOwnError(t *testing.T) {
	t.Parallel()

	f := newOAuthFixture(t)
	f.provider.err = identity.ErrProviderUnavailable

	begun := f.begin(t, "")
	_, err := f.oauth.Complete(t.Context(), identity.KindGitHub, begun.State, begun.State, "code")
	require.ErrorIs(t, err, identity.ErrProviderUnavailable)

	require.Empty(t, storetest.Column(t, f.db, `SELECT id FROM account`),
		"a failed exchange creates no account")
}

// TestBegin_SweepsExpiredFlows — abandoned logins are the only thing this table accumulates.
func TestBegin_SweepsExpiredFlows(t *testing.T) {
	t.Parallel()

	f := newOAuthFixture(t)
	f.begin(t, "")
	require.Len(t, storetest.Column(t, f.db, `SELECT state_hash FROM oauth_flow`), 1)

	f.clk.t = now.Add(auth.FlowTTL).Add(time.Minute)
	f.begin(t, "")
	require.Len(t, storetest.Column(t, f.db, `SELECT state_hash FROM oauth_flow`), 1,
		"the abandoned flow is swept when the next login starts")
}

// TestSafeRedirect_KeepsOnlySameSitePaths — an open redirect on a login callback is a phishing
// primitive, not a cosmetic bug.
//
// The three interesting rejections are the ones that are absolute URLs wearing a path's clothes.
func TestSafeRedirect_KeepsOnlySameSitePaths(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "a plain path", in: "/account", want: "/account"},
		{name: "a path with a query", in: "/account?tab=tokens", want: "/account?tab=tokens"},
		{name: "root", in: "/", want: "/"},
		{name: "empty", in: "", want: ""},
		{name: "an absolute url", in: "https://evil.example/", want: ""},
		{name: "protocol relative", in: "//evil.example/", want: ""},
		{name: "backslash, which several browsers normalise to //", in: `/\evil.example/`, want: ""},
		{name: "a bare word", in: "account", want: ""},
		{name: "a newline, which is header injection", in: "/account\r\nSet-Cookie: x=1", want: ""},
		{name: "a tab", in: "/account\tx", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, auth.SafeRedirect(tt.in))
		})
	}
}

// TestBegin_RejectedRedirect_IsDiscardedRatherThanStored — the validation is not only at the edge.
func TestBegin_RejectedRedirect_IsDiscardedRatherThanStored(t *testing.T) {
	t.Parallel()

	f := newOAuthFixture(t)
	begun := f.begin(t, "https://evil.example/")

	require.Equal(t, []string{""}, storetest.Column(t, f.db, `SELECT redirect_to FROM oauth_flow`))

	done, err := f.oauth.Complete(t.Context(), identity.KindGitHub, begun.State, begun.State, "code")
	require.NoError(t, err)
	require.Empty(t, done.RedirectTo, "the caller falls back to its own default, never to the input")
}
