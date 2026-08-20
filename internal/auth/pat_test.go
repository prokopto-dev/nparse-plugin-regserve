package auth_test

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

func (f fixture) tokens(t *testing.T) *auth.Tokens {
	t.Helper()

	tokens, err := auth.NewTokens(f.db, f.clk, core.NewSecret(testPepper))
	require.NoError(t, err)
	return tokens
}

// mint issues a token with one scope, for the tests that are about something else.
func (f fixture) mint(t *testing.T) auth.NewToken {
	t.Helper()

	minted, err := f.tokens(t).Mint(t.Context(), auth.MintRequest{
		AccountID: f.accountID,
		Name:      "merchant-mode release",
		Scopes:    []authz.Scope{"plugin:publish"},
	})
	require.NoError(t, err)
	return minted
}

func TestNewTokens_WithoutAPepper_IsRefusedAtConstruction(t *testing.T) {
	t.Parallel()

	_, err := auth.NewTokens(storetest.New(t), &movableClock{t: now}, core.Secret{})
	require.ErrorIs(t, err, auth.ErrNoPepper)
}

// TestMint_ProducesTheFormatCanonicalTenFixes — `nprs_pat_<8 hex>_<43 base64url>`.
//
// The shape is pinned because it is what a secret scanner matches on and what the query-string
// refusal looks for. The prefix is HEX and not base64url on purpose: base64url's alphabet contains
// the `_` this format uses as its separator, so a base64url prefix would make the token ambiguous
// to parse — on the authentication path.
func TestMint_ProducesTheFormatCanonicalTenFixes(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	minted := f.mint(t)

	require.True(t, strings.HasPrefix(minted.Secret, auth.TokenPrefix),
		"the fixed opening is how a token is recognised in a log")

	rest := strings.TrimPrefix(minted.Secret, auth.TokenPrefix)
	prefix, secret, found := strings.Cut(rest, "_")
	require.True(t, found)
	require.Len(t, prefix, auth.PrefixLen)
	require.Equal(t, minted.Prefix, prefix)
	require.Regexp(t, `^[0-9a-f]{8}$`, prefix, "the public prefix is lowercase hex")
	require.Len(t, secret, 43, "43 characters of unpadded base64url is 32 random bytes")
}

// TestMint_StoresAKeyedHashAndNeverTheSecret — canonical §10, read back off the row.
func TestMint_StoresAKeyedHashAndNeverTheSecret(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	minted := f.mint(t)

	stored := storetest.Column(t, f.db, `SELECT token_hash FROM pat`)
	require.Len(t, stored, 1)
	require.Len(t, stored[0], 64)
	require.NotContains(t, minted.Secret, stored[0])
	require.NotContains(t, stored[0], minted.Secret)

	// The whole token string must not appear anywhere in the database, in any column.
	for _, table := range []string{"pat", "pat_scope", "audit_log"} {
		dump := strings.Join(storetest.Column(t, f.db,
			`SELECT group_concat(x) FROM (SELECT * FROM `+table+`)`), " ")
		require.NotContains(t, dump, strings.TrimPrefix(minted.Secret, auth.TokenPrefix+minted.Prefix+"_"),
			"the secret half must not be in %s", table)
	}
}

// TestMint_RecordsThePrefixInTheAuditLogAndNotTheSecret — what the public half is FOR.
//
// A token found in somebody's CI log is traced back to a row by its prefix and revoked, without
// the log or this table ever having held the secret.
func TestMint_RecordsThePrefixInTheAuditLogAndNotTheSecret(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	minted := f.mint(t)

	detail := storetest.Column(t, f.db, `SELECT detail FROM audit_log WHERE action = 'token.mint'`)
	require.Len(t, detail, 1)
	require.Contains(t, detail[0], minted.Prefix)
	require.Contains(t, detail[0], "plugin:publish")
	require.NotContains(t, detail[0], strings.TrimPrefix(minted.Secret, auth.TokenPrefix))
}

func TestMint_RefusesAScopeTheCatalogueDoesNotHave(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		scopes []authz.Scope
		want   error
	}{
		{name: "no scopes at all", want: auth.ErrNoScopes},
		{name: "a scope nobody defined", scopes: []authz.Scope{"plugin:teleport"}, want: auth.ErrUnknownScope},
		// There is no admin:*. A token that could reach the capability floor would be equivalent
		// to the account, which is the thing there is deliberately no way to mint.
		{name: "a wildcard", scopes: []authz.Scope{"admin:*"}, want: auth.ErrUnknownScope},
		{name: "a permission spelled as a scope", scopes: []authz.Scope{"token.mint"}, want: auth.ErrUnknownScope},
		{name: "one good and one bad", scopes: []authz.Scope{"plugin:publish", "nope:nope"}, want: auth.ErrUnknownScope},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			_, err := f.tokens(t).Mint(t.Context(), auth.MintRequest{
				AccountID: f.accountID, Name: "x", Scopes: tt.scopes,
			})
			require.ErrorIs(t, err, tt.want)
			require.Empty(t, storetest.Column(t, f.db, `SELECT id FROM pat`),
				"a rejected mint writes nothing")
		})
	}
}

// TestMint_EveryCatalogueScope_IsAcceptedByTheDatabase — the generated CHECK and the Go list agree.
//
// The CHECK in db/schema.hcl is written from internal/authz by `make gen-authz`, and GEN001 fails
// on drift. This is the other direction: it proves the generated list is actually what the
// database enforces, by minting a token carrying every scope the catalogue has.
func TestMint_EveryCatalogueScope_IsAcceptedByTheDatabase(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	minted, err := f.tokens(t).Mint(t.Context(), auth.MintRequest{
		AccountID: f.accountID, Name: "everything", Scopes: authz.Scopes(),
	})
	require.NoError(t, err, "a scope the catalogue knows must be one the CHECK accepts")

	p, err := f.tokens(t).Resolve(t.Context(), minted.Secret)
	require.NoError(t, err)
	require.ElementsMatch(t, authz.Scopes(), p.Scopes)
}

func TestResolve_ReturnsAPrincipalThatIsAToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	minted := f.mint(t)

	p, err := f.tokens(t).Resolve(t.Context(), minted.Secret)
	require.NoError(t, err)

	require.Equal(t, f.accountID, p.AccountID)
	require.Equal(t, minted.ID, p.TokenID)
	require.Equal(t, minted.Prefix, p.TokenPrefix)
	require.Equal(t, []authz.Scope{"plugin:publish"}, p.Scopes)
	require.Empty(t, p.SessionID)

	// This is what the capability floor turns on. A principal that came from a token must say so,
	// or the refusal has nothing to test.
	require.True(t, p.ViaToken())
}

func TestResolve_RefusesEveryUnusableToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		present func(minted auth.NewToken) string
		arrange func(t *testing.T, f fixture, minted auth.NewToken)
		want    error
	}{
		{
			name:    "nothing presented",
			present: func(auth.NewToken) string { return "" },
			want:    auth.ErrNoCredential,
		},
		{
			name:    "not shaped like a token",
			present: func(auth.NewToken) string { return "hunter2" },
			want:    auth.ErrCredentialRejected,
		},
		{
			name:    "the right shape and never issued",
			present: func(auth.NewToken) string { return auth.TokenPrefix + "0123abcd_" + strings.Repeat("a", 43) },
			want:    auth.ErrCredentialRejected,
		},
		{
			name:    "a non-hex prefix",
			present: func(m auth.NewToken) string { return auth.TokenPrefix + "zzzzzzzz_" + strings.Repeat("a", 43) },
			want:    auth.ErrCredentialRejected,
		},
		{
			name:    "the secret without the prefix wrapper",
			present: func(m auth.NewToken) string { return strings.TrimPrefix(m.Secret, auth.TokenPrefix) },
			want:    auth.ErrCredentialRejected,
		},
		{
			name:    "revoked",
			present: func(m auth.NewToken) string { return m.Secret },
			arrange: func(t *testing.T, f fixture, m auth.NewToken) {
				require.NoError(t, f.tokens(t).Revoke(t.Context(), f.accountID, m.ID))
			},
			want: auth.ErrCredentialRejected,
		},
		{
			name:    "expired",
			present: func(m auth.NewToken) string { return m.Secret },
			arrange: func(_ *testing.T, f fixture, _ auth.NewToken) {
				f.clk.t = now.Add(48 * time.Hour)
			},
			want: auth.ErrCredentialRejected,
		},
		{
			name:    "the account was disabled",
			present: func(m auth.NewToken) string { return m.Secret },
			arrange: func(t *testing.T, f fixture, _ auth.NewToken) { f.disableAccount(t) },
			want:    auth.ErrCredentialRejected,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t)
			minted, err := f.tokens(t).Mint(t.Context(), auth.MintRequest{
				AccountID: f.accountID,
				Name:      "x",
				Scopes:    []authz.Scope{"plugin:publish"},
				ExpiresAt: now.Add(24 * time.Hour),
			})
			require.NoError(t, err)

			if tt.arrange != nil {
				tt.arrange(t, f, minted)
			}
			_, err = f.tokens(t).Resolve(t.Context(), tt.present(minted))
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestResolve_JustInsideTheExpiry_StillWorks(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	minted, err := f.tokens(t).Mint(t.Context(), auth.MintRequest{
		AccountID: f.accountID, Name: "x",
		Scopes: []authz.Scope{"plugin:publish"}, ExpiresAt: now.Add(24 * time.Hour),
	})
	require.NoError(t, err)

	f.clk.t = now.Add(24 * time.Hour).Add(-time.Second)
	_, err = f.tokens(t).Resolve(t.Context(), minted.Secret)
	require.NoError(t, err)
}

func TestResolve_UnderADifferentPepper_Fails(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	minted := f.mint(t)

	other, err := auth.NewTokens(f.db, f.clk, core.NewSecret("a different pepper"))
	require.NoError(t, err)

	_, err = other.Resolve(t.Context(), minted.Secret)
	require.ErrorIs(t, err, auth.ErrCredentialRejected)
}

// TestRevoke_CannotReachAnotherAccountsToken — the id comes from a URL.
//
// The account is in the WHERE clause, not only in a Go check above it. A revoke that succeeded on
// somebody else's token would be a denial of service performed by guessing a ULID; one that
// reported "that exists but is not yours" would be an oracle for other people's token ids.
func TestRevoke_CannotReachAnotherAccountsToken(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	minted := f.mint(t)

	other := newFixture(t)
	err := f.tokens(t).Revoke(t.Context(), other.accountID, minted.ID)
	require.ErrorIs(t, err, auth.ErrNoSuchToken)

	// Still usable: the failed revoke did nothing.
	_, err = f.tokens(t).Resolve(t.Context(), minted.Secret)
	require.NoError(t, err)
}

func TestRevoke_Twice_RecordsOneEvent(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	minted := f.mint(t)
	tokens := f.tokens(t)

	require.NoError(t, tokens.Revoke(t.Context(), f.accountID, minted.ID))
	require.ErrorIs(t, tokens.Revoke(t.Context(), f.accountID, minted.ID), auth.ErrNoSuchToken)

	revocations := storetest.Column(t, f.db,
		`SELECT id FROM audit_log WHERE action = 'token.revoke'`)
	require.Len(t, revocations, 1,
		"audit_log is the one table where a row recording something that did not happen cannot "+
			"be taken back")
}

// TestList_ShowsWhatAnOwnerNeedsAndNothingThatAuthenticates.
func TestList_ShowsWhatAnOwnerNeedsAndNothingThatAuthenticates(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	minted, err := f.tokens(t).Mint(t.Context(), auth.MintRequest{
		AccountID: f.accountID,
		Name:      "merchant-mode release",
		Scopes:    []authz.Scope{"plugin:publish", "plugin:read"},
		ExpiresAt: now.Add(90 * 24 * time.Hour),
	})
	require.NoError(t, err)

	listed, err := f.tokens(t).List(t.Context(), f.accountID)
	require.NoError(t, err)
	require.Len(t, listed, 1)

	require.Equal(t, minted.ID, listed[0].ID)
	require.Equal(t, minted.Prefix, listed[0].Prefix)
	require.Equal(t, "merchant-mode release", listed[0].Name)
	require.ElementsMatch(t, []authz.Scope{"plugin:publish", "plugin:read"}, listed[0].Scopes)
	require.Equal(t, now, listed[0].CreatedAt)
	require.NotNil(t, listed[0].ExpiresAt)
	require.Nil(t, listed[0].LastUsedAt, "never used")
	require.Nil(t, listed[0].RevokedAt)
}

func TestList_IsScopedToTheAccount(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	f.mint(t)

	other := newFixture(t)
	listed, err := f.tokens(t).List(t.Context(), other.accountID)
	require.NoError(t, err)
	require.Empty(t, listed)
}

// TestResolve_DoesNotWriteOnEveryRequest — one writer, and it is not token bookkeeping.
func TestResolve_DoesNotWriteOnEveryRequest(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	minted := f.mint(t)
	tokens := f.tokens(t)

	f.clk.t = now.Add(time.Minute)
	_, err := tokens.Resolve(t.Context(), minted.Secret)
	require.NoError(t, err)

	listed, err := tokens.List(t.Context(), f.accountID)
	require.NoError(t, err)
	require.NotNil(t, listed[0].LastUsedAt, "the first use is always recorded")
	require.Equal(t, now.Add(time.Minute), *listed[0].LastUsedAt)

	f.clk.t = now.Add(2 * time.Minute)
	_, err = tokens.Resolve(t.Context(), minted.Secret)
	require.NoError(t, err)

	listed, err = tokens.List(t.Context(), f.accountID)
	require.NoError(t, err)
	require.Equal(t, now.Add(time.Minute), *listed[0].LastUsedAt,
		"a second use a minute later must not have written")

	f.clk.t = now.Add(3 * time.Hour)
	_, err = tokens.Resolve(t.Context(), minted.Secret)
	require.NoError(t, err)

	listed, err = tokens.List(t.Context(), f.accountID)
	require.NoError(t, err)
	require.Equal(t, now.Add(3*time.Hour), *listed[0].LastUsedAt,
		"a use past the touch interval refreshes it")
}

// TestAuthenticator_ABearerToken_DoesNotFallBackToTheCookie — a fallback would be an escalation.
//
// A caller that sent a token MEANT to act as that token. Falling back to a session cookie that
// happened to be attached would authenticate them as the account, with the account's authority
// instead of the token's — including at the capability floor.
func TestAuthenticator_ABearerToken_DoesNotFallBackToTheCookie(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	session, err := f.sessions(t).Create(t.Context(), f.accountID)
	require.NoError(t, err)

	authn := auth.NewAuthenticator(f.sessions(t), f.tokens(t))

	p, err := authn.Resolve(t.Context(), auth.Credentials{
		SessionCookie: session.Secret,
		BearerToken:   auth.TokenPrefix + "0123abcd_" + strings.Repeat("a", 43),
	})
	require.ErrorIs(t, err, auth.ErrCredentialRejected)
	require.True(t, p.IsZero())
}

func TestAuthenticator_PicksTheCredentialThatWasPresented(t *testing.T) {
	t.Parallel()

	f := newFixture(t)
	session, err := f.sessions(t).Create(t.Context(), f.accountID)
	require.NoError(t, err)
	minted := f.mint(t)

	authn := auth.NewAuthenticator(f.sessions(t), f.tokens(t))

	viaToken, err := authn.Resolve(t.Context(), auth.Credentials{BearerToken: minted.Secret})
	require.NoError(t, err)
	require.True(t, viaToken.ViaToken())

	viaCookie, err := authn.Resolve(t.Context(), auth.Credentials{SessionCookie: session.Secret})
	require.NoError(t, err)
	require.False(t, viaCookie.ViaToken())

	_, err = authn.Resolve(t.Context(), auth.Credentials{})
	require.ErrorIs(t, err, auth.ErrNoCredential)
}
