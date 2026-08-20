// Package auth holds the credentials this service issues: browser sessions, the OAuth handshake
// that creates them, and (from the next phase) personal access tokens.
//
// The one rule everything here is built around is canonical §10: a credential's SECRET is never
// stored and never logged. What is stored is `HMAC-SHA256(pepper, secret)`, a keyed hash — keyed
// rather than bcrypt because verification sits on the hot path of every publish, and keyed rather
// than a plain digest because the pepper lives in the environment while the rows live on a disk,
// so a stolen database is not a stolen credential.
//
// What may be logged: the 8-character public prefix of a PAT, which is how a leaked token is found
// in a log. What may NEVER be logged: the token secret, the session id, the session cookie value,
// an OAuth access token, the client secret, or the pepper.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
)

// SessionCookieName is canonical §6's cookie, and the `__Host-` prefix is load-bearing rather than
// decorative: a browser only accepts such a cookie when it is Secure, has Path=/ and carries no
// Domain attribute. That makes it impossible for a subdomain — including one an attacker gets
// control of — to set a session cookie this service will then honour.
//
// The consequence is that the account surface REQUIRES https, including in development. That is a
// real cost and it is deliberate: the alternative is a second cookie name for insecure contexts,
// which is a switch somebody eventually leaves flipped.
const SessionCookieName = "__Host-regserve_session"

// OAuthStateCookieName carries the `state` nonce back to the callback.
//
// `state` in the URL alone is a nonce and not a binding: anyone who can make the browser follow a
// callback URL can supply one. Requiring the same value in a `__Host-` cookie the browser only
// returns to this origin is what turns it into a binding to the user agent that started the flow,
// which is the login-CSRF defence.
const OAuthStateCookieName = "__Host-regserve_oauth"

// TokenPrefix is the fixed opening of every personal access token (canonical §10). The whole
// format is `nprs_pat_<8-char public prefix>_<43 chars base64url of 32 random bytes>`.
//
// It is exported because it is how a token is RECOGNISED, not only how one is built: the rule that
// a token in a query string is refused with 401 is implemented by looking for this prefix in the
// query, and a value that looks like a token in a URL is already in somebody's access log.
const TokenPrefix = "nprs_pat_" //nolint:gosec // G101: the fixed, public opening of a token, not a secret

// subjectAccount is the audit_log subject kind for a row about an account. One spelling: the
// (subject_kind, subject_id) index is what an incident review queries on, and a second spelling
// would put half the rows somewhere nobody looks.
const subjectAccount = "account"

// Credentials is whatever a request presented. Both fields may be empty; both may be set.
//
// One struct rather than two parameters, because "cookie, bearer" is two strings of the same type
// in a fixed order, and the first time somebody swaps them the failure is that authentication
// silently stops working for one of the two.
type Credentials struct {
	// SessionCookie is the raw value of the SessionCookieName cookie. Never logged.
	SessionCookie string

	// BearerToken is what followed `Authorization: Bearer `. Never logged; its 8-character public
	// prefix is, once it has been parsed.
	BearerToken string
}

// Errors this package returns.
var (
	// ErrNoPepper is a service configured without one. It is fatal at construction rather than at
	// the first login: a zero pepper would produce a keyed hash keyed on nothing, and the whole
	// argument for storing hashes rather than secrets would quietly be false.
	ErrNoPepper = errors.New("no token pepper configured")

	// ErrNoCredential is a request that carried none. It is distinct from a rejected one because
	// the response differs: no credential is a 401 with a login hint, a rejected one is a 401
	// that should not encourage a retry with the same value.
	ErrNoCredential = errors.New("no credential presented")

	// ErrCredentialRejected covers every reason a presented credential is not usable — unknown,
	// expired, revoked, or belonging to a disabled account. They are ONE error on purpose: telling
	// a caller which of those it was is telling them whether the value they hold was ever real.
	ErrCredentialRejected = errors.New("credential rejected")
)

// Principal is who a request is, once a credential has been resolved.
//
// A session and a token produce different principals, and the difference is not cosmetic: a
// capability-floor operation accepts only the first, so the field that says which is what the
// enforcement reads. It is a struct rather than an interface because there are exactly two kinds
// and an interface would invite a third that nobody audited.
type Principal struct {
	AccountID   string
	DisplayName string

	// SessionID is set when the credential was a browser session, and empty otherwise. It is never
	// logged and never rendered into a page.
	SessionID string

	// TokenID is set when the credential was a personal access token, and empty otherwise.
	TokenID string

	// TokenPrefix is the token's 8-character PUBLIC identifier. It is the one part of a token that
	// may appear in a log, and it is how a leaked token is traced back to a row.
	TokenPrefix string

	// Scopes is what a token carries. A session carries none and needs none — it is the account.
	Scopes []authz.Scope

	// PluginID is the plugin a token is PINNED to, and is empty for an unpinned token or for a
	// session. It is the second half of ADR-0005's containment argument: the scope says what the
	// credential may do and the pin says what it may do it to, and a leak is contained to the
	// repository it leaked from only if BOTH are enforced.
	//
	// It is on the principal rather than looked up at the point of use because a pin that a
	// handler has to remember to fetch is a pin a handler forgets. AllowsPlugin is the only way to
	// ask, and internal/api's middleware asks it before any handler runs.
	PluginID string
}

// AllowsPlugin reports whether this principal may act on the given plugin.
//
// An unpinned credential — a session, or a token minted for no particular plugin — may act on any
// plugin the account owns, and OWNERSHIP is a separate question answered per request against
// plugin_owner. This answers only the pin.
func (p Principal) AllowsPlugin(pluginID string) bool {
	return p.PluginID == "" || p.PluginID == pluginID
}

// Pinned reports whether this credential is restricted to one plugin.
func (p Principal) Pinned() bool { return p.PluginID != "" }

// ViaToken reports whether this principal came from a personal access token.
//
// The capability floor is expressed as "not this": an operation in the floor refuses a token
// however it is scoped, because a token that could mint another token would be the account.
func (p Principal) ViaToken() bool { return p.TokenID != "" }

// IsZero reports whether no credential was resolved.
func (p Principal) IsZero() bool { return p.AccountID == "" }

// secretBytes is the entropy in a session or token secret. 32 bytes is 256 bits; canonical §10
// fixes it for PATs and there is no reason for a session to be weaker.
const secretBytes = 32

// newSecret returns a URL-safe, unpadded base64 secret of secretBytes bytes.
//
// crypto/rand, always: math/rand is depguard-banned in this repository precisely because a
// predictable session secret is a login as somebody else. rand.Read never returns a short read, so
// an error here means the operating system's entropy source failed — which is not a condition to
// paper over with a fallback.
func newSecret() (string, error) {
	buf := make([]byte, secretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read randomness for a credential: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// keyedHash is canonical §10's storage form: hex(HMAC-SHA256(pepper, value)).
//
// Hex rather than base64 because the column has a CHECK asserting 64 lowercase hex characters, and
// a shape the database can verify is a shape a hand-written UPDATE during an incident cannot get
// wrong.
func keyedHash(pepper core.Secret, value string) string {
	mac := hmac.New(sha256.New, []byte(pepper.Reveal()))
	// Hash.Write never returns an error; the interface has one because io.Writer does.
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil))
}

// equalHash compares two stored hashes in constant time.
//
// Both sides are already hashes, so a timing leak here reveals only how far a guess got through a
// digest — but the comparison is on the authentication path, and a variable-time compare on an
// authentication path is the kind of thing that is correct until the thing being compared changes.
func equalHash(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

// requirePepper is the constructor guard every service in this package shares.
func requirePepper(pepper core.Secret) error {
	if pepper.IsZero() {
		return ErrNoPepper
	}
	return nil
}

// Authenticator resolves whatever credential a request carried.
//
// It is the one place that decides which credential wins when a request presents both, and the
// answer is the bearer token: a caller that sent one MEANT to act as that token, and quietly
// falling back to a browser session would authenticate them as the person whose cookie happened to
// be attached — with the session's authority rather than the token's, which is an escalation
// performed by a fallback.
type Authenticator struct {
	sessions *Sessions
	tokens   *Tokens
}

// NewAuthenticator wires the credential kinds this build issues.
func NewAuthenticator(sessions *Sessions, tokens *Tokens) *Authenticator {
	return &Authenticator{sessions: sessions, tokens: tokens}
}

// Resolve turns credentials into a principal, or explains why it will not.
func (a *Authenticator) Resolve(ctx context.Context, creds Credentials) (Principal, error) {
	switch {
	case creds.BearerToken != "":
		return a.tokens.Resolve(ctx, creds.BearerToken)
	case creds.SessionCookie != "":
		return a.sessions.Resolve(ctx, creds.SessionCookie)
	default:
		return Principal{}, ErrNoCredential
	}
}
