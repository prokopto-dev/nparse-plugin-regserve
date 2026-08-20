package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/audit"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// The token format, canonical §10: `nprs_pat_<8-char public prefix>_<43 chars base64url>`.
//
// The prefix is HEX rather than base64url, and that is not a stylistic choice: base64url's
// alphabet contains `_`, which is the format's own separator. A prefix that could hold a separator
// makes the format ambiguous to parse, and the parser is on the authentication path.
const (
	// prefixBytes is 4 bytes rendered as 8 hex characters.
	prefixBytes = 4

	// PrefixLen is how many characters of a token are public. It is what a leaked token is found
	// by in a log, so it is long enough to identify a row and short enough to be useless alone.
	PrefixLen = prefixBytes * 2

	// secretLen is the encoded length of 32 random bytes in unpadded base64url.
	secretLen = 43
)

// tokenSep is the separator between the format's parts.
const tokenSep = "_"

// patTouchInterval is how stale `last_used_at` may get before a read pays for a write. Same
// reasoning as a session's, and the same single writer.
const patTouchInterval = time.Hour

// Errors minting can return. Resolution failures are ErrCredentialRejected, like every other
// credential: which of several reasons a token is unusable is not a caller's business.
var (
	// ErrUnknownScope is a mint request naming a scope the catalogue does not have. Rejected
	// rather than stored and ignored: a token whose scope matches no permission would look narrow
	// on the account page and be exactly as powerless in practice.
	ErrUnknownScope = errors.New("unknown scope")

	// ErrNoScopes is a mint request naming none. A token that grants nothing is a secret in a CI
	// configuration doing nothing, which somebody will eventually "fix" by minting a broader one.
	ErrNoScopes = errors.New("a token must carry at least one scope")
)

// Tokens mints, resolves and revokes personal access tokens.
type Tokens struct {
	db     *store.DB
	clk    clock.Clock
	pepper core.Secret
}

// NewTokens builds the token service.
func NewTokens(db *store.DB, clk clock.Clock, pepper core.Secret) (*Tokens, error) {
	if err := requirePepper(pepper); err != nil {
		return nil, fmt.Errorf("token service: %w", err)
	}
	return &Tokens{db: db, clk: clk, pepper: pepper}, nil
}

// MintRequest is what an account asks for.
type MintRequest struct {
	AccountID string

	// Name is what the owner calls it, so the account page can say which pipeline it belongs to. A
	// row nobody can identify is a row nobody dares revoke.
	Name string

	// Scopes must all be in the catalogue and must not be empty.
	Scopes []authz.Scope

	// PluginID pins the token to one plugin. Empty means unpinned. ADR-0005 wants the narrow
	// choice to be the easy one; the pin is the narrow choice.
	PluginID string

	// ExpiresAt is optional. Zero means the token does not expire on its own, and revocation is
	// the mechanism.
	ExpiresAt time.Time
}

// NewToken is a freshly minted token and the ONE moment its secret exists outside a CI secret store.
type NewToken struct {
	// Secret is the whole `nprs_pat_…` string. It is returned exactly once, is never stored, and
	// must not be logged, rendered twice, or put in an error message.
	Secret string

	// ID and Prefix identify the row afterwards. The prefix is the loggable half.
	ID     string
	Prefix string
}

// Mint issues a token and records it.
//
// Minting is a capability-floor operation (canonical §5): it is session-only, and no token can
// reach this however it is scoped. That is enforced at the route, by the access declaration — this
// function is what the route calls once it has decided, and it deliberately does not re-derive the
// rule, because two copies of "who may mint a token" is one copy too many.
func (t *Tokens) Mint(ctx context.Context, req MintRequest) (NewToken, error) {
	if len(req.Scopes) == 0 {
		return NewToken{}, ErrNoScopes
	}
	for _, s := range req.Scopes {
		if !authz.KnownScope(s) {
			return NewToken{}, fmt.Errorf("%w: %q", ErrUnknownScope, s)
		}
	}

	prefix, err := newPrefix()
	if err != nil {
		return NewToken{}, err
	}
	secret, err := newSecret()
	if err != nil {
		return NewToken{}, err
	}
	full := TokenPrefix + prefix + tokenSep + secret

	now := t.clk.Now()
	id, err := core.NewULID(now)
	if err != nil {
		return NewToken{}, fmt.Errorf("mint a token id: %w", err)
	}

	params := sqlitegen.InsertPATParams{
		ID:        id.String(),
		AccountID: req.AccountID,
		Prefix:    prefix,
		// The hash is over the SECRET half only, not the whole displayed string. The prefix is
		// public and the format is a constant, so including either would add no entropy while
		// making the stored value depend on a format that may one day gain a version.
		TokenHash: keyedHash(t.pepper, secret),
		Name:      strings.TrimSpace(req.Name),
		CreatedAt: core.MicrosFromTime(now).Int64(),
	}
	if req.PluginID != "" {
		params.PluginID = &req.PluginID
	}
	if !req.ExpiresAt.IsZero() {
		expires := core.MicrosFromTime(req.ExpiresAt).Int64()
		params.ExpiresAt = &expires
	}

	scopes := make([]string, 0, len(req.Scopes))
	for _, s := range req.Scopes {
		scopes = append(scopes, s.String())
	}

	err = t.db.Tx(ctx, func(q *store.Queries) error {
		if err := q.InsertPAT(ctx, params); err != nil {
			return fmt.Errorf("record the token: %w", err)
		}
		for _, s := range scopes {
			if err := q.InsertPATScope(ctx, sqlitegen.InsertPATScopeParams{
				PatID: id.String(),
				Scope: s,
			}); err != nil {
				return fmt.Errorf("record the token scope %s: %w", s, err)
			}
		}
		// The PREFIX goes in the audit row and the secret does not. That is the whole point of
		// having a public half: this row is what connects a token seen in a log to the account
		// that minted it, and audit_log is the one table nobody can redact later.
		return audit.Record(ctx, q, t.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   req.AccountID,
			Action:      "token.mint",
			SubjectKind: "token",
			SubjectID:   id.String(),
			Detail: map[string]any{
				"prefix": prefix,
				"scopes": scopes,
				"plugin": req.PluginID,
			},
		})
	})
	if err != nil {
		return NewToken{}, err
	}

	return NewToken{Secret: full, ID: id.String(), Prefix: prefix}, nil
}

// Resolve turns a presented token into a principal.
//
// Every rejection is ErrCredentialRejected: malformed, unknown, expired, revoked, or belonging to
// a disabled account are one answer, because distinguishing them tells the holder whether the
// value they have was ever real.
func (t *Tokens) Resolve(ctx context.Context, presented string) (Principal, error) {
	if presented == "" {
		return Principal{}, ErrNoCredential
	}
	secret, ok := splitToken(presented)
	if !ok {
		// Rejected before it reaches the database. A value that is not shaped like a token cannot
		// be one, and hashing it would be a database round trip bought by anybody sending noise.
		return Principal{}, ErrCredentialRejected
	}

	row, err := t.db.Read().GetPATByTokenHash(ctx, keyedHash(t.pepper, secret))
	switch {
	case errors.Is(err, store.ErrNoRows):
		return Principal{}, ErrCredentialRejected
	case err != nil:
		return Principal{}, fmt.Errorf("read the token: %w", err)
	}

	now := t.clk.Now()
	switch {
	case row.RevokedAt != nil,
		row.DisabledAt != nil,
		row.ExpiresAt != nil && core.Micros(*row.ExpiresAt).Time().Before(now):
		return Principal{}, ErrCredentialRejected
	}

	scopes, err := t.db.Read().ListPATScopes(ctx, row.ID)
	if err != nil {
		return Principal{}, fmt.Errorf("read the token scopes: %w", err)
	}
	held := make([]authz.Scope, 0, len(scopes))
	for _, s := range scopes {
		held = append(held, authz.Scope(s))
	}

	if err := t.touch(ctx, row.ID, row.LastUsedAt, now); err != nil {
		return Principal{}, err
	}

	principal := Principal{
		AccountID:   row.AccountID,
		DisplayName: row.DisplayName,
		TokenID:     row.ID,
		TokenPrefix: row.Prefix,
		Scopes:      held,
	}
	// The pin travels WITH the principal. Dropping it here would leave a publish handler with an
	// account and a set of scopes and no way to know the token was minted for one plugin — so a
	// token leaked from plugin A's pipeline would authorise plugin B, and ADR-0005's containment
	// argument would be false while the row said it was true.
	if row.PluginID != nil {
		principal.PluginID = *row.PluginID
	}
	return principal, nil
}

func (t *Tokens) touch(ctx context.Context, id string, lastUsed *int64, now time.Time) error {
	if lastUsed != nil && now.Sub(core.Micros(*lastUsed).Time()) < patTouchInterval {
		return nil
	}
	err := t.db.Tx(ctx, func(q *store.Queries) error {
		return q.TouchPAT(ctx, sqlitegen.TouchPATParams{
			LastUsedAt: ptr(core.MicrosFromTime(now).Int64()),
			ID:         id,
		})
	})
	if err != nil {
		return fmt.Errorf("touch the token: %w", err)
	}
	return nil
}

// ErrNoSuchToken is a revoke naming a token this account does not hold, or one already revoked.
//
// The two are one error deliberately: the id comes from a URL, and telling a caller "that token
// exists but is not yours" is an oracle for other people's token ids.
var ErrNoSuchToken = errors.New("no such token")

// Revoke ends a token. It is scoped to the account in the SQL, not only here.
func (t *Tokens) Revoke(ctx context.Context, accountID, tokenID string) error {
	now := core.MicrosFromTime(t.clk.Now()).Int64()

	return t.db.Tx(ctx, func(q *store.Queries) error {
		revoked, err := q.RevokePAT(ctx, sqlitegen.RevokePATParams{
			RevokedAt: &now,
			ID:        tokenID,
			AccountID: accountID,
		})
		if err != nil {
			return fmt.Errorf("revoke the token: %w", err)
		}
		if revoked == 0 {
			return ErrNoSuchToken
		}
		return audit.Record(ctx, q, t.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   accountID,
			Action:      "token.revoke",
			SubjectKind: "token",
			SubjectID:   tokenID,
		})
	})
}

// Listing is one token as the account page shows it. It carries no hash and no secret.
type Listing struct {
	ID         string
	Prefix     string
	Name       string
	PluginID   string
	Scopes     []authz.Scope
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// List returns the account's tokens, newest first.
func (t *Tokens) List(ctx context.Context, accountID string) ([]Listing, error) {
	rows, err := t.db.Read().ListPATsForAccount(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("list the tokens for %s: %w", accountID, err)
	}

	out := make([]Listing, 0, len(rows))
	for _, row := range rows {
		scopes, err := t.db.Read().ListPATScopes(ctx, row.ID)
		if err != nil {
			return nil, fmt.Errorf("read the scopes of token %s: %w", row.ID, err)
		}
		held := make([]authz.Scope, 0, len(scopes))
		for _, s := range scopes {
			held = append(held, authz.Scope(s))
		}

		listing := Listing{
			ID:        row.ID,
			Prefix:    row.Prefix,
			Name:      row.Name,
			Scopes:    held,
			CreatedAt: core.Micros(row.CreatedAt).Time(),
		}
		if row.PluginID != nil {
			listing.PluginID = *row.PluginID
		}
		listing.ExpiresAt = micros(row.ExpiresAt)
		listing.LastUsedAt = micros(row.LastUsedAt)
		listing.RevokedAt = micros(row.RevokedAt)
		out = append(out, listing)
	}
	return out, nil
}

// splitToken pulls the secret half out of a presented token, and reports whether it was one.
//
// It checks the SHAPE and nothing else. The point is to reject noise before it costs a database
// round trip, and to do it without a regular expression on the authentication path.
func splitToken(presented string) (string, bool) {
	rest, ok := strings.CutPrefix(presented, TokenPrefix)
	if !ok || len(rest) != PrefixLen+len(tokenSep)+secretLen {
		return "", false
	}
	prefix, secret := rest[:PrefixLen], rest[PrefixLen+len(tokenSep):]
	if rest[PrefixLen:PrefixLen+len(tokenSep)] != tokenSep {
		return "", false
	}
	// The prefix is hex; anything else was not minted here.
	if _, err := hex.DecodeString(prefix); err != nil {
		return "", false
	}
	return secret, true
}

// newPrefix returns the 8-character public identifier.
func newPrefix() (string, error) {
	buf := make([]byte, prefixBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("read randomness for a token prefix: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

func micros(v *int64) *time.Time {
	if v == nil {
		return nil
	}
	t := core.Micros(*v).Time()
	return &t
}

func ptr[T any](v T) *T { return &v }
