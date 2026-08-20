package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/audit"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// SessionTTL is how long a session lives. It is ABSOLUTE and does not slide.
//
// Fourteen days is long enough that a plugin author managing tokens once a month is not logging in
// every visit, and short enough that a cookie copied off a shared machine stops working inside a
// fortnight. A sliding window would make it "forever, as long as somebody keeps using it", which
// is a credential with no expiry wearing an expiry's clothes.
const SessionTTL = 14 * 24 * time.Hour

// sessionTouchInterval is how stale `last_seen_at` may get before a read pays for a write.
//
// This database has ONE writer (ADR-0001). Updating the session on every authenticated request
// would put session bookkeeping in the write queue ahead of every publish, for a column nothing
// makes a decision on — it is shown on the account page so a human can spot a session they do not
// recognise. An hour is precise enough for that and costs at most one write per session per hour.
const sessionTouchInterval = time.Hour

// Sessions issues and resolves browser sessions.
type Sessions struct {
	db     *store.DB
	clk    clock.Clock
	pepper core.Secret
}

// NewSessions builds the session service. A missing pepper is fatal here rather than at the first
// login: see ErrNoPepper.
func NewSessions(db *store.DB, clk clock.Clock, pepper core.Secret) (*Sessions, error) {
	if err := requirePepper(pepper); err != nil {
		return nil, fmt.Errorf("session service: %w", err)
	}
	return &Sessions{db: db, clk: clk, pepper: pepper}, nil
}

// NewSession is a freshly minted session and the one moment its secret exists outside a browser.
type NewSession struct {
	// Secret is the cookie value. It is returned exactly once, is never stored, and must not be
	// logged, rendered, or put in an error message.
	Secret string

	// ExpiresAt is when the session stops being accepted. It is also the cookie's Max-Age, so the
	// browser and the database agree on the deadline rather than the browser holding a cookie the
	// server has already stopped honouring.
	ExpiresAt time.Time
}

// Create issues a session for accountID and records the login.
//
// The audit row and the session row share one transaction. "Somebody is signed in and nothing says
// when they signed in" is a state this table exists to make unreachable.
func (s *Sessions) Create(ctx context.Context, accountID string) (NewSession, error) {
	secret, err := newSecret()
	if err != nil {
		return NewSession{}, err
	}

	now := s.clk.Now()
	expires := now.Add(SessionTTL)

	id, err := core.NewULID(now)
	if err != nil {
		return NewSession{}, fmt.Errorf("mint a session id: %w", err)
	}

	err = s.db.Tx(ctx, func(q *store.Queries) error {
		// Swept here rather than on a timer: a login is the one moment this service is certainly
		// awake and certainly writing, and a background sweeper is a goroutine to leak.
		if err := q.DeleteExpiredSessions(ctx, core.MicrosFromTime(now).Int64()); err != nil {
			return fmt.Errorf("sweep expired sessions: %w", err)
		}
		if err := q.InsertSession(ctx, sqlitegen.InsertSessionParams{
			ID:         id.String(),
			AccountID:  accountID,
			TokenHash:  keyedHash(s.pepper, secret),
			CreatedAt:  core.MicrosFromTime(now).Int64(),
			LastSeenAt: core.MicrosFromTime(now).Int64(),
			ExpiresAt:  core.MicrosFromTime(expires).Int64(),
		}); err != nil {
			return fmt.Errorf("record the session: %w", err)
		}
		// The session id is deliberately NOT in the detail. It is a credential-adjacent value
		// canonical §10 forbids logging, and this table is the one nobody can redact later.
		return audit.Record(ctx, q, s.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   accountID,
			Action:      "session.start",
			SubjectKind: subjectAccount,
			SubjectID:   accountID,
		})
	})
	if err != nil {
		return NewSession{}, err
	}

	return NewSession{Secret: secret, ExpiresAt: expires}, nil
}

// Resolve turns a cookie value into a principal.
//
// Every rejection returns ErrCredentialRejected, whatever the reason. A caller that could tell
// "expired" from "never existed" could tell a stolen cookie from a fabricated one, and there is
// nothing a legitimate user does with that distinction that logging in again does not cover.
func (s *Sessions) Resolve(ctx context.Context, secret string) (Principal, error) {
	if secret == "" {
		return Principal{}, ErrNoCredential
	}

	row, err := s.db.Read().GetSessionByTokenHash(ctx, keyedHash(s.pepper, secret))
	switch {
	case errors.Is(err, store.ErrNoRows):
		return Principal{}, ErrCredentialRejected
	case err != nil:
		return Principal{}, fmt.Errorf("read the session: %w", err)
	}

	now := s.clk.Now()
	switch {
	case row.RevokedAt != nil,
		row.DisabledAt != nil,
		core.Micros(row.ExpiresAt).Time().Before(now):
		return Principal{}, ErrCredentialRejected
	}

	// A best-effort write on a read path. A failure to record that a session was seen is not a
	// reason to refuse a request that is otherwise valid, so it is logged by the caller of Touch
	// rather than returned — but the error is not discarded silently either.
	if err := s.touch(ctx, row.ID, core.Micros(row.LastSeenAt).Time(), now); err != nil {
		return Principal{}, err
	}

	return Principal{
		AccountID:   row.AccountID,
		DisplayName: row.DisplayName,
		SessionID:   row.ID,
	}, nil
}

// touch refreshes last_seen_at, at most once per sessionTouchInterval.
func (s *Sessions) touch(ctx context.Context, id string, lastSeen, now time.Time) error {
	if now.Sub(lastSeen) < sessionTouchInterval {
		return nil
	}
	err := s.db.Tx(ctx, func(q *store.Queries) error {
		return q.TouchSession(ctx, sqlitegen.TouchSessionParams{
			LastSeenAt: core.MicrosFromTime(now).Int64(),
			ID:         id,
		})
	})
	if err != nil {
		return fmt.Errorf("touch the session: %w", err)
	}
	return nil
}

// Revoke ends a session and records it.
//
// The row is kept rather than deleted: "this session was ended at 14:02" and "this session was
// never here" are different answers to the question somebody asks after an account is misused.
func (s *Sessions) Revoke(ctx context.Context, p Principal) error {
	if p.SessionID == "" {
		return ErrNoCredential
	}
	now := core.MicrosFromTime(s.clk.Now()).Int64()

	return s.db.Tx(ctx, func(q *store.Queries) error {
		revoked, err := q.RevokeSession(ctx, sqlitegen.RevokeSessionParams{
			RevokedAt: &now,
			ID:        p.SessionID,
		})
		if err != nil {
			return fmt.Errorf("revoke the session: %w", err)
		}
		if revoked == 0 {
			// Already revoked, or gone. Signing out twice is not an error a browser should see —
			// but it is also not a second sign-out, and audit_log is the one table where a row
			// recording something that did not happen cannot be taken back.
			return nil
		}
		return audit.Record(ctx, q, s.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   p.AccountID,
			Action:      "session.end",
			SubjectKind: subjectAccount,
			SubjectID:   p.AccountID,
		})
	})
}

// List returns the account's sessions, newest first, for the account page.
//
// It returns no secrets and no hashes — there is nothing here that could authenticate anything.
func (s *Sessions) List(ctx context.Context, accountID string) ([]sqlitegen.ListSessionsForAccountRow, error) {
	rows, err := s.db.Read().ListSessionsForAccount(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("list the sessions for %s: %w", accountID, err)
	}
	return rows, nil
}

// CSRFFieldName is the form field the token travels in. It is also the name the templates use, so
// it is a constant rather than a string written twice.
const CSRFFieldName = "csrf_token"

// csrfPurpose separates the CSRF key from every other use of the pepper.
//
// The pepper keys credential hashes, whose inputs are 32 random bytes. A CSRF token's input is a
// session id, which is not secret from the server and is a much smaller space. Prefixing the
// message means a CSRF token can never collide with, or be mistaken for, a stored credential hash
// even though both are HMAC-SHA256 under the same key.
const csrfPurpose = "csrf:v1:"

// CSRFToken returns the token a form must carry back.
//
// It is derived from the session rather than stored, so there is no table, no expiry to manage and
// nothing to clean up: a token is valid exactly as long as the session it was minted for. It is
// bound to the session id, so a token from somebody else's session does not match.
//
// This is the SECOND CSRF defence, not the only one. The session cookie is SameSite=Lax, which
// already withholds it from a cross-site POST in every browser that matters. Lax is a browser
// behaviour we do not control and cannot test in CI; this is one we do and can, and the classic
// hole is exactly "a session cookie plus a form post".
func (s *Sessions) CSRFToken(p Principal) string {
	if p.SessionID == "" {
		return ""
	}
	return keyedHash(s.pepper, csrfPurpose+p.SessionID)
}

// CheckCSRF reports whether presented is the token for this session, compared in constant time.
//
// A principal with no session — a personal access token — can never satisfy it. That is not the
// mechanism protecting the account surface (every one of its routes is capability-floor and
// refuses a token outright), but a CSRF check that silently passed for a credential kind it was
// never designed for would be a hole waiting for the first route that forgets.
func (s *Sessions) CheckCSRF(p Principal, presented string) bool {
	want := s.CSRFToken(p)
	if want == "" || presented == "" {
		return false
	}
	return equalHash(want, presented)
}
