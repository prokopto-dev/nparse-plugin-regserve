package release

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/audit"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// Trust is what this service is willing to automate for an account (ADR-0007).
//
// It governs ONE thing: whether a version bump of an ALREADY-APPROVED plugin can publish without a
// human. It never governs the first appearance of a plugin id, and it never governs who may
// moderate — that is `internal/review`, deliberately kept separate, because a tier that did both
// would let a trusted publisher approve their own submissions.
//
// IT IS NEVER RAISED AUTOMATICALLY. A counter of successful publishes is a counter an attacker can
// run up: publish four harmless releases, earn the tier, publish the fifth. Trust is a judgement a
// human makes about a person, and the only way to change it is a reviewer deciding to.
type Trust string

const (
	// TrustBlocked is an explicit refusal. It is BELOW the default, not the absence of one: an
	// account here cannot publish at all, and saying so is the point.
	TrustBlocked Trust = "blocked"

	// TrustNew is the floor and the default for an account with no row at all. Everything it
	// publishes goes to review.
	TrustNew Trust = "new"

	// TrustTrusted is an account whose version bumps of an already-approved plugin publish without
	// a human, provided no quarantine rule fires.
	TrustTrusted Trust = "trusted"
)

func (t Trust) String() string { return string(t) }

// Valid reports whether t is a tier the database will accept.
func (t Trust) Valid() bool {
	return t == TrustBlocked || t == TrustNew || t == TrustTrusted
}

// ParseTrust validates a submitted tier.
func ParseTrust(s string) (Trust, error) {
	t := Trust(strings.ToLower(strings.TrimSpace(s)))
	if !t.Valid() {
		return "", fmt.Errorf("%w: %q is not one of %s, %s, %s",
			ErrBadTrustLevel, s, TrustBlocked, TrustNew, TrustTrusted)
	}
	return t, nil
}

// Errors the trust path returns.
var (
	// ErrBadTrustLevel is a tier that is not one.
	ErrBadTrustLevel = errors.New("not a trust level")

	// ErrAccountBlocked is a publish by an account somebody has explicitly blocked.
	//
	// It is refused BEFORE the artifact is fetched, so a blocked account cannot make this server
	// spend forty-five seconds and fifty megabytes on their behalf. That is not an optimisation:
	// an endpoint that downloads a stranger's URL for a stranger it has already refused is a
	// bandwidth amplifier with an authentication step in front of it.
	ErrAccountBlocked = errors.New("this account may not publish")

	// ErrNoSuchAccount is a trust change aimed at an account id that names nothing.
	ErrNoSuchAccount = errors.New("no such account")

	// ErrNoTrustReason is a trust change with nothing written down.
	//
	// A tier with no stated reason is one nobody can review later, and the schema keeps a `note`
	// column for exactly that. Raising somebody to trusted is the decision that most needs to be
	// explainable a year afterwards.
	ErrNoTrustReason = errors.New("a trust change must say why")
)

const (
	actionTrustSet    = "trust.set"
	subjectAccountKnd = "account"
	maxTrustNoteBytes = 2048
)

// TrustOf returns an account's tier.
//
// An account with no row is TrustNew. That is the floor, and reading it as anything else would
// mean the default depended on whether somebody had happened to look at the account before.
func (p *Publisher) TrustOf(ctx context.Context, accountID string) (Trust, error) {
	row, err := p.db.Read().GetAccountTrust(ctx, accountID)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return TrustNew, nil
	case err != nil:
		return "", fmt.Errorf("read the trust level of %s: %w", accountID, err)
	}

	level := Trust(row.Level)
	if !level.Valid() {
		// The column has a CHECK, so this is a row that arrived by a route nobody has thought of.
		// Reading it as the floor rather than as trusted is the only safe direction to be wrong in.
		return TrustNew, nil
	}
	return level, nil
}

// SetTrust records a reviewer's judgement about an account.
//
// The `set_by` column names the reviewer and an audit_log row records the change, because
// account_trust is an upsert and therefore carries only the CURRENT tier — the history lives in
// the table nothing can edit.
func (p *Publisher) SetTrust(ctx context.Context, accountID string, level Trust, reviewerID, note string) error {
	if !level.Valid() {
		return fmt.Errorf("%w: %q", ErrBadTrustLevel, level)
	}
	note = strings.TrimSpace(note)
	switch {
	case note == "":
		return ErrNoTrustReason
	case len(note) > maxTrustNoteBytes:
		return fmt.Errorf("the reason exceeds %d bytes", maxTrustNoteBytes)
	}

	now := p.clk.Now()

	return p.db.Tx(ctx, func(q *store.Queries) error {
		// The account has to exist. Without this the foreign key would refuse the insert with a
		// constraint message, and a reviewer who mistyped an id would get a driver error rather
		// than "no such account".
		if _, err := q.GetAccount(ctx, accountID); err != nil {
			if errors.Is(err, store.ErrNoRows) {
				return ErrNoSuchAccount
			}
			return fmt.Errorf("read account %s: %w", accountID, err)
		}

		previous, err := p.trustTx(ctx, q, accountID)
		if err != nil {
			return err
		}

		if err := q.SetAccountTrust(ctx, sqlitegen.SetAccountTrustParams{
			AccountID: accountID,
			Level:     level.String(),
			SetAt:     core.MicrosFromTime(now).Int64(),
			SetBy:     &reviewerID,
			Note:      &note,
		}); err != nil {
			return fmt.Errorf("set the trust level of %s: %w", accountID, err)
		}

		return audit.Record(ctx, q, p.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   reviewerID,
			Action:      actionTrustSet,
			SubjectKind: subjectAccountKnd,
			SubjectID:   accountID,
			Detail: map[string]any{
				// BOTH tiers. "Raised to trusted" and "lowered to trusted" are different events and
				// the row has to answer which without anybody reconstructing it from timestamps.
				"from":   previous.String(),
				"to":     level.String(),
				"reason": note,
			},
		})
	})
}

// trustTx reads a tier inside the caller's transaction.
func (p *Publisher) trustTx(ctx context.Context, q *store.Queries, accountID string) (Trust, error) {
	row, err := q.GetAccountTrust(ctx, accountID)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return TrustNew, nil
	case err != nil:
		return "", fmt.Errorf("read the trust level of %s: %w", accountID, err)
	}
	if level := Trust(row.Level); level.Valid() {
		return level, nil
	}
	return TrustNew, nil
}
