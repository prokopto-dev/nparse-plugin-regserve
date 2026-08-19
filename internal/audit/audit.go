// Package audit writes the append-only record of who did what.
//
// It exists so that there is ONE way to write an audit row. Two packages that each build their own
// INSERT will eventually disagree about what `actor_kind = 'system'` means or forget that `detail`
// is a JSON object, and the table that has to answer "who approved these exact bytes, and when"
// years later is the worst place for two conventions.
//
// The rules this package keeps, each of which the database also enforces so that a second writer
// arriving by another route still cannot break them:
//
//   - APPEND ONLY. There is one function and it inserts. BEFORE UPDATE and BEFORE DELETE triggers
//     abort anything else, and tests in internal/store assert that they fire.
//   - actor_account_id IS SET EXACTLY WHEN actor_kind IS 'account'. A CHECK says the same thing;
//     this catches it at the call site, where the caller can still say which it meant.
//   - `detail` NEVER CARRIES A SECRET. A token secret, a session id, an OAuth access token, a
//     client secret or the pepper in this table is unredactable — the triggers that make it
//     trustworthy are the same triggers that make it impossible to clean up.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// ActorKind is who performed the action.
type ActorKind string

const (
	// ActorAccount is a signed-in account or a token belonging to one.
	ActorAccount ActorKind = "account"

	// ActorSystem is the service acting with no account behind it: a migration, the boot-time
	// import of the static catalogue. It is not a fallback for "we did not look up who" — an
	// action recorded as the system when a person did it is a false alibi.
	ActorSystem ActorKind = "system"
)

// ErrActorMismatch is a call that names an account for a system action, or omits one for an
// account action. It is an error rather than a silent normalisation because the two mean opposite
// things to whoever reads the row during an incident.
var ErrActorMismatch = errors.New("actor kind and account id disagree")

// Entry is one row.
type Entry struct {
	// Actor and AccountID must agree: an account action names an account, a system action does not.
	Actor     ActorKind
	AccountID string

	// Action is `<resource>.<action>`, the same spelling as a permission (canonical §12). It is
	// free text in the database today; the CHECK that would close it is deliberately not there —
	// see docs/concepts/invariants.md for why adding one to this table is more dangerous than the
	// looseness it would remove.
	Action string

	// SubjectKind and SubjectID say what the action was done TO. SubjectID is optional: a login
	// has an account subject with an id, an import has a `catalogue` subject with none.
	SubjectKind string
	SubjectID   string

	// Detail is marshalled to a JSON object. It must never carry a secret; see the package comment.
	Detail map[string]any
}

// Record writes e inside the caller's transaction.
//
// It takes a *store.Queries rather than a *store.DB on purpose: an audit row and the change it
// records have to commit together or not at all. A helper that opened its own transaction would
// make "the release was approved but nothing says by whom" a reachable state.
func Record(ctx context.Context, q *store.Queries, clk clock.Clock, e Entry) error {
	switch {
	case e.Actor == ActorAccount && e.AccountID == "":
		return fmt.Errorf("%w: %s names no account", ErrActorMismatch, e.Action)
	case e.Actor == ActorSystem && e.AccountID != "":
		return fmt.Errorf("%w: %s is a system action and names an account", ErrActorMismatch, e.Action)
	case e.Actor != ActorAccount && e.Actor != ActorSystem:
		return fmt.Errorf("%w: %q is not an actor kind", ErrActorMismatch, e.Actor)
	}

	now := clk.Now()
	id, err := core.NewULID(now)
	if err != nil {
		return fmt.Errorf("mint an audit id for %s: %w", e.Action, err)
	}

	params := sqlitegen.InsertAuditLogParams{
		ID:          id.String(),
		RecordedAt:  core.MicrosFromTime(now).Int64(),
		ActorKind:   string(e.Actor),
		Action:      e.Action,
		SubjectKind: e.SubjectKind,
	}
	if e.AccountID != "" {
		params.ActorAccountID = &e.AccountID
	}
	if e.SubjectID != "" {
		params.SubjectID = &e.SubjectID
	}
	if len(e.Detail) > 0 {
		raw, err := json.Marshal(e.Detail)
		if err != nil {
			return fmt.Errorf("render the audit detail for %s: %w", e.Action, err)
		}
		detail := string(raw)
		params.Detail = &detail
	}

	if err := q.InsertAuditLog(ctx, params); err != nil {
		return fmt.Errorf("record %s in the audit log: %w", e.Action, err)
	}
	return nil
}
