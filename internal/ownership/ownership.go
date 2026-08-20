// Package ownership answers who may change a plugin's listing.
//
// The property it exists to keep is the one the static registry had and this service must not
// quietly lose (docs/concepts/trust-model.md): only an owner can change a listing. There, it was a
// CI job comparing a pull request's author against `owners.json` at the base revision. Here it is
// a row, checked PER REQUEST at the moment of the change (ADR-0005) — so removing an owner takes
// effect on their next call rather than after a sweep somebody has to remember to run.
//
// Changing owners is a capability-floor operation (canonical §5). No token can do it, however
// scoped, because a token that could hand a plugin to somebody else would be equivalent to the
// account. This package does not re-derive that rule; the route declares it and the middleware
// enforces it, and two copies of "who may transfer a plugin" is one copy too many.
package ownership

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/audit"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// Role is what a grant lets somebody do. The values are the database's `CHECK`.
type Role string

const (
	// RoleOwner may change the listing and manage the owners.
	RoleOwner Role = "owner"

	// RoleMaintainer may publish, and may not change who the owners are. It exists so that a
	// co-maintainer can be added without handing over the plugin.
	RoleMaintainer Role = "maintainer"
)

func (r Role) String() string { return string(r) }

// Valid reports whether r is a role the database will accept.
func (r Role) Valid() bool { return r == RoleOwner || r == RoleMaintainer }

// Errors this package returns.
var (
	// ErrNotAnOwner is the caller not holding the plugin. It is what the settings page turns into
	// a 404 rather than a 403: telling somebody "that plugin exists and is not yours" enumerates
	// plugins for anybody with a list of ids.
	ErrNotAnOwner = errors.New("not an owner of this plugin")

	// ErrNoSuchAccount is a handle nobody has signed in with. Granting ownership to a handle that
	// has never authenticated here would be granting it to whoever registers that name next.
	ErrNoSuchAccount = errors.New("no account has signed in with that handle")

	// ErrAlreadyAnOwner is a duplicate grant. Reported rather than ignored, because "I added them
	// and nothing happened" and "they were already there" are different things to explain.
	ErrAlreadyAnOwner = errors.New("already an owner of this plugin")

	// ErrLastOwner is a removal that would leave the plugin with nobody.
	//
	// A plugin id is permanent and can never be recycled, so an ownerless plugin is not a plugin
	// somebody else can take over — it is a listing nobody can update or delist, for ever, and the
	// only repair is a maintainer writing SQL. Transfers are add-then-remove for this reason.
	ErrLastOwner = errors.New("a plugin cannot be left with no owners")

	// ErrAccountDisabled is a grant to an account somebody has switched off.
	ErrAccountDisabled = errors.New("that account is disabled")
)

// The audit vocabulary this package writes. One spelling each: an incident review queries on
// (subject_kind, subject_id), and a second spelling would put half the rows somewhere nobody looks.
const (
	subjectPlugin = "plugin"
	detailAccount = "account"
	detailHandle  = "handle"
)

// Service reads and changes plugin ownership.
type Service struct {
	db  *store.DB
	clk clock.Clock
}

// New builds the service.
func New(db *store.DB, clk clock.Clock) *Service { return &Service{db: db, clk: clk} }

// Plugin is one row of the account page's "your plugins".
type Plugin struct {
	ID   string
	Name string
	Role Role

	// Listed is false for a delisted plugin. It is shown rather than hidden: the id is still
	// claimed and the owner still owns it, and a page that hid it would be telling somebody their
	// plugin was gone.
	Listed bool

	// HasApprovedRelease says whether anything of this plugin is in the index. A claimed id with
	// nothing approved behind it is the normal state of a new submission, and it is also what a
	// stuck review looks like — so it is visible rather than inferred from an absence.
	HasApprovedRelease bool

	GrantedAt time.Time
}

// Mine returns the plugins an account holds, by id.
func (s *Service) Mine(ctx context.Context, accountID string) ([]Plugin, error) {
	rows, err := s.db.Read().ListPluginsForAccount(ctx, accountID)
	if err != nil {
		return nil, fmt.Errorf("list the plugins for %s: %w", accountID, err)
	}

	out := make([]Plugin, 0, len(rows))
	for _, row := range rows {
		out = append(out, Plugin{
			ID:                 row.ID,
			Name:               row.Name,
			Role:               Role(row.Role),
			Listed:             row.DelistedAt == nil,
			HasApprovedRelease: row.ApprovedReleases > 0,
			GrantedAt:          core.Micros(row.GrantedAt).Time(),
		})
	}
	return out, nil
}

// Owner is one grant, as the settings page shows it.
type Owner struct {
	AccountID   string
	DisplayName string

	// Handle is the provider handle, refreshed at each login. It is what a human recognises; it is
	// never what anything matches on.
	Handle    string
	Role      Role
	GrantedAt time.Time
}

// Owners returns everybody who holds a plugin, oldest grant first.
//
// It requires the caller to be an owner. Ownership of a plugin is not secret — the index says who
// authored it — but the list of ACCOUNTS holding it is a list of people to target, and there is no
// reason for it to be readable by anybody who is not on it.
func (s *Service) Owners(ctx context.Context, pluginID, callerID string) ([]Owner, error) {
	if err := s.requireOwner(ctx, pluginID, callerID); err != nil {
		return nil, err
	}

	rows, err := s.db.Read().ListOwnersForPlugin(ctx, pluginID)
	if err != nil {
		return nil, fmt.Errorf("list the owners of %s: %w", pluginID, err)
	}

	out := make([]Owner, 0, len(rows))
	for _, row := range rows {
		out = append(out, Owner{
			AccountID:   row.AccountID,
			DisplayName: row.DisplayName,
			Handle:      row.Handle,
			Role:        Role(row.Role),
			GrantedAt:   core.Micros(row.GrantedAt).Time(),
		})
	}
	return out, nil
}

// Add grants a plugin to the account behind a provider handle.
//
// The handle is resolved to an account that has already signed in. There is no invitation and no
// grant-by-name: a row naming a handle nobody has proved they hold is a row that hands the plugin
// to whoever registers that name next, which is the failure the whole identity model exists to
// prevent.
func (s *Service) Add(ctx context.Context, pluginID, callerID, handle string, role Role) error {
	if !role.Valid() {
		return fmt.Errorf("%q is not a role", role)
	}
	handle = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(handle), "@"))
	if handle == "" {
		return ErrNoSuchAccount
	}

	now := s.clk.Now()

	return s.db.Tx(ctx, func(q *store.Queries) error {
		if err := requireOwnerTx(ctx, q, pluginID, callerID); err != nil {
			return err
		}

		target, err := q.GetAccountByHandle(ctx, sqlitegen.GetAccountByHandleParams{
			ProviderKind: identity.KindGitHub.String(),
			Handle:       handle,
		})
		switch {
		case errors.Is(err, store.ErrNoRows):
			return ErrNoSuchAccount
		case err != nil:
			return fmt.Errorf("resolve the handle %s: %w", handle, err)
		case target.DisabledAt != nil:
			return ErrAccountDisabled
		}

		if _, err := q.GetPluginOwner(ctx, sqlitegen.GetPluginOwnerParams{
			PluginID:  pluginID,
			AccountID: target.ID,
		}); err == nil {
			return ErrAlreadyAnOwner
		} else if !errors.Is(err, store.ErrNoRows) {
			return fmt.Errorf("check the existing grant: %w", err)
		}

		if err := q.InsertPluginOwner(ctx, sqlitegen.InsertPluginOwnerParams{
			PluginID:  pluginID,
			AccountID: target.ID,
			Role:      role.String(),
			GrantedAt: core.MicrosFromTime(now).Int64(),
			GrantedBy: &callerID,
		}); err != nil {
			return fmt.Errorf("grant %s to %s: %w", pluginID, handle, err)
		}

		return audit.Record(ctx, q, s.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   callerID,
			Action:      "owner.add",
			SubjectKind: subjectPlugin,
			SubjectID:   pluginID,
			Detail: map[string]any{
				detailAccount: target.ID,
				detailHandle:  target.Handle,
				"role":        role.String(),
			},
		})
	})
}

// Remove revokes a grant.
//
// It refuses to remove the last owner. An ownerless plugin is not a plugin somebody else can take
// over — ids are never recycled — it is a listing nobody can update or delist, and the only repair
// is a maintainer writing SQL against production.
func (s *Service) Remove(ctx context.Context, pluginID, callerID, targetID string) error {
	return s.db.Tx(ctx, func(q *store.Queries) error {
		if err := requireOwnerTx(ctx, q, pluginID, callerID); err != nil {
			return err
		}

		owners, err := q.CountOwnersForPlugin(ctx, pluginID)
		if err != nil {
			return fmt.Errorf("count the owners of %s: %w", pluginID, err)
		}
		if owners <= 1 {
			return ErrLastOwner
		}

		removed, err := q.DeletePluginOwner(ctx, sqlitegen.DeletePluginOwnerParams{
			PluginID:  pluginID,
			AccountID: targetID,
		})
		if err != nil {
			return fmt.Errorf("remove the owner of %s: %w", pluginID, err)
		}
		if removed == 0 {
			return ErrNotAnOwner
		}

		// The removed account is recorded, and so is who did it. This is the row somebody reads
		// when a handover is disputed, and `granted_by` on the surviving rows is only half of it.
		return audit.Record(ctx, q, s.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   callerID,
			Action:      "owner.remove",
			SubjectKind: subjectPlugin,
			SubjectID:   pluginID,
			Detail:      map[string]any{detailAccount: targetID},
		})
	})
}

// IsOwner reports whether an account holds a plugin. It is the per-request check ADR-0005 wants.
func (s *Service) IsOwner(ctx context.Context, pluginID, accountID string) (bool, error) {
	_, err := s.db.Read().GetPluginOwner(ctx, sqlitegen.GetPluginOwnerParams{
		PluginID:  pluginID,
		AccountID: accountID,
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("check ownership of %s: %w", pluginID, err)
	}
	return true, nil
}

func (s *Service) requireOwner(ctx context.Context, pluginID, accountID string) error {
	held, err := s.IsOwner(ctx, pluginID, accountID)
	switch {
	case err != nil:
		return err
	case !held:
		return ErrNotAnOwner
	}
	return nil
}

// requireOwnerTx is the same check inside a transaction, so the caller's ownership and the change
// it authorises are decided against the same snapshot. Checking outside would leave a window in
// which an owner removed a moment ago still gets one more write.
func requireOwnerTx(ctx context.Context, q *store.Queries, pluginID, accountID string) error {
	_, err := q.GetPluginOwner(ctx, sqlitegen.GetPluginOwnerParams{
		PluginID:  pluginID,
		AccountID: accountID,
	})
	switch {
	case errors.Is(err, store.ErrNoRows):
		return ErrNotAnOwner
	case err != nil:
		return fmt.Errorf("check ownership of %s: %w", pluginID, err)
	}
	return nil
}
