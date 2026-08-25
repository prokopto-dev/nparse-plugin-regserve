package review

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/audit"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// The catalogue as a MODERATOR sees it, and the two acts a moderator performs on a listing.
//
// # Why this is not the directory
//
// internal/plugin answers "what is publicly visible": it drops a delisted id and an id with
// nothing approved, and counts them so the shortfall is never silent. That is the right answer for
// a visitor and the wrong one for a reviewer, because the rows it drops are the ones moderation is
// about. A registry's moderator who could only see what the public sees would be unable to find
// the id somebody claimed and never published, or the one somebody else already delisted.
//
// So this reads every plugin row, in every state, with its owners and the tier this registry
// currently holds each of them at.
//
// # Why delisting is moderation and not management
//
// An owner removing their own listing and a reviewer removing somebody else's are different acts
// that happen to write the same column, and the difference is the whole reason this lives here.
// `plugin.manage` is bounded by ownership (ADR-0005: effective capability is the intersection of
// the scope, the token's plugin pin and the account's ownership at request time) and therefore
// cannot express "somebody with no grant on this plugin takes it out of every client's index".
// Widening it until it could would mean a `plugin:manage` token that can delist a stranger's
// plugin, which is the escalation the capability floor exists to prevent.
//
// So the permission is `plugin.moderate`, it is capability-floor, and the audit row says WHICH ACT
// IT WAS rather than leaving an incident review to infer it from who happened to hold a grant at
// the time. See Delist.
//
// # What delisting is not
//
// It is not a delete, and it never can be. The plugin row IS the claim: an id is permanent,
// first-come and never recycled, because it names the plugin in every installed copy on every
// user's machine. Delisting clears the listing and keeps the claim, so a delisted id is spoken for
// for ever and by nobody else. The schema enforces this from underneath with a BEFORE DELETE
// trigger; this package never asks it to.

// Errors the moderation path returns.
var (
	// ErrNoSuchPlugin is an id that names nothing.
	ErrNoSuchPlugin = errors.New("no such plugin")

	// ErrAlreadyDelisted is a delisting of a listing that is already gone.
	//
	// Reported rather than treated as success, for the reason ErrNotPending is: two reviewers with
	// the same page open is the normal case, and a moderator told "done" when somebody else did it
	// is a moderator who does not know the reason on the row is not theirs.
	ErrAlreadyDelisted = errors.New("that plugin is already delisted")

	// ErrNotDelisted is a relisting of a plugin that was never delisted.
	ErrNotDelisted = errors.New("that plugin is not delisted")

	// ErrNoModerationReason is a delisting or a relisting with nothing written down.
	//
	// Required for BOTH directions, and the symmetry is deliberate. Delisting needs it because the
	// schema's CHECK will not store the timestamp without it and because a listing that vanishes
	// with no stated reason is indistinguishable from a bug. Relisting needs it because clearing
	// `delisted_at` also clears `delisted_reason` — after a relist the audit log is the ONLY
	// surviving record that the plugin was ever delisted or why it came back, and an unexplained
	// row there is a moderation decision nobody can review a year later.
	ErrNoModerationReason = errors.New("a moderation action must say why")
)

// The audit vocabulary for moderating a listing. One spelling each, like the release actions
// above, because an incident review queries audit_log on (subject_kind, subject_id).
const (
	subjectPlugin = "plugin"

	actionDelist = "plugin.delist"
	actionRelist = "plugin.relist"

	// detailActedAs is the key that says WHICH ACT a delisting was: moderation, or an owner
	// removing their own listing.
	//
	// It exists because both write the same column and only one of them is somebody acting on
	// another person's plugin. Inferring it later from whether the actor held a grant at the time
	// does not work — grants change, and an owner can be removed after the fact — so the row
	// records the answer rather than the evidence for it. Owner delisting is not built yet (see
	// the package comment); when it is, it writes the same action with actedAsOwner, and one query
	// on (subject_kind, subject_id) still answers "what has happened to this plugin".
	detailActedAs = "acted_as"

	// detailPermission names the permission the actor exercised, so the row says under what
	// authority as well as by whom.
	detailPermission = "permission"

	detailReason = "reason"

	// actedAsReviewer is the only value this package writes. The constant exists so the value and
	// the reason for it sit together.
	actedAsReviewer = "reviewer"

	// permModerate is the catalogue key the routes declare. Spelled here as a whole literal for
	// the same reason internal/authz spells its keys that way — grepping for a permission should
	// find every place it appears — while the catalogue in internal/authz stays the definition.
	permModerate = "plugin.moderate"
)

// maxModerationReasonBytes bounds a moderator's note. Same cap as a review note and a trust note,
// because it is read in the same places by the same people.
const maxModerationReasonBytes = 2048

// TrustFloor is the tier an account with no `account_trust` row holds.
//
// SPELLED HERE AND DEFINED IN internal/release, which is two places, and that is a deliberate
// trade rather than an oversight. internal/review does not import internal/release — the two are
// kept apart so that "how much this registry trusts somebody's releases" and "who may approve
// them" cannot become one dependency, and queue.go's ArtifactFetcher makes the same trade for the
// same reason. Borrowing one string literal is cheaper than taking on that direction of coupling.
//
// It is only safe because a test asserts the agreement through the REAL path: it sets a tier with
// release.Publisher.SetTrust and reads it back through this package. If the two ever disagree that
// test fails, rather than a reviewer page quietly showing the wrong tier next to a control that
// changes it. release.TrustOf is the authority on what the floor means.
const TrustFloor = "new"

// Plugins is the moderator's view of the catalogue, and the two writes that change a listing.
type Plugins struct {
	db  *store.DB
	clk clock.Clock
}

// NewPlugins builds the service.
func NewPlugins(db *store.DB, clk clock.Clock) *Plugins {
	return &Plugins{db: db, clk: clk}
}

// Holder is one ownership grant, as a moderator sees it.
type Holder struct {
	AccountID   string
	DisplayName string

	// Handle is the provider handle, refreshed at each login. It is what a human recognises and is
	// never what anything matches on.
	Handle string
	Role   string

	// Trust is the tier this registry currently holds this account at, never empty: an account
	// with no row reads as TrustFloor.
	//
	// It is here because the control that CHANGES a tier is offered on the same page, and a
	// control offered without the current value is a reviewer guessing. ADR-0007: the tier is a
	// property of the ACCOUNT and not of the plugin — the same person shows the same tier against
	// every plugin they hold, and the page says so rather than letting the layout imply otherwise.
	Trust string
}

// Listing is one plugin as a moderator sees it: every state, not only the visible ones.
type Listing struct {
	ID          string
	Name        string
	Description string
	Author      string
	Homepage    string
	ClaimedAt   time.Time

	// Delisted and DelistedAt/DelistedReason are the moderation state. Delisted is derived from
	// the timestamp rather than stored twice, so "is it delisted" and "when was it delisted"
	// cannot disagree.
	Delisted       bool
	DelistedAt     time.Time
	DelistedReason string

	// LiveVersion is what the index currently serves for this plugin, empty when nothing is
	// approved. A DELISTED plugin can still have one: the release stays approved and the listing
	// is what was removed, which is why the reviewer page can say "delisted, and 1.2.0 is what
	// would come back".
	LiveVersion string

	// Pending is how many releases of this plugin are waiting for a human.
	Pending int64

	// Owners is everybody holding the plugin, oldest grant first, each with their current tier.
	Owners []Holder
}

// Listed reports whether this plugin is in the public index right now.
//
// Both conditions, because both are reasons a plugin is not in it and they are different
// situations: one was removed and one has never had anything approved. A page that showed only the
// first would present a never-published id as though it were live.
func (l Listing) Listed() bool { return !l.Delisted && l.LiveVersion != "" }

// List returns every plugin this registry knows, in id order, with its owners.
//
// TWO STATEMENTS, NOT ONE PER PLUGIN. The owners of every plugin come back in a single read and
// are bucketed here, so the cost of this page does not grow with the number of plugins in the way
// a query-per-row would. The catalogue is tens of rows today; this is what stops it from being the
// page that gets slow first.
func (p *Plugins) List(ctx context.Context) ([]Listing, error) {
	rows, err := p.db.Read().ListPluginsForModeration(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the catalogue for moderation: %w", err)
	}

	owners, err := p.ownersByPlugin(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]Listing, 0, len(rows))
	for _, row := range rows {
		l := listingFrom(row)
		l.Owners = owners[row.ID]
		out = append(out, l)
	}
	return out, nil
}

// Get returns one plugin, mapping a miss onto ErrNoSuchPlugin.
func (p *Plugins) Get(ctx context.Context, pluginID string) (Listing, error) {
	row, err := p.db.Read().GetPluginForModeration(ctx, pluginID)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return Listing{}, ErrNoSuchPlugin
	case err != nil:
		return Listing{}, fmt.Errorf("read plugin %s for moderation: %w", pluginID, err)
	}

	owners, err := p.ownersByPlugin(ctx)
	if err != nil {
		return Listing{}, err
	}

	out := listingFrom(sqlitegen.ListPluginsForModerationRow(row))
	out.Owners = owners[pluginID]
	return out, nil
}

// Delist removes a plugin's listing as a moderator, keeping the claim.
//
// The audit row names the reviewer, the reason, and — through `acted_as` — that this was
// MODERATION rather than an owner removing their own listing. That last part is the one a later
// incident review cannot reconstruct: both acts write the same column, grants change afterwards,
// and "did they hold this plugin at the time" is not a question the schema keeps an answer to.
//
// The plugin row is never deleted and the owners are never touched. What changes is one timestamp
// and one sentence; the id stays claimed, permanently, by the same people.
func (p *Plugins) Delist(ctx context.Context, pluginID, reviewerID, reason string) error {
	reason, err := moderationReason(reason)
	if err != nil {
		return err
	}

	now := p.clk.Now()
	micros := core.MicrosFromTime(now).Int64()

	return p.db.Tx(ctx, func(q *store.Queries) error {
		row, err := p.pluginTx(ctx, q, pluginID)
		if err != nil {
			return err
		}

		changed, err := q.DelistPlugin(ctx, sqlitegen.DelistPluginParams{
			DelistedAt:     &micros,
			DelistedReason: &reason,
			UpdatedAt:      micros,
			ID:             pluginID,
		})
		if err != nil {
			return fmt.Errorf("delist plugin %s: %w", pluginID, err)
		}
		if changed == 0 {
			// The statement's WHERE requires it to still be listed, so zero rows means somebody
			// else delisted it between the read above and this write. Reported rather than
			// retried: the reason on the row is now theirs and not this reviewer's.
			return ErrAlreadyDelisted
		}

		return audit.Record(ctx, q, p.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   reviewerID,
			Action:      actionDelist,
			SubjectKind: subjectPlugin,
			SubjectID:   pluginID,
			Detail: map[string]any{
				detailActedAs:    actedAsReviewer,
				detailPermission: permModerate,
				detailReason:     reason,
				// What was taken out of the index, so the row says what the effect WAS rather than
				// only what was done. Empty means the plugin had nothing listed to remove, which
				// is a different act from removing a live listing and must not read the same.
				"delisted_version": row.LiveVersion,
			},
		})
	})
}

// Relist puts a delisted plugin's listing back.
//
// It restores nothing except the row's eligibility for the index, because nothing else was taken
// away: the releases, the owners and the claim were untouched throughout. A plugin that was
// delisted before it ever published relists to exactly where it was — claimed, awaiting review.
//
// The reason is required here as well as on the way out, and this is the direction where it
// matters most: relisting CLEARS `delisted_reason`, so after this runs the audit log is the only
// place that records the plugin was ever delisted at all.
func (p *Plugins) Relist(ctx context.Context, pluginID, reviewerID, reason string) error {
	reason, err := moderationReason(reason)
	if err != nil {
		return err
	}

	now := p.clk.Now()
	micros := core.MicrosFromTime(now).Int64()

	return p.db.Tx(ctx, func(q *store.Queries) error {
		row, err := p.pluginTx(ctx, q, pluginID)
		if err != nil {
			return err
		}

		changed, err := q.RelistPlugin(ctx, sqlitegen.RelistPluginParams{
			UpdatedAt: micros,
			ID:        pluginID,
		})
		if err != nil {
			return fmt.Errorf("relist plugin %s: %w", pluginID, err)
		}
		if changed == 0 {
			return ErrNotDelisted
		}

		return audit.Record(ctx, q, p.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   reviewerID,
			Action:      actionRelist,
			SubjectKind: subjectPlugin,
			SubjectID:   pluginID,
			Detail: map[string]any{
				detailActedAs:    actedAsReviewer,
				detailPermission: permModerate,
				detailReason:     reason,
				// The reason the plugin was delisted, carried forward into the row that undoes it,
				// because the column holding it is cleared by the statement above. Without this
				// the pair of audit rows would record that a listing came back and no longer say
				// what it came back from.
				"was_delisted_because": derefString(row.DelistedReason),
			},
		})
	})
}

// pluginTx reads a plugin inside the caller's transaction, mapping a miss onto ErrNoSuchPlugin.
//
// It runs before every write so that an id naming nothing is a sentence a moderator can act on
// rather than a silent zero-rows that is indistinguishable from "somebody got there first".
func (p *Plugins) pluginTx(
	ctx context.Context, q *store.Queries, pluginID string,
) (sqlitegen.GetPluginForModerationRow, error) {
	row, err := q.GetPluginForModeration(ctx, pluginID)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return sqlitegen.GetPluginForModerationRow{}, ErrNoSuchPlugin
	case err != nil:
		return sqlitegen.GetPluginForModerationRow{}, fmt.Errorf("read plugin %s: %w", pluginID, err)
	}
	return row, nil
}

// ownersByPlugin reads every grant in the registry, bucketed by plugin id.
func (p *Plugins) ownersByPlugin(ctx context.Context) (map[string][]Holder, error) {
	rows, err := p.db.Read().ListOwnersWithTrust(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the ownership grants for moderation: %w", err)
	}

	out := make(map[string][]Holder, len(rows))
	for _, row := range rows {
		out[row.PluginID] = append(out[row.PluginID], Holder{
			AccountID:   row.AccountID,
			DisplayName: row.DisplayName,
			Handle:      row.Handle,
			Role:        row.Role,
			Trust:       trustOrFloor(row.TrustLevel),
		})
	}
	return out, nil
}

// trustOrFloor reads an absent tier as the floor.
//
// The query LEFT JOINs account_trust and coalesces a missing row to the empty string, and empty is
// NOT a tier — it is "nobody has assessed this account". Rendering it as blank would make an
// unassessed publisher and a bug look alike on the one page whose job is to tell a reviewer what
// this registry has already decided about somebody. release.TrustOf makes exactly this reading for
// exactly this reason.
func trustOrFloor(level string) string {
	if strings.TrimSpace(level) == "" {
		return TrustFloor
	}
	return level
}

// moderationReason validates a moderator's note.
func moderationReason(raw string) (string, error) {
	reason := strings.TrimSpace(raw)
	switch {
	case reason == "":
		return "", ErrNoModerationReason
	case len(reason) > maxModerationReasonBytes:
		return "", fmt.Errorf("%w of %d bytes", errReasonTooLong, maxModerationReasonBytes)
	}
	return reason, nil
}

// listingFrom maps a row onto the domain type.
func listingFrom(row sqlitegen.ListPluginsForModerationRow) Listing {
	l := Listing{
		ID:             row.ID,
		Name:           row.Name,
		Description:    row.Description,
		Author:         row.Author,
		Homepage:       row.Homepage,
		ClaimedAt:      core.Micros(row.ClaimedAt).Time(),
		DelistedReason: derefString(row.DelistedReason),
		LiveVersion:    row.LiveVersion,
		Pending:        row.PendingReleases,
	}
	if row.DelistedAt != nil {
		l.Delisted = true
		l.DelistedAt = core.Micros(*row.DelistedAt).Time()
	}
	return l
}

// derefString reads an optional column, treating NULL and empty alike.
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
