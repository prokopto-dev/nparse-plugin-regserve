package review

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/audit"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// Errors the queue returns.
var (
	// ErrNoSuchRelease is an id that names nothing.
	ErrNoSuchRelease = errors.New("no such release")

	// ErrNotPending is a release somebody else already decided, or one that was never waiting.
	//
	// It is reported rather than retried. Two reviewers with the queue open is the normal case,
	// and "somebody approved this while you were reading it" is a thing a person needs told —
	// silently doing nothing would leave them believing they had acted.
	ErrNotPending = errors.New("that release is no longer waiting for review")

	// ErrNoReason is a rejection with nothing written down.
	//
	// A rejection with no reason is indistinguishable from a mistake to the author, who cannot see
	// the queue and has no other way to learn what to fix. Approvals may be silent; refusals may
	// not.
	ErrNoReason = errors.New("a rejection must say why")

	// ErrNotVerified is an attempt to approve a release whose artifact this server never hashed.
	//
	// THE DATABASE REFUSES THIS ANYWAY — release_approved_has_a_hash — and that is the mechanism.
	// This check exists so the answer is a sentence a reviewer can act on rather than a constraint
	// name, and so the re-verify path can be suggested by the thing that refused them.
	ErrNotVerified = errors.New("that release cannot be approved: its artifact was never verified")

	// ErrAlreadyVerified is a re-verification of a release that already has a hash.
	//
	// Refused, and the refusal is load-bearing rather than tidiness: a stored hash is what every
	// client verifies against, so a path that could recompute one is a path that could swap the
	// bytes behind a listing without anybody reviewing the swap. Re-verification can only ever
	// fill in a blank.
	ErrAlreadyVerified = errors.New("that release has already been verified")
)

// The audit vocabulary. One spelling each: an incident review queries audit_log on
// (subject_kind, subject_id), and a second spelling puts half the rows out of reach.
const (
	subjectRelease = "release"

	actionApprove  = "release.approve"
	actionReject   = "release.reject"
	actionReverify = "release.reverify"

	// The audit detail's keys. One spelling each, for the same reason the actions have one: an
	// incident review reads these objects by hand, and two spellings of "which plugin" means
	// half the rows do not answer the question that was asked.
	detailPlugin  = "plugin"
	detailVersion = "version"
)

// maxReasonBytes bounds a reviewer's note. It is stored in review_note, which has no CHECK of its
// own, and it is read by the author — so it is capped where the notes column is capped, for the
// same reason.
const maxReasonBytes = 2048

// ArtifactFetcher is what re-verification needs. Declared here rather than imported from
// internal/release so the two packages do not depend on each other; both are satisfied by the one
// *artifact.Fetcher the binary builds.
type ArtifactFetcher interface {
	Fetch(ctx context.Context, rawURL string) (artifact.Result, error)
}

// Queue is the review queue.
type Queue struct {
	db      *store.DB
	clk     clock.Clock
	fetcher ArtifactFetcher
}

// NewQueue builds the service.
func NewQueue(db *store.DB, clk clock.Clock, fetcher ArtifactFetcher) *Queue {
	return &Queue{db: db, clk: clk, fetcher: fetcher}
}

// Waiting is one entry in the queue, as a reviewer sees it.
type Waiting struct {
	ReleaseID  string
	PluginID   string
	PluginName string
	Version    string

	ArtifactURL string

	// SHA256 is the hash this server computed, empty when it never managed to. Empty is the
	// interesting case: it is the one a reviewer cannot approve.
	SHA256 string
	Bytes  *int64

	// Verified says whether the artifact was fetched and hashed. A queue that did not show this
	// would send reviewers into a constraint violation.
	Verified bool

	// FirstRelease says this plugin has nothing approved yet. It is the strongest signal in the
	// queue: a new id is where impersonation is caught, and ADR-0007 says nothing bypasses that
	// review — not trust, not automation, not an owner who has published fifty times.
	FirstRelease bool

	SubmittedBy string

	// SubmittedByHandle is the GitHub handle behind SubmittedBy, empty when the account has none.
	//
	// DECORATION, and never what anything matches on -- the account id is the identity and this is
	// refreshed at each login. It is here because the decisions taken from these pages are about a
	// PERSON: a reviewer marking somebody trusted from a queue of ULIDs is a reviewer guessing,
	// and the query this reads was written for exactly that and then never called.
	SubmittedByHandle string

	SubmittedAt time.Time
	Note        string
}

// List returns everything waiting, oldest first.
func (q *Queue) List(ctx context.Context) ([]Waiting, error) {
	rows, err := q.db.Read().ListPendingReleases(ctx)
	if err != nil {
		return nil, fmt.Errorf("read the review queue: %w", err)
	}

	// One lookup per DISTINCT submitter rather than one per row: the same account usually holds
	// several of the plugins in a queue, and a handle that is decoration should not cost a query
	// per line to render.
	handles, err := q.handlesOf(ctx, rows)
	if err != nil {
		return nil, err
	}

	out := make([]Waiting, 0, len(rows))
	for _, row := range rows {
		w := Waiting{
			ReleaseID:    row.ID,
			PluginID:     row.PluginID,
			PluginName:   row.PluginName,
			Version:      row.Version,
			ArtifactURL:  row.ArtifactUrl,
			Bytes:        row.ArtifactBytes,
			Verified:     row.VerifiedAt != nil,
			FirstRelease: row.ApprovedReleases == 0,
			SubmittedAt:  core.Micros(row.SubmittedAt).Time(),
		}
		if row.ArtifactSha256 != nil {
			w.SHA256 = *row.ArtifactSha256
		}
		if row.SubmittedBy != nil {
			w.SubmittedBy = *row.SubmittedBy
			w.SubmittedByHandle = handles[*row.SubmittedBy]
		}
		if row.ReviewNote != nil {
			w.Note = *row.ReviewNote
		}
		out = append(out, w)
	}
	return out, nil
}

// handlesOf reads the GitHub handle behind each distinct submitter in a queue listing.
//
// An account that names nothing yields an empty handle rather than an error -- see handleOf -- so
// the only failure that reaches the caller here is a database that could not be read, and the
// listing above would already have failed on that. It is propagated rather than swallowed for
// exactly that reason: there is no case left where hiding it would still leave a working queue.
func (q *Queue) handlesOf(ctx context.Context, rows []sqlitegen.ListPendingReleasesRow) (map[string]string, error) {
	handles := make(map[string]string, len(rows))
	for _, row := range rows {
		if row.SubmittedBy == nil {
			continue
		}
		if _, seen := handles[*row.SubmittedBy]; seen {
			continue
		}
		handle, err := q.handleOf(ctx, *row.SubmittedBy)
		if err != nil {
			return nil, err
		}
		handles[*row.SubmittedBy] = handle
	}
	return handles, nil
}

// handleOf reads one account's GitHub handle. An account that names nothing is empty rather than
// an error: a release whose submitter row has gone is a release a reviewer still has to decide.
func (q *Queue) handleOf(ctx context.Context, accountID string) (string, error) {
	handle, err := q.db.Read().GetAccountHandle(ctx, accountID)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return "", nil
	case err != nil:
		return "", fmt.Errorf("read the handle of %s: %w", accountID, err)
	}
	return handle, nil
}

// Pending is how many releases are waiting. For the boot log and the account surface.
func (q *Queue) Pending(ctx context.Context) (int64, error) {
	n, err := q.db.Read().CountPendingReleases(ctx)
	if err != nil {
		return 0, fmt.Errorf("count the review queue: %w", err)
	}
	return n, nil
}

// Decision is what a reviewer did.
type Decision struct {
	ReleaseID string
	PluginID  string
	Version   string

	// Superseded is the release this approval retired, empty when the plugin had none. It is
	// returned so the answer can say what was replaced: an approval that silently retired somebody
	// else's live release would be a listing changing with nothing saying so.
	Superseded string
}

// Approve makes a release the plugin's live one.
//
// Everything happens in one transaction: the previous approved release is superseded, this one is
// approved, and the audit row is written. The partial unique index permits exactly one approved
// release per plugin, so the supersede MUST come first and MUST share the transaction — doing it
// in two would be a constraint violation on a good day and two live releases on a bad one.
func (q *Queue) Approve(ctx context.Context, releaseID, reviewerID, note string) (Decision, error) {
	note = strings.TrimSpace(note)
	if len(note) > maxReasonBytes {
		return Decision{}, fmt.Errorf("%w of %d bytes", errReasonTooLong, maxReasonBytes)
	}

	now := q.clk.Now()
	var out Decision

	err := q.db.Tx(ctx, func(tx *store.Queries) error {
		row, err := q.pendingTx(ctx, tx, releaseID)
		if err != nil {
			return err
		}

		// A release whose artifact this server never hashed cannot be approved. The CHECK would
		// refuse it; this refuses it with a sentence naming the way out.
		if row.VerifiedAt == nil || row.ArtifactSha256 == nil {
			return ErrNotVerified
		}

		out = Decision{ReleaseID: row.ID, PluginID: row.PluginID, Version: row.Version}

		// Retire whatever is live now. Zero rows is the normal case for a plugin's first release.
		prior, err := tx.GetLatestApprovedRelease(ctx, row.PluginID)
		switch {
		case err == nil:
			out.Superseded = prior.ID
			if _, err := tx.SupersedeApprovedRelease(ctx, row.PluginID); err != nil {
				return fmt.Errorf("supersede the live release of %s: %w", row.PluginID, err)
			}
		case !errors.Is(err, store.ErrNoRows):
			return fmt.Errorf("read the live release of %s: %w", row.PluginID, err)
		}

		changed, err := tx.ApproveRelease(ctx, sqlitegen.ApproveReleaseParams{
			ReviewedBy: &reviewerID,
			ReviewedAt: ptr(core.MicrosFromTime(now).Int64()),
			ReviewNote: nullable(note),
			ID:         releaseID,
		})
		if err != nil {
			return fmt.Errorf("approve release %s: %w", releaseID, err)
		}
		if changed == 0 {
			// Somebody decided it between the read above and this write, inside one transaction on
			// the single writer -- so this is close to unreachable and is still checked, because
			// "the update affected nothing" must never be read as "the update happened".
			return ErrNotPending
		}

		return audit.Record(ctx, tx, q.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   reviewerID,
			Action:      actionApprove,
			SubjectKind: subjectRelease,
			SubjectID:   releaseID,
			Detail: map[string]any{
				detailPlugin:  row.PluginID,
				detailVersion: row.Version,
				"sha256":      *row.ArtifactSha256,
				"superseded":  out.Superseded,
				"note":        note,
			},
		})
	})
	if err != nil {
		return Decision{}, err
	}
	return out, nil
}

// Reject refuses a release. The row stays, and so does its claim on the version.
func (q *Queue) Reject(ctx context.Context, releaseID, reviewerID, reason string) (Decision, error) {
	reason = strings.TrimSpace(reason)
	switch {
	case reason == "":
		return Decision{}, ErrNoReason
	case len(reason) > maxReasonBytes:
		return Decision{}, fmt.Errorf("%w of %d bytes", errReasonTooLong, maxReasonBytes)
	}

	now := q.clk.Now()
	var out Decision

	err := q.db.Tx(ctx, func(tx *store.Queries) error {
		row, err := q.pendingTx(ctx, tx, releaseID)
		if err != nil {
			return err
		}
		out = Decision{ReleaseID: row.ID, PluginID: row.PluginID, Version: row.Version}

		changed, err := tx.RejectRelease(ctx, sqlitegen.RejectReleaseParams{
			ReviewedBy: &reviewerID,
			ReviewedAt: ptr(core.MicrosFromTime(now).Int64()),
			ReviewNote: &reason,
			ID:         releaseID,
		})
		if err != nil {
			return fmt.Errorf("reject release %s: %w", releaseID, err)
		}
		if changed == 0 {
			return ErrNotPending
		}

		return audit.Record(ctx, tx, q.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   reviewerID,
			Action:      actionReject,
			SubjectKind: subjectRelease,
			SubjectID:   releaseID,
			Detail: map[string]any{
				detailPlugin:  row.PluginID,
				detailVersion: row.Version,
				"reason":      reason,
			},
		})
	})
	if err != nil {
		return Decision{}, err
	}
	return out, nil
}

// pendingTx reads a release and requires it to be waiting.
func (q *Queue) pendingTx(
	ctx context.Context, tx *store.Queries, releaseID string,
) (sqlitegen.Release, error) {
	row, err := tx.GetReleaseByID(ctx, releaseID)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return row, ErrNoSuchRelease
	case err != nil:
		return row, fmt.Errorf("read release %s: %w", releaseID, err)
	case row.State != string(statePending):
		return row, ErrNotPending
	}
	return row, nil
}

// statePending mirrors the database's CHECK. It is spelled here rather than imported from
// internal/release, because a package that imports another one only to borrow a string constant
// has taken on that package's whole dependency set to avoid typing eight characters.
const statePending = "pending"

var errReasonTooLong = errors.New("the review note exceeds the size cap")

func ptr[T any](v T) *T { return &v }

// nullable renders an optional note, keeping "nothing was written" distinct from "an empty string
// was written". review_note is read by a human during an incident and the two say different things.
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
