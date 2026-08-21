package review

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
)

// One release, with everything a reviewer needs in order to decide.
//
// The queue answers "what is waiting". This answers the harder question — WHY is this waiting —
// and the answer is not in the release row. The row carries a rendered sentence in `review_note`;
// the structured reasons, and the hash the submitter claimed when it disagreed with the one this
// server computed, are in the audit row the publish wrote. So this reads both, and the page shows
// a reviewer the same facts the publish path acted on rather than a summary of them.
//
// A reviewer deciding from an incomplete picture is the failure this exists to prevent: approving
// a release whose only visible problem was "awaiting human review" when the audit row said the
// artifact had moved host and the hash did not match.

// Detail is one release as the review pages show it.
type Detail struct {
	// Waiting is the same shape the queue list uses, so the two surfaces cannot disagree about
	// what a release is called or whether it was verified.
	Waiting

	// State is where the release is now: pending, approved, rejected or superseded. The queue only
	// ever lists pending ones; this page can be reached for any of them, because a reviewer is
	// sent back to it after acting.
	State string

	// Source says whether this server fetched these bytes ('publish') or inherited the hash from
	// the static registry ('import'). ADR-0008: those are different statements about provenance
	// and must not read the same.
	Source string

	SDKSpecifier      string
	MinimumAppVersion string

	// Notes are the author's plain-text patch notes, shown so a reviewer reads what will be
	// published to every client (ADR-0013). It is author-supplied text; the templates escape it,
	// and nothing here treats it as markup.
	Notes string

	// LiveVersion is what this release would replace, empty when the plugin has nothing approved.
	// Empty is the interesting case: it means this is the first appearance of the id.
	LiveVersion string

	// SubmittedSHA256 is the hash the SUBMITTER claimed, and it is present ONLY when it disagreed
	// with the one this server computed. ADR-0008 discards the submitted value after comparing it,
	// so the audit row is the only place it survives — recorded precisely because a mismatch is
	// unreadable without both halves.
	SubmittedSHA256 string

	// Quarantine is every rule that fired at publish time, as recorded then. It is read from the
	// audit row rather than recomputed, because recomputing would answer "what would fire now",
	// and a reviewer needs to know what the server actually decided on.
	Quarantine []string

	ReviewedBy string
	ReviewedAt time.Time

	// Events is the audit trail, oldest first. Append-only: a correction is a new row, so a
	// reviewer reading this sees the history rather than its latest state.
	Events []Event
}

// Event is one audit row, rendered for a page.
type Event struct {
	At time.Time

	// Action is the `<resource>.<action>` key, e.g. `plugin.publish`.
	Action string

	// Actor is the account's display name, empty for a system action. System says which, because
	// "nobody" and "we could not resolve the name" must not look alike.
	Actor  string
	System bool

	// Detail is the audit row's detail object, verbatim. It is a STRING and not a decoded map
	// because a domain type carrying `any` is a domain type nobody can reason about — and because
	// what belongs on the page is the record as written, not this package's interpretation of it.
	//
	// Showing it is safe by invariant, not by inspection: `audit_log.detail` never carries a
	// secret, which is the rule that makes the table redaction-proof in the first place.
	Detail string
}

// auditDetail is the subset of an audit row's detail this package reads.
//
// THE KEYS ARE SPELLED HERE AND WRITTEN IN internal/release, which is two places. That is the same
// trade the action constants in queue.go make — importing a package to borrow four string literals
// takes on its whole dependency set — and it is only safe because a test publishes a quarantined
// release through the real publish path and reads it back through Detail. If the writer renames a
// key, that test fails; without it, this page would quietly show a release with no reasons.
type auditDetail struct {
	Release    string   `json:"release"`
	Quarantine []string `json:"quarantine"`
	Submitted  string   `json:"submitted_sha256"`
}

// Detail returns one release with its quarantine reasons and its audit trail.
func (q *Queue) Detail(ctx context.Context, releaseID string) (Detail, error) {
	row, err := q.db.Read().GetReleaseForReview(ctx, releaseID)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return Detail{}, ErrNoSuchRelease
	case err != nil:
		return Detail{}, fmt.Errorf("read release %s for review: %w", releaseID, err)
	}

	out := Detail{
		Waiting: Waiting{
			ReleaseID:   row.ID,
			PluginID:    row.PluginID,
			PluginName:  row.PluginName,
			Version:     row.Version,
			ArtifactURL: row.ArtifactUrl,
			Bytes:       row.ArtifactBytes,
			Verified:    row.VerifiedAt != nil,
			// The plugin has nothing else approved, so this release is the first appearance of
			// the id — the case ADR-0007 says always gets a human.
			FirstRelease: row.LiveVersion == "",
			SubmittedAt:  core.Micros(row.SubmittedAt).Time(),
		},
		State:             row.State,
		Source:            row.Source,
		SDKSpecifier:      row.SdkSpecifier,
		MinimumAppVersion: deref(row.MinimumAppVersion),
		Notes:             deref(row.Notes),
		LiveVersion:       row.LiveVersion,
		ReviewedBy:        deref(row.ReviewedBy),
	}
	out.SHA256 = deref(row.ArtifactSha256)
	out.SubmittedBy = deref(row.SubmittedBy)
	out.Note = deref(row.ReviewNote)
	if row.ReviewedAt != nil {
		out.ReviewedAt = core.Micros(*row.ReviewedAt).Time()
	}

	if err := q.appendReleaseEvents(ctx, &out); err != nil {
		return Detail{}, err
	}
	if err := q.appendPluginEvents(ctx, &out); err != nil {
		return Detail{}, err
	}

	// Oldest first, by the recorded time and then the id. Audit ids are ULIDs, which sort by the
	// millisecond they were minted in, so the tiebreaker is chronological rather than arbitrary.
	sort.SliceStable(out.Events, func(i, j int) bool {
		return out.Events[i].At.Before(out.Events[j].At)
	})
	return out, nil
}

// appendReleaseEvents adds the rows whose subject is the release itself.
func (q *Queue) appendReleaseEvents(ctx context.Context, out *Detail) error {
	rows, err := q.db.Read().ListAuditForRelease(ctx, ptr(out.ReleaseID))
	if err != nil {
		return fmt.Errorf("read the audit trail of release %s: %w", out.ReleaseID, err)
	}
	for _, row := range rows {
		out.Events = append(out.Events, Event{
			At:     core.Micros(row.RecordedAt).Time(),
			Action: row.Action,
			Actor:  row.ActorName,
			System: row.ActorKind == string(actorSystem),
			Detail: deref(row.Detail),
		})
	}
	return nil
}

// appendPluginEvents adds the plugin-subject rows that name this release, and reads the publish
// row's structured reasons off the way past.
//
// The rows that do NOT name this release are dropped rather than shown: a plugin's ownership
// changes and its other publishes are not this release's history, and a page that mixed them would
// be answering a different question from the one a reviewer asked.
func (q *Queue) appendPluginEvents(ctx context.Context, out *Detail) error {
	rows, err := q.db.Read().ListAuditForPlugin(ctx, ptr(out.PluginID))
	if err != nil {
		return fmt.Errorf("read the audit trail of plugin %s: %w", out.PluginID, err)
	}

	for _, row := range rows {
		raw := deref(row.Detail)
		if raw == "" {
			continue
		}

		var d auditDetail
		if err := json.Unmarshal([]byte(raw), &d); err != nil {
			// A detail object this package cannot read is not an error: the column is free-form
			// JSON and older rows may carry a shape nobody writes any more. It is skipped rather
			// than failing the page, because a reviewer who cannot open a release at all is worse
			// off than one reading a trail with a gap in it.
			continue
		}
		if d.Release != out.ReleaseID {
			continue
		}

		if len(d.Quarantine) > 0 {
			out.Quarantine = d.Quarantine
		}
		out.SubmittedSHA256 = d.Submitted

		out.Events = append(out.Events, Event{
			At:     core.Micros(row.RecordedAt).Time(),
			Action: row.Action,
			Actor:  row.ActorName,
			System: row.ActorKind == string(actorSystem),
			Detail: raw,
		})
	}
	return nil
}

// actorSystem mirrors audit.ActorSystem. Spelled here rather than imported for the reason the
// state constants are: this package would take on internal/audit's whole dependency set to borrow
// six characters, and the value is asserted by a test that writes a real row.
const actorSystem = "system"

// deref reads an optional column, treating NULL and empty alike.
func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
