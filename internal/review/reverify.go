package review

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/audit"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// Re-verification exists because of a hole the publish path would otherwise leave, and the hole is
// worth stating plainly:
//
// A release whose artifact could not be fetched is recorded `pending` with no hash — correctly, so
// that "we could not check" is visible rather than lost. But a version is used ONCE PER PLUGIN,
// EVER, over a table nothing deletes from. So a GitHub outage lasting thirty seconds would
// permanently consume `1.0.0`, and the author's only remedy would be to publish `1.0.1` — a
// version number burned by somebody else's bad afternoon, with the release notes and the tag now
// disagreeing with the registry.
//
// Re-verification is the repair: the SAME row, the SAME version, fetched again by the server, with
// the hash the server computes written into the blank it left. It cannot do anything else.

// Verification is the outcome of a re-verification attempt.
type Verification struct {
	ReleaseID string
	PluginID  string
	Version   string

	// Verified says whether this attempt succeeded. FALSE IS NOT AN ERROR — the artifact still
	// could not be fetched, the release is still pending, and the reason is recorded. It is
	// reported honestly for the same reason the original publish reports it: "we could not check"
	// and "we checked and it was fine" must never produce the same answer.
	Verified bool

	// SHA256 is what the server computed, empty when it still could not.
	SHA256 string
	Bytes  *int64

	// Note is what was recorded on the row, and always says something. On failure it is
	// artifact.Reason's sentence, which always begins "not verified: ".
	Note string
}

// Reverify fetches a release's artifact again and records the hash if it succeeds.
//
// IT CAN ONLY FILL IN A BLANK. A release that already carries a hash is refused, and the SQL says
// so too — `RecordReleaseVerification` has `verified_at IS NULL` in its WHERE. That is not
// belt-and-braces: a stored hash is what every installed client verifies an artifact against, so a
// path that could RECOMPUTE one is a path that could swap the bytes behind a listing without
// anybody reviewing the swap. That is the single property this service exists to keep, and the
// repair for a transient outage must not be the thing that breaks it.
//
// The submitted hash is NOT re-checked here, because it no longer exists: ADR-0008 compares it and
// discards it, and this server keeps no copy. So a re-verification records what the bytes hash to
// NOW, with no cross-check against what the author originally claimed — and the release stays
// `pending`, so a human still decides. The audit row records every attempt, which is what makes an
// artifact that changed between attempts visible rather than inferred.
func (q *Queue) Reverify(ctx context.Context, releaseID, reviewerID string) (Verification, error) {
	row, err := q.db.Read().GetReleaseByID(ctx, releaseID)
	switch {
	case errors.Is(err, store.ErrNoRows):
		return Verification{}, ErrNoSuchRelease
	case err != nil:
		return Verification{}, fmt.Errorf("read release %s: %w", releaseID, err)
	case row.State != statePending:
		return Verification{}, ErrNotPending
	case row.VerifiedAt != nil:
		return Verification{}, ErrAlreadyVerified
	}

	out := Verification{ReleaseID: row.ID, PluginID: row.PluginID, Version: row.Version}

	// Outside the transaction, like the original publish and for the same reason: this takes up to
	// forty-five seconds and SQLite has exactly one writer.
	res, fetchErr := q.fetcher.Fetch(ctx, row.ArtifactUrl)
	if fetchErr != nil {
		slog.WarnContext(ctx, "artifact still not verified",
			"release_id", releaseID, "plugin_id", row.PluginID, "error", fetchErr)
		out.Note = artifact.Reason(fetchErr)
	} else {
		out.Verified = true
		out.SHA256 = res.Digest.Hex()
		out.Bytes = &res.Bytes
		out.Note = reverifiedNote
	}

	if err := q.db.Tx(ctx, func(tx *store.Queries) error {
		if out.Verified {
			if err := recordVerification(ctx, tx, releaseID, res, out.Note); err != nil {
				return err
			}
		}
		// The audit row is written on BOTH paths. A failed re-verification is a fact about the
		// artifact — three failures in a row is a different story from one — and a queue that only
		// recorded successes would hide exactly the pattern worth noticing.
		return audit.Record(ctx, tx, q.clk, audit.Entry{
			Actor:       audit.ActorAccount,
			AccountID:   reviewerID,
			Action:      actionReverify,
			SubjectKind: subjectRelease,
			SubjectID:   releaseID,
			Detail: map[string]any{
				detailPlugin:  row.PluginID,
				detailVersion: row.Version,
				"verified":    out.Verified,
				"note":        out.Note,
				"sha256":      out.SHA256,
			},
		})
	}); err != nil {
		return Verification{}, err
	}
	return out, nil
}

// reverifiedNote replaces the "not verified" sentence once the bytes have been read.
//
// It says the artifact was fetched LATER than the submission rather than just clearing the note: a
// reviewer looking at this row needs to know the hash and the submission are from different
// moments, because the submitted hash was compared against neither.
const reverifiedNote = "the artifact was fetched and hashed on a later attempt; the hash the " +
	"submitter claimed was compared only against the first, failed, attempt"

// recordVerification writes the computed hash into the blank the failed fetch left.
//
// THIS IS THE SECOND DOOR INTO release.artifact_sha256, and it goes through artifact.StoredHash
// like the first one. Gate HASH001 fails any assignment to that field whose right-hand side is not
// that call — which is how a path added months after the rule was written is still held to it.
func recordVerification(
	ctx context.Context, tx *store.Queries, releaseID string, res artifact.Result, note string,
) error {
	params := sqlitegen.RecordReleaseVerificationParams{
		ArtifactBytes: &res.Bytes,
		VerifiedAt:    ptr(core.MicrosFromTime(res.FetchedAt).Int64()),
		ReviewNote:    &note,
		ID:            releaseID,
	}

	// The assignment IS the call, in one expression, so HASH001 can see where the value came from.
	var err error
	params.ArtifactSha256, err = artifact.StoredHash(res.Digest)
	if err != nil {
		return fmt.Errorf("store the hash for release %s: %w", releaseID, err)
	}

	changed, err := tx.RecordReleaseVerification(ctx, params)
	if err != nil {
		return fmt.Errorf("record the verification of %s: %w", releaseID, err)
	}
	if changed == 0 {
		// The row gained a hash between the read and this write. Refusing is the only safe reading:
		// the alternative is overwriting a hash somebody else just recorded.
		return ErrAlreadyVerified
	}
	return nil
}
