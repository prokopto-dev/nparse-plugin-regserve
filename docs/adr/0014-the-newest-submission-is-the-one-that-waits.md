# ADR-0014 — A plugin has one release waiting for review: the newest submission

**Status:** accepted · **Date:** 2026-08-24 · **Deciders:** Courtney Caldwell

## Context and problem statement

Approving a new plugin showed the same plugin id several times in the review queue, each row badged
"first release of this id". Nothing bounded how many `pending` releases a plugin could hold:
`release_plugin_version_key` is `(plugin_id, version)`, so a second submission is simply a second
row, and `release_one_approved_per_plugin` has no counterpart for the waiting state. A plugin whose
CI published 1.0.0, 1.0.1 and 1.0.2 into a backlogged queue produced three entries, and every layer
below the page — the query, the service, the template — faithfully showed what was there.

The visible cost is a reviewer deciding the same thing repeatedly. The cost that matters is that
**approving is not ordered.** The version comparison in `internal/release/version.go` runs when a
release is *submitted*, against whatever was approved then; there is no equivalent on the approve
path. So a 1.0.1 left waiting after 1.0.2 went live could be approved afterwards, and
`SupersedeApprovedRelease` would retire 1.0.2 to do it — the downgrade that check exists to
prevent, reached by a route it does not cover. The same hole needs no human at all: a trusted
owner's auto-published 1.0.2 leaves their 1.0.1 in the queue.

## Considered options

| Option | For | Against |
|---|---|---|
| A — Collapse the queue at read time | No schema change, no migration, no change for publishers | The stale rows stay `pending` and stay approvable through `/review/releases/{id}` and the JSON API, so the downgrade is untouched. It hides the symptom and keeps the defect |
| B — Retire the older submissions when a newer one arrives, plus a partial unique index | The ambiguous state becomes unrepresentable, exactly as it already is for the approved release. The queue is one row per plugin because that is what exists, and `Approve` needs no new check | A publisher's earlier submission is cancelled with no human deciding so. Needs a data migration: the live database already holds the rows the index forbids |
| C — Refuse a publish while one is waiting | The ambiguity never exists, and the author is told at the door | Turns our queue depth into somebody else's CI failure, and the author can do nothing about it |
| D — Compare versions on the approve path | Fixes the downgrade without touching the queue | Leaves the duplicate rows that were reported, and puts a second copy of the version rules on a second path — what `decide` exists as one function to avoid |

## Decision outcome

**Chosen: B.** A new submission supersedes that plugin's waiting releases, in the same transaction
as its own insert, and `release_one_pending_per_plugin` makes any other state impossible.

**Newest means most recently submitted** — `submitted_at`, then the release id, a ULID, so a tie
breaks in submission order rather than arbitrarily. It is what the author last asked for and it is
always decidable: `compareVersions` may answer "I do not know" for pre-release and local suffixes,
so a version-ordered rule would need this one underneath it anyway.

**The supersede is unconditional, including on the auto-publish path.** A release that goes live
without a human retires a waiting one for the same reason a reviewed one does, and making it
conditional would leave the index a gate over only half of what can violate it.

**`review_note` is not rewritten.** It carries the quarantine reasons, which are the only
explanation the author of a refused release ever gets, and `RecordReleaseVerification` in
`db/queries/review.sql` records what it cost the last time a statement here overwrote them. The
retirement is recorded as a new `audit_log` row against each release instead — append-only, and
what the release page already reads.

**Superseding is a state change and never a delete.** ADR-0010 keeps every release row, and a
`BEFORE DELETE` trigger aborts anything that tries.

### Consequences

- Good, because the reported bug and a live downgrade path close together, and the second was not
  visible from the first.
- Good, because the queue depth logged at boot and shown on the account surface becomes a number a
  reviewer can work down, rather than one inflated by submissions that can never be approved.
- Good, because `Approve` needs no version comparison: the ordering problem is removed rather than
  guarded against on one more path.
- **Bad, because an author's earlier submission is cancelled by their own later one, with no human
  deciding it.** Publishing 1.0.2 by mistake while 1.0.1 is under review retires 1.0.1, and the
  recovery is to publish again under a new version — a version is used once per plugin, ever, so
  1.0.1 does not come back.
- **Bad, because a *verified* waiting release can be retired for an unverified newer one.** If the
  newer artifact could not be fetched, the queue's one entry is the one badged "never checked" and
  the reviewer must re-verify or reject. Visible rather than silent, and still worse than before.
- **Bad, because "newest" is submission order and not version order**, so a deliberate rollback
  submission wins over a higher version that was waiting. The reviewer sees which version they are
  approving, and the quarantine rules still compare it against what is live.
- **Bad, because the index could not be added on its own.** A data migration had to retire the
  duplicates already live, choosing a survivor for rows nobody reviewed.

### Reversal cost

Moderate. Dropping the index and the supersede restores the previous behaviour for new submissions
in one migration and a small change to the publish transaction. What does not come back is the rows
the data migration retired: they are `superseded` permanently, and the queue they were in is gone.
Reversing also reopens the downgrade path, so it would need option D underneath it rather than
nothing.
