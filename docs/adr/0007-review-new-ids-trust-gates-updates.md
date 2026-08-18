# ADR-0007 — Review every new id; trust levels gate updates

**Status:** accepted · **Date:** 2026-08-18 · **Deciders:** Courtney Caldwell

## Context and problem statement

The static registry's safety property came from the merge: a maintainer read the source before any
listing changed, and because the sha256 pinned the reviewed bytes, changing what users received
*required* another review. Handing authors a publish token deletes that property unless something
replaces it. But requiring a human for every patch release also deletes the reason for building this.

## Considered options

| Option | For | Against |
|---|---|---|
| A — Review everything, forever | Preserves today's property exactly | The token saves only the fork-and-paste step. An author still waits on a maintainer for a typo fix, so pipelines are not actually automated |
| B — Trust the token: any valid owner publish goes live | Fully automated, which is the stated goal | Drops the reviewed-bytes guarantee entirely. A compromised CI secret ships arbitrary code to every installed copy, immediately and silently |
| C — Review new ids; auto-publish version bumps from owners above a trust threshold, with quarantine rules that force review regardless | Curation stays where it matters — the first time code appears — and routine updates flow. The dangerous transitions still stop | Two mechanisms to reason about, and the trust tier is a judgement a human has to keep making |

## Decision outcome

**Chosen: C.**

A **new plugin id always requires human approval.** Nothing bypasses this — not trust, not
automation, not an owner who has published fifty times before. The first appearance of an id is
where curation is cheapest and where impersonation is caught.

After that, a version bump by an owner at or above the trust threshold publishes automatically, but
only after `internal/artifact` has fetched and re-hashed the bytes clean
([ADR-0008](0008-server-rehashes-every-artifact.md)).

**Quarantine rules send a release to review regardless of trust**, when the change looks like the
thing we are afraid of:

- the artifact host differs from previous releases of this plugin
- the artifact size differs from the previous release by more than a set proportion
- the version is not greater than the current `latest`
- the artifact could not be fetched, or the fetched bytes did not match the submitted hash

Trust is a per-account tier a maintainer raises or revokes, recorded in `account_trust` with an
`audit_log` row for every change. It starts low for every new account and is never raised
automatically — a counter of successful publishes would be a counter an attacker can run up.

### Consequences

- Good, because the routine case — an author fixing a bug and tagging a release — is fully
  automated, which is the reason the service exists.
- Good, because the expensive human attention lands on new code and on suspicious transitions
  instead of being spread evenly across every patch bump.
- Good, because every quarantine trigger is a named, testable condition rather than a reviewer's
  intuition, so the same submission gets the same answer twice.
- **Bad, because a trusted owner can ship unreviewed code to their existing users.** That is the
  bargain: we have traded per-release review for a smaller blast radius and a paper trail, and a
  compromised CI secret on a trusted account is a real incident with no automated stop.
- **Bad, because the quarantine heuristics will have false positives**, and an author whose
  legitimate release is held will experience that as the service being broken.
- **Bad, because trust is a human judgement that nobody is scheduled to make.** Without a habit of
  reviewing the tier, everyone stays at the floor and the automation never engages, or everyone gets
  raised once and it stops meaning anything.

### Reversal cost

An afternoon in either direction: the state machine already has a review state, so tightening is
setting the threshold to unreachable and loosening is setting it to zero.
