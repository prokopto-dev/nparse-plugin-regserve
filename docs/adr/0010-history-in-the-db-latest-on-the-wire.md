# ADR-0010 — Keep every release in the database; ship only `latest`

**Status:** accepted · **Date:** 2026-08-18 · **Deciders:** Courtney Caldwell

## Context and problem statement

The wire format carries one release per plugin. There is no history and no downgrade path: the
client's own documentation says the previous copy in `plugins/trash/` is the only way back. The
question is whether the *server* should mirror that and keep only the current row.

What the server discards, it cannot audit. Every publish is a decision — approved by whom, verified
against which bytes — and that record is the evidence for the trust model.

## Considered options

| Option | For | Against |
|---|---|---|
| A — Store only the current release per plugin, mirroring the wire | Smallest schema, and the table matches the document it produces | The approval history is gone. "Which version did we approve, and who approved it" becomes unanswerable, and that question is exactly what a compromise investigation asks |
| B — Append a row per release; the current one is derived | Full audit trail, rollback is a state change rather than a re-submission, and quarantine rules can compare against previous releases | The table grows forever, and "which one is live" becomes a query rather than a fact |

## Decision outcome

**Chosen: B.** Every submitted release is a row in `release`, with its own `state`
(`pending`/`approved`/`rejected`/`superseded`), the hash **the server computed**, who submitted it,
who reviewed it, and when it was verified. Rows are never deleted and never rewritten; a superseded
release moves state and stays.

This is not storage for its own sake — three mechanisms depend on it:

- **Quarantine rules compare against previous releases** ([ADR-0007](0007-review-new-ids-trust-gates-updates.md)):
  artifact host change and size delta are both differences from a prior row. With only the current
  release stored, half the heuristics have nothing to compare to.
- **Rollback becomes a state change.** Delisting a bad release and re-pointing `latest` at the
  previous approved row does not require the author to re-submit anything, which matters because the
  moment you need a rollback is the moment the author is asleep.
- **Version monotonicity is checkable** against everything ever published, not just the current one,
  so a version number cannot be quietly reused after a delisting.

`latest` on the wire is derived: the highest approved, non-superseded release. It is a query, and
`internal/registry` is the only place that runs it.

### Consequences

- Good, because "who approved these exact bytes, and when" is answerable years later, which is the
  evidence the trust model is built on.
- Good, because rollback and delisting are state transitions rather than data loss.
- Good, because the quarantine heuristics have prior releases to compare against, which is what makes
  them more than a size check.
- **Bad, because the live release is derived rather than stored**, so a bug in that derivation is a
  bug in what every user downloads. It needs its own test, not just coverage of the surrounding code.
- **Bad, because the table grows without bound.** At the expected rate this is megabytes a decade,
  but nothing prunes it and nobody is watching the number.
- **Bad, because keeping rejected submissions means keeping URLs somebody wanted us to fetch**, which
  is a small pile of attacker-supplied strings living in the database indefinitely.

### Reversal cost

An afternoon to collapse to the current row, and the history is gone the moment you do — so the
reversal is only cheap in the direction nobody wants to go.
