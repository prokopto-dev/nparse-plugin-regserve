# The trust model

This service replaces a curated, PR-gated static index. That index had real safety properties, and
they came from mechanisms — a human merge, a pinned hash — rather than from good intentions. Every
one of them had to be replaced by something, or deliberately given up in writing.

This page is the ledger of that trade.

## What the static registry guaranteed

The registry repository is `prokopto-dev/nparseplus-plugins`: one `index.json`, published from
GitHub Pages, changed only by pull request, checked by `.github/workflows/validate-index.yml`, and
merged by a maintainer.

Its README states the property plainly:

> An author cannot swap the artifact behind an already-listed URL without a new PR and a new review.

That works because the index carries a sha256, and the nParse+ installer refuses to extract an
archive whose bytes do not match it — *before* extraction, so unreviewed code never runs. Changing
what users receive therefore requires changing the index, which requires another human look.

Five properties follow from that arrangement:

1. **Every listed byte sequence was reviewed by a human.**
2. **Plugin ids are first-come, permanent, and never recycled** — enforced by `owners.json`, where a
   delisted id keeps its claim.
3. **Only an owner can change a listing** — the CI job checks the PR author against `owners.json` at
   the base revision, so a handover and an update can land together without opening a hole.
4. **The published hash was verified against the real artifact** — CI re-downloads and re-hashes,
   best effort, and a mismatch fails the check.
5. **The artifact is never executed during validation.** CI deliberately does not run
   `nparseplus-plugin validate`, because that imports the plugin and calls `activate()`.

## What replaces each one

| Property | Replacement | Where |
|---|---|---|
| Human review of every listing | Human review of every **new id**; version bumps by trusted owners auto-publish after mechanical checks | [ADR-0007](../adr/0007-review-new-ids-trust-gates-updates.md) |
| Ids permanent, never recycled | `id_claim` rows are never deleted; delisting clears the listing and keeps the claim | [canonical §3](../design/00-canonical-conventions.md#3-identifiers) |
| Only an owner may change a listing | Ownership checked per request, against `plugin_owner`, at the moment of publish | [ADR-0005](../adr/0005-pats-scoped-to-plugins.md) |
| Hash verified against the real artifact | The server fetches and hashes it itself, and **never stores a submitted hash** | [ADR-0008](../adr/0008-server-rehashes-every-artifact.md) |
| Artifact never executed | Bytes are hashed streaming and discarded — never extracted, never written to a persistent path, never imported | [ADR-0008](../adr/0008-server-rehashes-every-artifact.md) |

## What we gave up, in writing

**Per-release human review of already-approved plugins.** A trusted owner's version bump reaches
users without anyone reading the diff. In exchange we get: a smaller credential blast radius
(a publish token cannot mint another token, and can be pinned to one plugin), a server-computed hash
rather than an author-supplied one, an append-only record of who published what and when, and
quarantine rules that stop the transitions most likely to be an attack.

This is a real reduction in review coverage. It is the price of the automation the service exists to
provide, and it is stated here so that nobody has to rediscover it during an incident.

**What has not changed:** the hash is still the security boundary. The URL is transport. A
compromised CDN, a re-uploaded release asset or a hijacked domain all produce bytes that fail the
recorded hash, and the client refuses them before extraction — exactly as before.

## Where a tier is set, and what happens when nobody sets one

Trust is a per-account tier: `blocked`, `new` or `trusted`. **An account with no row at all is
`new`**, which is the floor and the default, and it is never raised automatically — a counter of
successful publishes is a counter an attacker can run up
([ADR-0007](../adr/0007-review-new-ids-trust-gates-updates.md)).

A reviewer sets it from **the release's page in the review queue**, or with
`PUT /api/v1/accounts/{id}/trust`. Both are capability-floor: no personal access token can set a
tier however it is scoped, because a token that could raise its own account would be a token that
could publish without review. Both are reviewer-only as well, because a tier that a publisher could
set for themselves is not a judgement about them.

ADR-0007 wrote down the failure mode of that arrangement — *"without a habit of reviewing the tier,
everyone stays at the floor and the automation never engages"* — and it is exactly what happened on
the live deployment. Every account was at the floor, so every release queued, including clean
version bumps of plugins that had already been approved. Nothing was wrong; nothing said so either.
The tier appeared on no page, no publish response named it, and the only way to raise anybody was to
copy a session cookie into `curl`.

So the tier is now shown wherever the decision is made or felt: on your own account page, beside
every submitter in the review queue, and on the release page next to the form that sets it. A
release that waits **only** because of the tier says so in the sentence its author is given:

> awaiting human review: this registry has not marked the submitting account trusted, so every
> release it publishes goes to a person — including a version bump of a plugin whose earlier
> release was approved

That is a fact about the account and not about the release, which is why it is not a quarantine
reason: those are facts about a *change*, and the tier is a judgement about a *person*.

## The failure mode we design against

A **confident mistake**, not a miss.

An artifact that could not be fetched is not published; it goes to review with the reason recorded.
"We could not check" and "we checked and it was fine" must never produce the same outcome, and the
rule most likely to be quietly optimised away by someone reading a timeout as a transient annoyance
is exactly that one.

The same instinct applies to listings: if a filter drops a plugin from the index, the count is
recorded somewhere visible. A listing that vanishes without explanation is indistinguishable from a
bug, and a user cannot tell the difference.
