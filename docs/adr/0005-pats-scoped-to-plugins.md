# ADR-0005 — PATs belong to accounts and are scoped to plugins

**Status:** accepted · **Date:** 2026-08-18 · **Deciders:** Courtney Caldwell

## Context and problem statement

The point of this service is that a release workflow can publish without a human. That means a
long-lived credential sitting in a GitHub Actions secret, in a repository whose write access is not
necessarily limited to the plugin's owner. The blast radius of that token leaking has to be smaller
than "everything the owner can do".

## Considered options

| Option | For | Against |
|---|---|---|
| A — One token per account, full account authority | One secret to manage; simplest mental model | A token stolen from one plugin's CI can publish to every plugin that owner holds, and can mint more tokens. The credential in the least-trusted place has the most authority |
| B — Tokens belong to the account, carry coarse scopes, and are optionally pinned to one plugin id | The CI secret can do exactly one thing to exactly one plugin. A leak is contained to the repository it leaked from | Two dimensions to reason about (scope and plugin pin), and an owner with five plugins manages five secrets |
| C — Tokens belong to a service account per plugin | The credential outlives the person, which matters for a bot | Invents a "service account" concept for a population of solo hobbyist authors who will never want one, and an abandoned service account is an orphaned plugin |

## Decision outcome

**Chosen: B.** The token is a *deployment credential for one plugin's pipeline*, so that is what it
should be able to do.

Format and storage inherit from
[tod-serve ADR-0005](https://github.com/prokopto-dev/tod-serve/blob/main/docs/adr/0005-pats-bound-to-memberships.md)
unchanged: `nprs_pat_<8-char public prefix>_<43 chars base64url of 32 random bytes>`, stored as
`HMAC-SHA256(server_pepper, secret)` — a keyed hash rather than bcrypt, because verification sits on
the hot path of every publish. The prefix is loggable and is how a leaked token is found in a log;
the secret is never logged, never returned after minting, and never stored.

Scopes are `family:verb` and coarse: `plugin:publish`, `plugin:read`, `plugin:manage`. A token may
additionally name a single plugin id, and the effective authority is the intersection of the scope,
the pin, and the account's ownership *at request time* — ownership is checked per request rather
than cascade-revoked, so removing an owner takes effect on their next call rather than after a sweep.

**The capability floor carries no scope at all.** Minting tokens, changing owners, and setting trust
levels are session-only; there is no `admin:*` and no token that can escalate itself. A leaked
publish token cannot mint a second token, which is the property that makes the containment real.

### Consequences

- Good, because the credential in CI — the least defensible place a secret lives — can do one thing
  to one plugin and cannot escalate.
- Good, because revocation is immediate and per-token, so a suspected leak costs one rotation rather
  than an account reset.
- Good, because the 8-character prefix makes a token in a log searchable without the log ever having
  held the secret.
- **Bad, because an owner with several plugins manages several secrets**, and the friction of that
  will tempt people to mint one broad token and reuse it. The UI has to make the narrow choice the
  easy one, and it will not always win.
- **Bad, because checking ownership on every request is a join on every request**, where cascade
  revocation would have paid that cost once.
- **Bad, because a token dies when its owner loses ownership**, which is correct and will still
  surprise someone mid-handover. Transfers need to be documented as a two-step: add the new owner,
  let them mint their own token, then remove the old one.

### Reversal cost

A day to widen tokens to full account authority, which is a schema relaxation and a nullable column.
Narrowing them again afterwards is the expensive direction, which is why they start narrow.
