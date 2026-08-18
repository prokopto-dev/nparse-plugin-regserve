# ADR-0003 — Identity is a `(provider, subject)` pair

**Status:** accepted, amended in part by [ADR-0011](0011-github-is-the-only-identity-provider.md)
· **Date:** 2026-08-18 · **Deciders:** Courtney Caldwell

> The `(provider, subject)` model below stands unchanged. What ADR-0011 withdraws is the plan to
> implement three providers against it: only `github` ships. Read the rest as the record of what
> was thought at the time.

## Context and problem statement

Publishers need accounts. The population is P99 plugin authors, who universally have Discord, mostly
have GitHub, and variably have anything else. Ownership of a plugin id is permanent and consequential
— it is the right to ship code to everyone who installed that plugin — so the account it attaches to
has to survive a username change and be revocable in a way that sticks.

Picking one provider excludes people; storing a bare Discord id makes the account and the provider
the same object, which cannot be undone later.

## Considered options

| Option | For | Against |
|---|---|---|
| A — GitHub only | Ownership already means a GitHub handle in `owners.json`, so nothing is lost. One integration | Excludes the Discord-only author from even browsing or watching a plugin, and ties every future feature to one company's account system |
| B — Store a bare Discord id as the account key | Simplest possible; everyone in the community has one | The account *is* the Discord id, so adding a second provider later is a data migration on the primary key. A deleted Discord account orphans a plugin permanently |
| C — `(provider, subject)` rows pointing at an account, with `discord`, `google` and `github` implementations | Each population gets a path in, an account can hold several identities, and adding a provider is a row rather than a schema change | Three verification paths to build and keep from diverging, and the account/identity split is a join on every login |

## Decision outcome

**Chosen: C**, matching [tod-serve ADR-0003](https://github.com/prokopto-dev/tod-serve/blob/main/docs/adr/0003-pluggable-identity-providers.md).
An `account` is the thing that owns plugins and holds tokens; an `identity(provider, subject)` is a
way to prove you are that account. One account may link several.

`subject` is the provider's immutable id — a Discord snowflake, a Google `sub`, a GitHub numeric
node id — **never the display name or handle**, which all three let users change. The static
registry's `owners.json` keyed on GitHub *handles*, compared case-insensitively; migrating those
claims means resolving each handle to its numeric id once, at import, and recording both.

Whether a provider may publish is `identity_provider.can_publish`, a `CHECK` against `kind` rather
than an operator toggle, because [ADR-0004](0004-github-required-to-publish.md) hangs off it.
Identity linking is deliberate and authenticated on both sides; automatic linking by matching email
addresses is not implemented, because an unverified email is an account takeover.

### Consequences

- Good, because a Discord-only author can hold an account, watch plugins and be added as a
  co-maintainer, then link GitHub when they first need to publish.
- Good, because a handle change breaks nothing — the subject is the identity, and the display name is
  cached decoration we refresh on login.
- Good, because losing access to one provider does not lose the account when another is linked.
- **Bad, because an account with one linked identity is as fragile as that provider.** A deleted
  GitHub account still orphans its plugins, and the recovery path is a human proving ownership out
  of band.
- **Bad, because three OAuth integrations is three sets of client secrets, callback URLs and quirks**
  to keep working, and a provider changing its consent screen is our outage.
- **Bad, because the account/identity split costs a join on every authenticated request** and makes
  "who is this" a two-table answer in every debugging session.

### Reversal cost

A day to collapse to one provider, plus a migration dropping the other identity rows and a support
process for anyone who only had those. Adding a *fourth* provider is an afternoon, which is the point.
