# ADR-0011 — GitHub is the only identity provider

**Status:** accepted · **Date:** 2026-08-18 · **Deciders:** Courtney Caldwell
· amends [ADR-0003](0003-identity-is-provider-subject.md) and [ADR-0004](0004-github-required-to-publish.md)

## Context and problem statement

[ADR-0003](0003-identity-is-provider-subject.md) planned three provider implementations — Discord,
Google and GitHub — against a `(provider, subject)` identity model.
[ADR-0004](0004-github-required-to-publish.md) then made GitHub the only provider that may publish,
as a `CHECK` on `identity_provider.can_publish` against `kind`.

That leaves a Discord or Google account able to do exactly one thing: log in. `GET /index.json` is
unauthenticated, so browsing needs no account at all, and the two features ADR-0003 offered such an
account — watching a plugin, being added as a co-maintainer — are on no phase of the ROADMAP.
The question is whether to build and operate two OAuth integrations that grant a signed-in user
nothing an anonymous visitor does not already have.

## Considered options

| Option | For | Against |
|---|---|---|
| A — Ship all three as planned | Keeps ADR-0003 as written, and the login page is welcoming to a community that lives on Discord | Two integrations whose accounts can do nothing, three sets of client secrets and callback URLs, and ADR-0004's own admission that "offering three login buttons and then refusing two of them at the moment of publish is a confusing product" |
| B — Ship GitHub only, against the same `(provider, subject)` schema | One integration, one consent screen, one set of secrets. Every account that exists can publish, so there is no dead-end login. The schema still holds any number of providers | No account recovery through a second linked identity, and a Discord-only author cannot register at all — though registering bought them nothing |
| C — Ship GitHub only *and* collapse the schema to a bare GitHub id | Removes the account/identity join from every authenticated request | This is ADR-0003 option B, rejected then and rejected now: the account becomes the GitHub id, and adding a second provider later is a migration on a primary key |

## Decision outcome

**Chosen: B.** `github` is the only row in `identity_provider`, and `internal/identity/github` is
the only implementation. Discord and Google are dropped: no client registration, no callback route,
no environment slots in `deploy/env.example` or `deploy/compose.yaml`.

**What is kept, and it is the whole point:** the `(provider, subject)` data model of ADR-0003 is
unchanged. An `account` is still the thing that owns plugins and holds tokens; an
`identity(provider, subject)` is still a way to prove you are that account, and an account may still
link several. `subject` remains the provider's immutable numeric id — a GitHub node id, **never
the handle**, which users change. This ships *one provider against that schema*; it does not
collapse the schema. ADR-0003's reversal cost stands: adding a provider later is an afternoon,
because it is a row and a package, not a migration.

ADR-0004's mechanism is unchanged and is now trivially satisfied: `can_publish` stays a `CHECK`
against `kind` rather than an operator toggle, so a second provider added later is non-publishing
until someone argues otherwise in a PR.

### Consequences

- Good, because every account that can exist can publish. There is no login that ends in a 403
  explaining what you cannot do.
- Good, because the operator holds one client secret and one callback URL, and one provider's
  consent-screen change is the only one that can become our outage.
- Good, because the reviewer's question — "is this claimant the author of that repository" — is
  answerable for every account in the system, with no second class of user it cannot be asked about.
- **Bad, because account recovery through a second linked identity is given up.** Every account has
  exactly one identity, so a lost or deleted GitHub account orphans its plugins, and the only
  recovery is a human proving ownership out of band. ADR-0003 named this fragility and answered it
  with "link another provider"; that answer is gone.
- **Bad, because an author who does not use GitHub cannot hold an account at all**, where before
  they could at least register. What they could *do* with it was nothing, but the door is now shut
  rather than ajar.
- **Bad, because the account/identity join is now cost without present benefit.** It buys a future
  provider and nothing today, and a reader meeting the two tables for the first time will
  reasonably ask why.

### Reversal cost

An afternoon per provider: a package under `internal/identity/`, a row in `identity_provider`, two
environment variables and a callback route. The schema does not move, which is why ADR-0003's
model was kept.
