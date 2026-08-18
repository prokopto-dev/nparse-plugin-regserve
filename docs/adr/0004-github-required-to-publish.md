# ADR-0004 — GitHub identity is required to publish

**Status:** accepted, amended in part by [ADR-0011](0011-github-is-the-only-identity-provider.md)
· **Date:** 2026-08-18 · **Deciders:** Courtney Caldwell

> The `can_publish` `CHECK` below stands unchanged. ADR-0011 drops the Discord and Google logins
> this ADR was drawing a line against, so the non-publishing account it describes no longer
> exists. Read the rest as the record of what was thought at the time.

## Context and problem statement

Three login providers are offered ([ADR-0003](0003-identity-is-provider-subject.md)), but artifacts
live on GitHub Releases ([ADR-0002](0002-index-only-artifacts-stay-on-github.md)) and the ownership
records being migrated are GitHub handles. If any authenticated account can claim any plugin id and
point it at any URL, the first-come id rule becomes a land grab with no way to tell a real author
from someone who read the repository list.

## Considered options

| Option | For | Against |
|---|---|---|
| A — Any provider may claim and publish; review is the only check | Lowest friction, and a human reviews new ids anyway | The reviewer has nothing to check *against*. "Is this person the author of that repo" is exactly the question an identity could answer and a Google login cannot |
| B — GitHub identity required to publish; Discord and Google log in and browse | The publisher's identity is in the same namespace as the artifact they are publishing, so repository ownership is checkable. Matches the ownership data being migrated | An author who only uses GitLab is excluded from publishing, and we have added a hard dependency on one company for the write path |
| C — Any provider, but require a proof-of-repo-control challenge (a file, a gist, a release note) | Provider-agnostic, and it verifies the thing we actually care about | A bespoke challenge flow to build, document and support, for a population that is already almost entirely on GitHub |

## Decision outcome

**Chosen: B.** The registry's whole trust argument is that the reviewed bytes came from the person
who owns the plugin. GitHub is where those bytes live, so a GitHub identity is the one credential
that lets a reviewer — or later, an automated check — connect the publisher to the artifact.

Mechanism: `identity_provider.can_publish` is a `CHECK` against `kind`, true only for `github`. It is
**not an operator toggle**, because everything about the claim "this listing is the author's" hangs
off it, and a boolean an operator can flip is a boolean somebody eventually flips at 2am.

The boundary of the decision: this gates *publishing and ownership*, not accounts. A Discord- or
Google-authenticated account is a real account — it can log in, browse, hold no plugins, and be
linked to a GitHub identity later, at which point it can publish. Linking, not re-registering.

An account attempting to publish without a linked GitHub identity gets a 403 whose problem document
names the missing link and the endpoint that adds it. Silence here would be indistinguishable from
a permissions bug.

### Consequences

- Good, because the reviewer of a new plugin id can compare the claimant's GitHub identity against
  the repository the artifact URL points at, which is the actual question.
- Good, because the migration from `owners.json` is a resolution of handles to subjects rather than
  an invitation for every existing author to re-prove who they are.
- Good, because it leaves room for automating the review: repository ownership is machine-checkable
  through GitHub's API in a way "some Google account" never is.
- **Bad, because it excludes authors who do not use GitHub** from publishing at all, and the answer
  we have for them is "make an account", which is a real cost we are imposing.
- **Bad, because the write path now depends on GitHub being up** — not just for downloads, but for
  login. A GitHub outage stops publishing entirely.
- **Bad, because offering three login buttons and then refusing two of them at the moment of publish
  is a confusing product.** The 403 message is doing a lot of work, and some users will hit it.

### Reversal cost

An afternoon to flip the CHECK and allow any verified provider, plus whatever review process has to
grow to replace what GitHub identity was answering. The data model does not move.
