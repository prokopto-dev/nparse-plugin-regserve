# Publishing from CI

**Audience:** a plugin author with a repository, a build, and a tag. This page is how your release
pipeline lists a new version in the nParse+ plugin registry without anybody opening a pull request.

It replaces the old flow — a PR against `prokopto-dev/nparseplus-plugins`, edited by hand, merged by
a maintainer — with a call to a workflow this repository publishes.

The same walkthrough, shorter and on the web, is at
<https://nparseplugins.prokopto.dev/publish>.

## Start here

Six steps, in this order. The order is load-bearing in one place: a token is pinned to a plugin id,
so the id has to exist before the token can be minted.

1. **Start from the template.**
   [`prokopto-dev/nparse-plugin-template`](https://github.com/prokopto-dev/nparse-plugin-template)
   is a plugin that builds, with the manifest, the layout and a release workflow already in it. Use
   it as a GitHub template repository. Writing one from scratch is fine too: what this registry
   needs from a build is one artifact at a public `https` URL and a version string your plugin
   declares.
2. **Claim your plugin id.** Sign in at <https://nparseplugins.prokopto.dev/> with GitHub and use
   the **Claim a plugin id** form on [/account](https://nparseplugins.prokopto.dev/account). Ids are
   first-come, permanent and **never recycled** — an id names your plugin in every installed copy on
   every user's machine. **No token can do this step**, however scoped; see
   [Claiming is a separate step, and session-only](#claiming-is-a-separate-step-and-session-only).
3. **Mint a scoped token** on **/account**: `plugin:publish`, pinned to that id, nothing else. The
   pin is a plugin id you must already hold, which is why step 2 comes first.
4. **Store it as a repository secret** in your plugin repository, as `REGSERVE_TOKEN`.
5. **Tag a release.** Your workflow builds the artifact and uploads it to the GitHub Release.
6. **Call the reusable workflow** as one more job. It publishes, or it records that a human needs to
   look — see [Reading the result](#reading-the-result).

**Expect your first release to wait for a human.** A new plugin id *always* goes to human review,
whatever your trust level ([ADR-0007](../adr/0007-review-new-ids-trust-gates-updates.md)). The job
succeeds with a warning and reports `state: pending`; the release is durably recorded and its
version is claimed. That is the correct outcome, not a broken publish, and reading it as a failure
is the mistake this page most wants to prevent.

### Claiming is a separate step, and session-only

**Publishing does not claim an id, and a token cannot claim one.** These are two different acts with
two different credentials, and the order matters: claim first, mint second.

Claiming is **capability-floor** — session-only, no scope, no token, ever — because a deployment
credential that could register new ids would grow its own reach every time it was used
([ADR-0005](../adr/0005-pats-scoped-to-plugins.md)). There are two doors onto the same
act and both need a browser session:

- the **Claim a plugin id** form on [/account](https://nparseplugins.prokopto.dev/account);
- `POST /api/v1/plugins`, carrying your own `__Host-regserve_session` cookie.

If you skip it, your publish job is answered **404**, and the message names the step:

```json
{
  "code": "not_found",
  "detail": "no such plugin, or you do not hold it. Publishing never claims an id, and no token
             can claim one however scoped — claiming is session-only. If you have not claimed this
             id, sign in at https://nparseplugins.prokopto.dev/account and claim it there, then
             publish again; if you have, check that you are still an owner."
}
```

**That is the same answer for an id nobody has claimed and an id somebody else holds**, and
deliberately so. The registry will not tell you which, from this endpoint, however you ask: ids
are permanent and never recycled, so a refusal that distinguished the two would let anyone with a
publish token sweep a wordlist for unclaimed names. The guidance above is unconditional — it is
true of the registry rather than of your id — which is why it can be said at all.

If you are not sure which of the two you are in, the claim form tells you: claiming an id somebody
else holds is a `409`, and it still does not say who.

## The short version

```yaml
# .github/workflows/release.yml, in YOUR plugin repository
name: Release

on:
  push:
    tags: ['v*']

permissions:
  contents: write        # to create the GitHub Release and upload the artifact

jobs:
  build:
    runs-on: ubuntu-24.04
    outputs:
      version: ${{ steps.meta.outputs.version }}
      sha256: ${{ steps.meta.outputs.sha256 }}
    steps:
      - uses: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 # v5.0.0

      # …build merchant_mode.zip however your plugin builds…

      - id: meta
        env:
          TAG: ${{ github.ref_name }}
        run: |
          set -euo pipefail
          # The TAG is v1.2.0 and the VERSION is 1.2.0. Stripping it here, in your repository,
          # where you can see it happen — the registry deliberately does not guess.
          echo "version=${TAG#v}" >> "$GITHUB_OUTPUT"
          echo "sha256=$(sha256sum merchant_mode.zip | cut -d' ' -f1)" >> "$GITHUB_OUTPUT"

      # …create the GitHub Release and upload merchant_mode.zip to it…

  publish:
    needs: build
    uses: prokopto-dev/nparse-plugin-regserve/.github/workflows/publish-plugin.yml@5b0d87f7666f20c0c188b7208ad2738bd55c10d7 # v0.3.0
    with:
      plugin-id: merchant-mode
      version: ${{ needs.build.outputs.version }}
      artifact-url: https://github.com/${{ github.repository }}/releases/download/${{ github.ref_name }}/merchant_mode.zip
      artifact-sha256: ${{ needs.build.outputs.sha256 }}
      minimum-app-version: '2.1.0'
      notes: |
        Fixed the price graph on servers with no recent sales.
        Took the mule list out of the tooltip.
    secrets:
      registry-token: ${{ secrets.REGSERVE_TOKEN }}
```

### Pin the `uses:` line to a commit, not to a tag and not to a branch

The ref above is a **40-character commit SHA** with `# v0.3.0` beside it, and both halves are doing
work.

A reusable workflow runs *your* job with *your* secret, so the ref you copy from us decides what
gets to run next to your publish token. `@main` would mean whatever that branch says tomorrow gets
it. **`@v0.3.0` would not be a pin either:** a tag is a movable label, and one `git tag -f` and a
force-push in this repository would change what every pipeline that copied it runs on its next
release — no diff to review, nothing to notice. That is `@main`'s property, spelled slower. Only the
commit SHA cannot move.

The comment is not decoration. Forty hex characters do not say which release you are on, and a pin
you cannot place is a pin you will never update. This repository pins every action it uses the same
way (gate `PIN001`), and gate `DOC003` fails this page if a reference here is anything other than a
commit SHA that names its release.

**Upgrading is then a thing you choose.** Watch this repository's releases, read what changed, and
move the SHA on a day you are looking at it — rather than discovering the new version on your own
release day.

## Getting the token

This is step 3 above, and it needs step 2 done first: a token is pinned to a plugin id, and the
`/account` form offers only ids you already own.

1. Sign in at <https://nparseplugins.prokopto.dev/> with the GitHub account that owns the plugin.
2. On **/account**, mint a token:
   - **scope: `plugin:publish`** and nothing else. Not `plugin:manage`, not `plugin:read` — a
     release pipeline publishes.
   - **pinned to your plugin id.** The pin is the half that contains a leak: a token that can
     publish to one plugin, stolen from one repository's CI, can publish to one plugin
     ([ADR-0005](../adr/0005-pats-scoped-to-plugins.md)).
3. **The secret is shown exactly once**, in that one response. It is never recoverable: what this
   registry stores is a keyed hash of it. Copy it straight into your repository's secrets
   (*Settings → Secrets and variables → Actions*) as `REGSERVE_TOKEN`.
4. If you lose it, revoke it and mint another. That costs one rotation, which is the point of
   per-token revocation.

The 8-character piece after `nprs_pat_` is the **public prefix**. The publish workflow prints it,
and nothing else: it is how a token found in a log is identified without the log ever having held
the secret.

A token stops working the moment its holder stops being an owner of the plugin — ownership is
checked on every request, not cascade-revoked. **Handing a plugin over is therefore two steps**: add
the new owner, let them mint their own token, and only then remove the old one.

## What the inputs mean

| Input | Required | Notes |
|---|---|---|
| `plugin-id` | yes | The permanent id in the registry, e.g. `merchant-mode`. Not the repository name unless they happen to match. Ids are never recycled |
| `version` | yes | **Exactly what your plugin declares.** A tag is `v1.2.0` and a version is usually `1.2.0`; the workflow does not guess which you meant. A version is used once per plugin, ever |
| `artifact-url` | yes | An `https` URL the artifact downloads from. Transport only — see below |
| `artifact-sha256` | no | The digest your build produced. Optional, and worth passing |
| `sdk-specifier` | no | PEP 440 specifier, default `>=1.0,<2`. Carried, not evaluated |
| `minimum-app-version` | no | Empty means no constraint, which is a different statement from a low number |
| `notes` | no | Plain text, ≤ 2048 bytes. See below |
| `registry-url` | no | Override only for a staging instance. `https` only |
| `idempotency-key` | no | Overrides the derived key. You almost certainly do not need this |

### The hash you send is not the hash that gets published

The registry **downloads the artifact and computes the sha256 itself**. Your `artifact-sha256` is
compared against that value and then discarded; what appears in the index is always a hash derived
from bytes this server read ([ADR-0008](../adr/0008-server-rehashes-every-artifact.md)). The URL is
transport; the hash is the security boundary.

So passing `artifact-sha256` is not a formality — it is an independent claim about the bytes *you
built*, and a disagreement between it and what the registry downloads means something changed
between your build and the fetch. That release is not published; it goes to review with the mismatch
recorded.

If you omit it, the workflow downloads the URL and hashes that instead, and says so in the job
summary. Both ends are then looking at the published file, so the check catches a URL that changed
between two fetches and *cannot* catch a release asset that never matched your build. It is the
weaker path and it is labelled as one.

### Notes are plain text, and they come from the workflow input

`notes` is rendered inside a desktop application on somebody else's machine, so it is plain text by
contract: not Markdown, not HTML
([ADR-0013](../adr/0013-release-notes-are-plain-text-with-a-hard-cap.md)). `**bold**` arrives as
literal asterisks. The registry does not strip markup or escape HTML — it promises never to
*interpret* the field, which is a stronger guarantee than sanitising it, and it is what lets a client
render it in a text widget with no sanitiser at all.

What is refused, rather than cleaned up: invalid UTF-8, control characters other than newline and
tab, and anything over **2048 bytes**. The publish fails and says so; it does not shorten your
changelog behind your back.

**They are not read from the GitHub Release body**, deliberately. A release body is Markdown, and it
is editable after the fact — so notes taken from one would be markup this registry promises is not
markup, and would silently stop matching what was published the first time somebody fixed a typo.

### Re-runs are safe

The workflow sends an `Idempotency-Key` derived from your repository, plugin id and version, so it
is the same key every time that release publishes. Re-run the job from the Actions tab, or let a
flaky runner retry it, and the registry returns the **original result** instead of submitting a
second release for a version that can only ever be used once. The summary says `Replayed: true` when
that happens.

## Reading the result

There are three outcomes and the workflow tells them apart, because a green tick that means three
different things is a green tick nobody reads.

**Live.** `state: approved`. The release is in the index and clients will see it on their next poll.
This happens when the plugin id already has an approved release, your account is trusted, and no
quarantine rule fired.

**Waiting for review.** `state: pending`, and the job **succeeds with a warning annotation**. This is
not a failed publish — the release is durably recorded and its version is claimed — and it is not a
completed one either. The summary lists every rule that sent it to a human. The common ones:

- **it is the plugin's first release.** A new plugin id *always* gets human review, whatever your
  trust level: the first appearance of an id is where impersonation is caught
  ([ADR-0007](../adr/0007-review-new-ids-trust-gates-updates.md)). Nothing bypasses this;
- the submitted sha256 disagreed with the bytes the registry downloaded;
- the artifact moved to a different host, or changed size sharply, or the version does not advance.

**Waiting, and the bytes were never checked.** `verified: false`. The registry could not download
the artifact — an outage, a 404, a URL that is not public yet. The release cannot be approved until
it is re-verified, because there is no hash to publish. Check that `artifact-url` actually answers
for an anonymous caller; a GitHub Release asset does not exist until the release is published, so
ordering matters if you create the release as a draft.

A refusal — anything that is not one of the three above — fails the job and prints the registry's own
sentence explaining why. Nothing is recorded, and the version is still free.

**`404 not_found` on a plugin id you believe is yours** is the one worth naming here, because it is
the first thing a new author meets. Either you never claimed the id — the message says so and says
where to claim it — or you are no longer an owner of it. Ownership is checked on every request
rather than carried on the credential, so a token that worked last month stops working the moment
its holder stops being an owner.

## Outputs

`state`, `release-id`, `verified`, `quarantine` (newline-separated) and `replayed`, so a caller can
decide for itself. To make a release that lands in review fail your pipeline:

```yaml
  require-published:
    needs: publish
    if: needs.publish.outputs.state != 'approved'
    runs-on: ubuntu-24.04
    steps:
      - env:
          REASONS: ${{ needs.publish.outputs.quarantine }}
        run: |
          echo "not live yet:"; echo "$REASONS"; exit 1
```

That is a policy for your repository to hold, not one this workflow imposes: for a plugin's first
release, "waiting for a human" is the *correct* outcome and failing on it would be failing on
success.

## Publishing without this workflow

The workflow is a convenience over one HTTP call. The endpoint is
`POST /api/v1/plugins/{id}/releases`, documented in `openapi/openapi.json`, and it needs an
`Idempotency-Key` header. Everything above about hashes, notes and outcomes applies identically —
those are properties of the registry, not of the workflow.
