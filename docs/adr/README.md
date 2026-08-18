# Architecture decision records

Why things are the way they are, including the downsides. Use
[`0000-template.md`](0000-template.md); budget one screen, about 900 words, 1000 is the ceiling.

**An ADR with no negative consequences is rejected in review.** Six months from now the person
re-litigating a decision needs the costs stated plainly by the people who accepted them.

Never edit an accepted ADR's decision — write a new one and mark the old one superseded, both
directions linked. Where the new ADR narrows the old one rather than replacing it, the status is
`accepted, amended in part by ADR-NNNN` and a blockquote under it names which part still governs —
`superseded by` on a decision whose model is still the one in the code sends the next reader past a
document they need.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-go-single-binary-and-sqlite.md) | One Go binary and one SQLite file | accepted |
| [0002](0002-index-only-artifacts-stay-on-github.md) | Index metadata only; artifacts stay on GitHub Releases | accepted |
| [0003](0003-identity-is-provider-subject.md) | Identity is a `(provider, subject)` pair | accepted, amended by [0011](0011-github-is-the-only-identity-provider.md) |
| [0004](0004-github-required-to-publish.md) | GitHub identity is required to publish | accepted, amended by [0011](0011-github-is-the-only-identity-provider.md) |
| [0005](0005-pats-scoped-to-plugins.md) | PATs belong to accounts and are scoped to plugins | accepted |
| [0006](0006-atlas-authors-goose-applies.md) | Atlas authors migrations, goose applies them | accepted |
| [0007](0007-review-new-ids-trust-gates-updates.md) | Review every new id; trust levels gate updates | accepted |
| [0008](0008-server-rehashes-every-artifact.md) | The server re-hashes every artifact | accepted |
| [0009](0009-serve-schema-v1-at-a-stable-path.md) | Serve schema v1 at a stable path | accepted |
| [0010](0010-history-in-the-db-latest-on-the-wire.md) | Keep every release; ship only `latest` | accepted |
| [0011](0011-github-is-the-only-identity-provider.md) | GitHub is the only identity provider | accepted |

## What this project replaces

The static registry at [`prokopto-dev/nparseplus-plugins`](https://github.com/prokopto-dev/nparseplus-plugins):
one `index.json` published from GitHub Pages, edited by pull request, validated by
`.github/workflows/validate-index.yml`, and merged by a human. Its safety properties are the
baseline every decision here is measured against — see
[`docs/concepts/trust-model.md`](../concepts/trust-model.md) for what each one became.

## Where this project diverges from its siblings

`dragonkillparty` and `tod-serve` share this house style, so a divergence is a thing to justify
rather than a thing to notice later.

| Divergence | Sibling rule | Here | Why |
|---|---|---|---|
| Outbound HTTP | Only `internal/identity/*` | Also `internal/artifact` | Publishing requires fetching the artifact to hash it ([0008](0008-server-rehashes-every-artifact.md)) |
| Token binding | Bound to a membership (tod-serve) | Bound to an account, optionally pinned to one plugin | There is no membership concept here; the blast radius that matters is per-plugin ([0005](0005-pats-scoped-to-plugins.md)) |
| Wire format ownership | The project owns its API shape | `index.json` is pinned by a parser we do not control | Released desktop clients already parse it ([0009](0009-serve-schema-v1-at-a-stable-path.md)) |
| Public read path | Everything behind auth | `/index.json` is unauthenticated | The client sends no credentials and cannot be taught to ([canonical §1](../design/00-canonical-conventions.md#1-the-wire-format-is-not-ours-to-change)) |
