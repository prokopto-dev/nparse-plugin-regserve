# Contributing

Thanks for wanting to help. This is a small project with an unusually explicit rulebook, because
much of it is written by AI agents under human review and a rule nobody enforces stops being true.

**Read [`AGENTS.md`](AGENTS.md) first.** It is normative for humans too, not just agents.

## Before you start

```bash
make setup-check   # tells you what tooling you are missing
make check         # everything CI runs
```

You need Go 1.26. For container work you need **BuildKit**: the Dockerfile uses `$BUILDPLATFORM` and
cache mounts, which the legacy builder cannot parse — and, worse, it fails while exiting 0, so a
build that did nothing looks like a build that worked. On macOS:

```bash
brew install docker-buildx
mkdir -p ~/.docker/cli-plugins
ln -sfn "$(brew --prefix)/opt/docker-buildx/bin/docker-buildx" ~/.docker/cli-plugins/docker-buildx
docker buildx version   # should print a version, not "unknown command"
```

Hooks are tracked. Either works:

```bash
lefthook install
# or
git config core.hooksPath .githooks
```

They add your DCO sign-off automatically, format staged Go files, refuse to commit a database or a
key, and run the gates before a push.

## The shape of a good change

- **A rule ships with its gate.** If you add an invariant, add the test or check that enforces it
  and register it in [`docs/concepts/invariants.md`](docs/concepts/invariants.md). If you cannot
  mechanise it, say so in the PR and put it in the "review rules" section — an unenforced rule in
  the enforced table is worse than no rule, because people trust the table.
- **Docs change in the same PR as the behaviour they describe.**
- **A decision gets an ADR.** Use [`docs/adr/0000-template.md`](docs/adr/0000-template.md). It must
  name what it rejected and state a real downside — `make docs-check` fails otherwise, and an ADR
  with no downsides reads as a decision made carelessly.
- **Tests are `require`, not `assert`.** `assert` continues after failure and buries the real first
  failure under cascading noise.

## What will get a change sent back

- Editing a generated file instead of its source (`internal/store/sqlitegen/`, `db/migrations-*/`).
- Editing `internal/registry/testdata/index-v1.schema.json`. It is generated upstream from the
  models a released client parses with; a mismatch means the renderer is wrong.
- Weakening or skipping a test to go green. A failing test is information.
- Disabling a lint rule or a gate to land something.
- Adding a dependency without proposing it first, with the reason and the licence.

## Commits and PRs

- Sign off: `git commit -s` (DCO). The hook does it for you.
- Conventional Commits are enforced on the **PR title only** — squash-merge makes it the commit
  subject. Your WIP commits can say anything.
- One concern per PR.

## Security

Do not open a public issue for a vulnerability. See [`SECURITY.md`](SECURITY.md).
