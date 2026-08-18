# ADR-0002 — Index metadata only; artifacts stay on GitHub Releases

**Status:** accepted · **Date:** 2026-08-18 · **Deciders:** Courtney Caldwell

## Context and problem statement

The registry has to tell a client where to get a plugin and how to know it got the right bytes. It
does not have to be the thing that serves those bytes. Deciding otherwise commits the project to
storage costs, egress costs, an abuse surface, and a takedown process — permanently, because once a
download URL points at us, moving it breaks installs.

Today every listed plugin is a zip attached to a GitHub release of the plugin's own repository.

## Considered options

| Option | For | Against |
|---|---|---|
| A — Index only: store URL + sha256, artifacts stay on GitHub | No storage, no egress, no abuse surface, and it matches what every plugin already publishes. GitHub's CDN is better than ours will be | A dead upstream repo means a dead download, and we cannot serve a plugin whose author deleted it |
| B — Host artifacts ourselves | Downloads survive the upstream disappearing; one place to revoke a malicious build | Storage and egress on a hobby VPS, plus we become a distributor of third-party code, with the moderation and legal exposure that implies |
| C — Index now, mirror opportunistically later | Cheap start, keeps the option | The option is only real if the schema and API leave room for it, which is work done now for a benefit taken later |

## Decision outcome

**Chosen: A, with C's discipline.** Store `url` and `sha256`; do not store bytes. The `release`
table carries `artifact_bytes` and the fetch machinery already streams the whole artifact to hash
it, so adding storage later is a column and a writer, not a redesign — but nothing in this pass
implements it.

The consequence that matters is a division of labour: **GitHub is transport, and the hash is the
security boundary.** A compromised CDN, a redirected URL or a re-uploaded release asset all produce
bytes that fail the recorded hash, and the client refuses them before extraction. That property is
why option A does not weaken security relative to option B — the registry is not trusted to serve
correct bytes under either.

Enforcement: `internal/artifact` computes the hash from bytes it fetched itself
([ADR-0008](0008-server-rehashes-every-artifact.md)); a submitted hash is never stored.

### Consequences

- Good, because the running cost of the service is a small VPS and stays there regardless of how
  popular a plugin becomes.
- Good, because we are an index, not a distributor, which keeps the moderation question about
  *listings* rather than about hosting other people's code.
- Good, because plugin authors change nothing: they already publish a release zip.
- **Bad, because a deleted or renamed upstream repository breaks the download** for everyone who has
  not yet installed, and we can do nothing about it but delist.
- **Bad, because we cannot serve an older version.** Only `latest` is on the wire and the bytes are
  not ours; a user who needs to roll back has the copy in their `plugins/trash/` or nothing.
- **Bad, because availability is now a third party's.** A GitHub outage is a registry outage from the
  user's point of view, and our status page cannot explain it away.

### Reversal cost

Two weeks to add object storage, a download endpoint and a backfill that re-fetches every listed
artifact. Cheap because the schema and the fetch path were built with it in mind; the expensive part
is the operational commitment, not the code.
