# ADR-0008 — The server re-hashes every artifact; the hash is the security boundary

**Status:** accepted · **Date:** 2026-08-18 · **Deciders:** Courtney Caldwell

## Context and problem statement

A publish request arrives with a URL and a sha256. The nParse+ installer refuses to extract an
archive whose bytes do not match the hash the registry published, so that hash is the only thing
standing between a user and arbitrary code. The question is where the value we publish comes from.

The submitter is the least trustworthy source available: their CI computed it, and their CI is what
we are worried about being compromised.

## Considered options

| Option | For | Against |
|---|---|---|
| A — Store the submitted hash | Free. The plugin release workflow already computes it correctly | We would be publishing an attacker-chosen hash for attacker-chosen bytes. The client would verify perfectly against exactly the wrong value |
| B — Fetch the artifact and compute the hash ourselves; require it to match the submission | The published value is one we derived from bytes we saw. A mismatch is a signal, and it is caught before anyone installs | Every publish downloads up to 50 MiB, so publishing is slow and the server is an SSRF surface by construction |
| C — Fetch and compute, but do not require a submitted hash at all | Simpler request; nothing to disagree with | Loses the cross-check. If the author's CI and our fetch see different bytes, we would silently publish ours and never know |

## Decision outcome

**Chosen: B.** `internal/artifact` downloads the artifact and computes the sha256; the submitted
value is compared against it and then **discarded**. The stored hash is always ours.

The comparison is the point. If they differ, something between the author's build and our fetch
changed the bytes — a re-uploaded release asset, a compromised token, a hijacked URL — and that is
precisely the event worth stopping. A mismatch is fatal to the request and recorded.

An artifact that **could not be fetched is not published.** It goes to review with the reason
recorded. This is the rule most likely to be "optimised" later by someone who reads a timeout as a
transient annoyance; it is not, because "we could not check" and "we checked and it was fine" must
never produce the same outcome.

The fetch is hostile-input handling throughout: `https` re-asserted on **every** redirect hop, hop
count capped, **50 MiB enforced during the read** rather than after, an explicit timeout, and a
dialer that refuses private, link-local, loopback, multicast and cloud-metadata addresses. The bytes
are hashed streaming and **discarded** — never extracted, never written to a persistent path, never
executed. The CI job this replaces made the same choice for the same reason.

### Consequences

- Good, because the published hash is one we derived from bytes we saw, so the client's verification
  is anchored to something we actually checked.
- Good, because a hash mismatch surfaces artifact tampering at publish time rather than on a user's
  machine.
- Good, because refusing to publish an unverifiable artifact means a listing always represents bytes
  that existed and were measured.
- **Bad, because every publish downloads the whole artifact**, which makes publishing slow, uses
  bandwidth, and means a large plugin's release can time out for reasons unrelated to its contents.
- **Bad, because we have built a service that fetches user-supplied URLs**, which is an SSRF surface
  that would not exist otherwise. The dialer restrictions are load-bearing and one careless refactor
  from being bypassed.
- **Bad, because an upstream that is merely slow gets treated as suspicious**, so a GitHub incident
  turns routine releases into a review backlog a human has to clear by hand.

### Reversal cost

Not reversible in any meaningful sense — trusting the submitted hash would be abandoning the trust
model, not changing a decision. The tunable parts (size cap, timeout, hop limit) are constants.
