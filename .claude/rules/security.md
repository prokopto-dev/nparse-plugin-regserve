---
description: The trust model, and the parts of it that are load-bearing
paths: ["internal/artifact/**", "internal/auth/**", "internal/identity/**", "internal/moderation/**", "internal/ownership/**"]
---

# What this service is trusted with

The published sha256 is the last thing between a user and arbitrary code: the nParse+ installer
refuses to extract an archive whose bytes do not match it, *before* extraction.

- **Never store a submitted hash.** `internal/artifact` downloads the artifact and computes the
  hash; the submitted value is only ever compared, then discarded. See ADR-0008.
- **An artifact that could not be fetched is not published.** It goes to review with the reason
  recorded. "We could not check" and "we checked and it was fine" must never produce the same
  outcome — this is the rule most likely to be optimised away by someone reading a timeout as a
  transient annoyance.
- **Bytes are hashed and discarded.** Never extracted, never written to a persistent path, never
  executed, never imported.
- **The fetch is hostile-input handling.** `https` re-asserted on *every* redirect hop, hop count
  capped, 50 MiB enforced *during* the read, explicit timeout, and a dialer refusing private,
  link-local, loopback, multicast and cloud-metadata addresses. Each is load-bearing; removing one
  is a security change that must be argued in the PR.
- **Plugin ids are never recycled.** Delisting clears the listing and keeps the claim. An id that
  becomes available again is a way to ship an update to somebody else's users.
- **A new plugin id always gets human review.** Trust levels govern version bumps of an
  already-approved plugin, never the first appearance of an id.
- **The capability floor carries no scope.** Minting tokens, changing owners and setting trust are
  session-only. There is no `admin:*` and no token that can escalate itself — that is what makes a
  leaked publish token containable.
- **Only `github` identities may publish.** A `CHECK` against `identity_provider.kind`, not an
  operator toggle.

`audit_log` is append-only. Corrections are new rows.

Full accounting of what the static registry guaranteed and what replaced it:
`docs/concepts/trust-model.md`.
