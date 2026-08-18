# Security policy

## Reporting

**Do not open a public issue.** Use GitHub's private vulnerability reporting on this repository
(*Security → Report a vulnerability*), or email the maintainer.

Expect an acknowledgement within a few days. This is a volunteer project; there is no SLA and
pretending otherwise would be worse than saying so.

## What this service is trusted with

Worth stating plainly, because it shapes what counts as a vulnerability here:

- **Every publisher's identity and credentials.** OAuth subjects, sessions, and PAT hashes.
- **The sha256 of every listed plugin.** This is the one that matters most. The nParse+ installer
  refuses to extract an archive whose bytes do not match the hash we published, *before*
  extraction — so that hash is the last thing standing between a user and arbitrary code running on
  their machine. Anything that lets an attacker choose a published hash is critical, full stop.
- **Who owns which plugin id.** Ownership is the right to ship code to everyone who installed that
  plugin. Ids are permanent and never recycled precisely so a delisted plugin cannot be adopted by
  someone else and used to push an update to its former users.

## Especially interested in

- Anything that results in a published sha256 the server did not compute from bytes it fetched.
- SSRF via a publish request. The server fetches user-supplied URLs by design
  ([ADR-0008](docs/adr/0008-server-rehashes-every-artifact.md)); the dialer refuses private,
  link-local, loopback, multicast and cloud-metadata addresses, `https` is re-asserted on **every**
  redirect hop, and the size cap is enforced *during* the read. A way around any of those is a
  finding.
- Claiming or publishing to a plugin id you do not own, including through a handover race.
- Token scope or plugin-pin escape, or any path by which a PAT reaches a capability-floor operation
  (minting tokens, changing owners, setting trust). Those are session-only and there is no
  `admin:*` scope.
- OAuth `state`/PKCE handling, session fixation, or identity linking that lets one account inherit
  another's ownership.
- Anything that makes the served index invalid. A malformed document is not cosmetic: every client
  refuses the whole index, so one bad listing takes the plugin browser down for everybody at once.

## Known gaps

Stated rather than discovered:

- **The index is not signed.** Its integrity rests on TLS and on our not being compromised. Index
  signing (minisign/ed25519, public key shipped in the app) is on the nParse+ roadmap and is what
  would survive a compromise of this server. Until then, a registry compromise means an attacker can
  publish a hash of their choosing, and the client will honour it.
- **A trusted owner's version bump is not reviewed by a human** before it reaches users. That is a
  deliberate trade, accounted for in [`docs/concepts/trust-model.md`](docs/concepts/trust-model.md).
- **Pre-1.0 and incomplete.** Authentication, publishing and moderation are specified but not yet
  built; do not run this against real users expecting the full model to be in place. Check
  [`ROADMAP.md`](ROADMAP.md).

## Out of scope

- Vulnerabilities in a listed plugin. Report those to its author; if one is malicious, report it
  here privately and it will be delisted.
- Findings from automated scanners with no demonstrated impact.
- Anything requiring an already-compromised droplet or an already-stolen maintainer credential.
