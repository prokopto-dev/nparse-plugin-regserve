# ADR-0013 — Release notes are plain text, capped, and additive on the wire

**Status:** accepted · **Date:** 2026-08-20 · **Deciders:** Courtney Caldwell

## Context and problem statement

Users should be able to see what changed in a release. Today the index carries a version, a URL and
a hash, and nothing that says why anyone would want the update — so a plugin browser can offer
"1.4.0 is available" and nothing more.

The complication is what a release note *is*: author-supplied text rendered inside a desktop
application on someone else's machine. It is the first field whose *content* is meant for a human
rather than checked by a machine, and the first whose length an author controls — against an index
budget the client aborts past at 5 MiB
([canonical §1](../design/00-canonical-conventions.md#1-the-wire-format-is-not-ours-to-change)).

## Considered options

| Option | For | Against |
|---|---|---|
| A — No notes at all | Nothing to sanitise or budget; the client already links to a GitHub release page | That link is a page the user must leave the app to read. "What changed" is the one question a browse list cannot answer |
| B — Plain text, hard byte cap, additive field on `latest` | The client needs no sanitiser: text is text. The cap is arithmetic against a budget we do not own. A Markdown subset can be added later, additively | No emphasis, no links, no lists. Authors who write Markdown see asterisks, and some will file that as a bug |
| C — A restricted Markdown subset | Reads the way a changelog is already written | Every client needs a sanitiser and a renderer, and they must agree across versions we cannot patch. A link is an author-controlled navigation inside an app the user trusts. The subset can never be *narrowed* later |
| D — Full Markdown or HTML | No surprises for authors | Arbitrary markup from a publish request, rendered in a desktop client. The shape of the vulnerability, not a decision |

## Decision outcome

**Chosen: B.** Plain text, a hard cap enforced by the server, surfaced as an additive field.

**Plain text is a contract with the client, not a filter on the input.** The registry does not strip
Markdown or escape HTML: it stores what was submitted, minus what is not text at all. The promise is
that the field is *not markup*, so a client renders it in a text widget. What is rejected at publish
time is stated precisely, because "we sanitise this" and "we promise not to interpret it" are a
guarantee and a hope:

- it must be valid UTF-8;
- it must carry no C0 or C1 control characters other than `\n`, so a terminal-style renderer cannot
  be driven by an escape sequence;
- it must be **at most 2048 bytes**.

An author who writes `**bold**` gets literal asterisks. That is a real cost and it is the point:
nothing in the pipeline has to decide what markup means.

**The cap is bytes, enforced by the database as well as by the publish path.** The budget is bytes
on a wire and SQLite's `length()` counts characters, so the `CHECK` uses
`length(CAST(notes AS BLOB))`. 2048 bytes is roughly three hundred words, and arithmetic fixes it:
`SIZE001` fails as the index approaches 80% of the client's 5 MiB cap, and at 2 KiB a thousand
listings spend 2 MiB on notes alone — a 4 KiB cap would put a thousand plugins over the gate. A cap
living only in Go is one that a migration, a later phase, or a hand-run `UPDATE` during an incident
does not go through.

**The column is `release.notes`; the wire field is `release_notes`.** Canonical §7: a column is
never named after a wire field, because sqlc writes column names into Go string literals in
`internal/store/sqlitegen`, and one named after a wire field would put that name in a second package
and fail `SCHEMA002`.

**What lands now is the column and the cap.** *Populating* notes belongs with the publish path
(Phase 3) and *rendering* them with the client update (Phase 4), so `internal/registry` is untouched
and the served bytes are unchanged. Released clients ignore unknown keys, which is what makes the
field additive and landing it in three pieces safe.

### Consequences

- Good, because a client needs no sanitiser and no Markdown renderer to show a changelog.
- Good, because the cap is enforced where it cannot be bypassed, and is arithmetic against a budget
  somebody else owns rather than a number that felt about right.
- Good, because the restriction can be relaxed later, and relaxing is the direction that breaks
  nothing.
- **Bad, because authors will write Markdown and see asterisks.** The first bug report about it
  will be right about the experience and wrong about the fix.
- **Bad, because 2048 bytes will be too few for somebody's genuine changelog**, and the publish
  fails rather than shortening it — the right half of that choice, and still a failed publish at
  the end of a release process.
- **Bad, because the index grows by up to 2 KiB per listing**, bringing the day `SIZE001` fires
  closer for decoration rather than function. The gate makes that visible in advance.
- **Bad, because "plain text" is a promise no gate can check on the client's side.** A client that
  renders the field as Markdown is doing what this ADR says it should not, and nothing here stops
  it.

### Reversal cost

Low in the permissive direction and high in the restrictive one, which is why it starts strict.
Widening to a Markdown subset is an additive change plus a client release. Narrowing — dropping the
field, shrinking the cap, removing a syntax once it renders — breaks listings already published and
clients already shipped, and neither can be un-shipped.
