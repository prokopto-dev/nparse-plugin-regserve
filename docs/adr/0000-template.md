# ADR-NNNN — Short imperative title

**Status:** proposed · **Date:** YYYY-MM-DD · **Deciders:** owner

## Context and problem statement

Five sentences at most. What forced a decision, what constraint applies, and what breaks if the
question is left open. Mark any empirical claim as an assumption and name where it gets verified.

## Considered options

At least two, each with one real argument for and one real argument against. An option you never
seriously considered does not belong here; padding the list makes the ADR less trustworthy, not more.

| Option | For | Against |
|---|---|---|
| A — … | … | … |
| B — … | … | … |

## Decision outcome

**Chosen: B.** One paragraph of justification, then the specifics — the shape of the thing, the
enforcement mechanism, the boundary of the decision. Where a rule has a mechanism (a test, a lint
rule, a CI gate, a DB trigger), name it. A rule without a mechanism is a wish.

### Consequences

- Good, because …
- Good, because …
- **Bad, because …**
- **Bad, because …**

An ADR with no negative consequences is rejected in review. Six months from now the person
re-litigating this decision needs the costs stated plainly by the people who accepted them; if they
have to discover the downside themselves, they will conclude the decision was made carelessly.

### Reversal cost

One line: what it costs to undo this in two years. Be specific — "a day", "a release", "a rewrite of
`internal/ledger` and a data migration nobody can validate".

---

**Rules for writing one of these.**

- Budget one screen, about 900 words. The docs word-count check fails an ADR over budget; over budget
  usually means two decisions in one file.
- Status values: `proposed` · `accepted` · `superseded by ADR-NNNN` · `deprecated`. Never edit an
  accepted ADR's decision — write a new one and mark the old one superseded, both directions linked.
- Present tense, second person for instructions. No marketing voice.
- Link the enforcing test, gate or trigger by name, not by description.
