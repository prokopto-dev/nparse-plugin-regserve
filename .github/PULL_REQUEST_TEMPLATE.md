## What and why

<!-- What changes, and what problem it solves. Link the issue if there is one. -->

## Rules and gates

<!-- Delete rows that do not apply. Do not delete a row because the answer is awkward. -->

- [ ] Any new rule ships with its gate, registered in `docs/concepts/invariants.md`
- [ ] Docs changed in this PR, not a later one
- [ ] A decision here got an ADR (with what it rejected, and a real downside)
- [ ] `make check` passes

## Wire format

<!-- Only if this touches internal/registry or the index endpoints. -->

- [ ] `schema_version` is still `1`
- [ ] `SCHEMA001` passes and the vendored schema was **not** edited
- [ ] Any new field is additive; nothing renamed or removed

## Trust model

<!-- Only if this touches publishing, artifacts, ownership, auth or moderation. -->

- [ ] No submitted sha256 is persisted; the stored hash is one the server computed
- [ ] An unverifiable artifact still goes to review rather than being published
- [ ] No new outbound HTTP outside `internal/identity/*` and `internal/artifact`

## Risks and follow-ups

<!-- What could this break, and what did you deliberately leave for later? -->

## Issues filed

<!-- Out-of-scope findings you hit. File them; a link here, not a paragraph. -->
