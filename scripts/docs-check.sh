#!/usr/bin/env bash
# Documentation gates. The shape rules from docs/adr/0000-template.md, mechanised.
#
# These exist because the ADR format's value is entirely in the parts people skip when rushed: the
# rejected options and the honest downsides. A template nobody enforces becomes a heading nobody
# fills in.

set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
report() { printf '\033[31m%s\033[0m  %s\n' "$1" "$2"; fail=1; }
pass()   { printf '\033[32m%-10s\033[0m %s\n' "$1" "$2"; }
vacant() { printf '\033[33m%-10s\033[0m %s\n' "$1" "$2 (nothing to check yet)"; }

adrs() { find docs/adr -name '[0-9][0-9][0-9][0-9]-*.md' -not -name '0000-template.md' 2>/dev/null | sort; }

WORD_LIMIT=1000

if [ -z "$(adrs)" ]; then
  report ADR000 "no ADRs found; a project with no recorded decisions has undocumented ones"
else
  pass ADR000 "$(adrs | wc -l | tr -d ' ') ADRs present"

  over=""
  for f in $(adrs); do
    n=$(wc -w < "$f" | tr -d ' ')
    [ "$n" -gt "$WORD_LIMIT" ] && over="$over$f ($n words)\n"
  done
  if [ -n "$over" ]; then
    report ADR001 "ADR over the $WORD_LIMIT-word budget — usually two decisions in one file:"
    printf "%b" "$over"
  else
    pass ADR001 "every ADR is within the $WORD_LIMIT-word budget"
  fi

  missing=""
  for f in $(adrs); do
    grep -q -- '- \*\*Bad, because' "$f" || missing="$missing$f (no honest downside)\n"
    grep -q '^### Reversal cost' "$f"    || missing="$missing$f (no reversal cost)\n"
  done
  if [ -n "$missing" ]; then
    report ADR002 "an ADR with no stated downside is a decision nobody can re-litigate:"
    printf "%b" "$missing"
  else
    pass ADR002 "every ADR states a downside and a reversal cost"
  fi

  missing=""
  for f in $(adrs); do
    grep -q '^## Considered options' "$f" || missing="$missing$f\n"
  done
  if [ -n "$missing" ]; then
    report ADR003 "ADR missing '## Considered options':"; printf "%b" "$missing"
  else
    pass ADR003 "every ADR records what it rejected"
  fi
fi

# --- DOC001 — every error code in the closed enum has a docs page ------------------------------
# The enum is public API: a client switches on the code, so an undocumented one is a code nobody
# outside this repo can handle correctly.
if [ -f internal/api/errors.go ]; then
  missing=""
  codes=$(grep -oE 'Code[A-Za-z0-9]+[[:space:]]+Code[[:space:]]*=[[:space:]]*"[a-z_]+"' internal/api/errors.go \
          | grep -oE '"[a-z_]+"' | tr -d '"' | sort -u || true)
  if [ -z "$codes" ]; then
    vacant DOC001 "every error code has a docs page"
  else
    for c in $codes; do
      grep -rq "$c" docs/api/errors.md 2>/dev/null || missing="$missing  $c\n"
    done
    if [ -n "$missing" ]; then
      report DOC001 "error code with no entry in docs/api/errors.md:"; printf "%b" "$missing"
    else
      pass DOC001 "every error code is documented"
    fi
  fi
else
  vacant DOC001 "every error code has a docs page"
fi

# --- DOC002 — invariants.md names a mechanism for every gate the scripts define ----------------
# Catches the reverse drift: a gate that exists in the script but was never written down, so nobody
# knows the rule is enforced and somebody eventually "simplifies" it away.
if [ -f docs/concepts/invariants.md ]; then
  missing=""
  # Both locations: the shell gates and the AST gates in test/repo. A gate that exists in code but
  # was never written down is a rule nobody knows is enforced, so somebody eventually "simplifies"
  # it away in a refactor and no reviewer objects.
  gates=$( { grep -ohE '^\s*(report|pass|vacant) [A-Z]+[0-9]{3}' scripts/repo-gates.sh
             grep -ohE 'func Test[A-Z]+[0-9]{3}_' test/repo/*.go 2>/dev/null
           } | grep -oE '[A-Z]+[0-9]{3}' | sort -u )
  for g in $gates; do
    grep -q "$g" docs/concepts/invariants.md || missing="$missing  $g\n"
  done
  if [ -n "$missing" ]; then
    report DOC002 "gate defined in scripts/repo-gates.sh but not recorded in invariants.md:"
    printf "%b" "$missing"
  else
    pass DOC002 "every gate is recorded in docs/concepts/invariants.md"
  fi
else
  report DOC002 "docs/concepts/invariants.md is missing; it is where every gate is registered"
fi


# --- DOC003 — the reusable workflow is referenced by an immutable commit SHA -------------------
# `.github/workflows/publish-plugin.yml` is consumed by OTHER repositories through `workflow_call`.
# It runs their release job, with their publish token, so the ref an author copies out of our
# documentation decides what gets to run next to that secret.
#
# A TAG IS NOT A PIN. `git tag -f` plus a force-push moves `v0.3.0`, and every pipeline that copied
# it runs different code on its next release, with no diff to review and nothing to notice. That is
# `@main`'s property spelled slower, so the gate refuses both: only the 40-character commit SHA
# cannot be moved. This is deliberately stricter than what the prose used to recommend, because a
# page that calls a movable label a "pin" teaches the wrong lesson while passing its own gate.
#
# THE RELEASE TAG STILL HAS TO APPEAR, in a comment on the same line. Forty hex characters do not
# say which release a reader is on, and a pin nobody can place is a pin nobody will ever update.
#
# It also has to be ONE commit. Two pages quoting different SHAs is drift where neither page looks
# wrong on its own, and the author who reaches the older one publishes through a version nobody
# documented.
#
# The sources are overridable so the gate can be pointed at fixtures and WATCHED FAILING. A shell
# gate fails in the direction that reports success — a pattern that stops matching says "no
# findings" over a file it never read — so test/repo/docs_test.go runs this against trees it must
# reject. That is the same reason scripts/act-gates.sh takes a directory.
REF_PREFIX='prokopto-dev/nparse-plugin-regserve/\.github/workflows/publish-plugin\.yml@'
REF_SOURCES="${DOC003_SOURCES:-docs internal/api/webtmpl README.md}"
reflines=$(grep -rhE "${REF_PREFIX}[A-Za-z0-9._/-]+" $REF_SOURCES 2>/dev/null || true)

if [ -z "$reflines" ]; then
  vacant DOC003 "the reusable workflow is referenced by an immutable commit SHA"
else
  refs=$(printf '%s\n' "$reflines" | grep -oE "${REF_PREFIX}[A-Za-z0-9._/-]+" \
         | sed 's/.*@//' | sort -u)

  movable=""
  for r in $refs; do
    # A branch, a tag, a `v1` alias and an abbreviated sha are all refs somebody can repoint at
    # code the author never read. Only the full commit SHA is immutable.
    printf '%s' "$r" | grep -qE '^[0-9a-f]{40}$' || movable="$movable  @$r\n"
  done

  commits=$(printf '%s\n' $refs | grep -cE '^[0-9a-f]{40}$' || true)
  named=$(printf '%s\n' "$reflines" | grep -cE '#[[:space:]]*v[0-9]+\.[0-9]+\.[0-9]+' || true)
  total=$(printf '%s\n' "$reflines" | grep -c . || true)

  if [ -n "$movable" ]; then
    report DOC003 "the reusable workflow is referenced by a movable ref; a tag can be retagged and \
a branch is worse:"
    printf "%b" "$movable"
  elif [ "$commits" != "1" ]; then
    report DOC003 "the reusable workflow is quoted at $commits different commits; there is one \
pin or there is none"
  elif [ "$named" != "$total" ]; then
    report DOC003 "$((total - named)) reference(s) do not name the release they pin; forty hex \
characters are not a version"
  else
    pass DOC003 "the reusable workflow is pinned to one commit, named by its release"
  fi
fi

exit $fail
