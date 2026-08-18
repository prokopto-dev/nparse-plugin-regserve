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

exit $fail
