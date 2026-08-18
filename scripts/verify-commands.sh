#!/usr/bin/env bash
# Every `make <target>` named in AGENTS.md must resolve to a real Makefile target.
#
# The failure this prevents: AGENTS.md tells an agent to run `make check-all`, no such target
# exists, and the agent invents something plausible instead of stopping. Documentation that names a
# command is a promise the command exists.
#
# Only CODE is scanned — inline backtick spans and fenced blocks. Scanning prose matches sentences
# like "make it fail" and produces noise that gets the whole gate disabled.
#
# The reverse is NOT checked: the Makefile may have internal helpers AGENTS.md never mentions.

set -uo pipefail
cd "$(dirname "$0")/.."

DOCS=(AGENTS.md README.md CONTRIBUTING.md docs/design/00-canonical-conventions.md docs/operations/deployment.md)

fail=0
targets=$(grep -oE '^## [a-z][a-z0-9-]*:' Makefile | sed 's/^## //;s/:$//' | sort -u)

# Inline spans: `make build`
inline=$(grep -ohE '`make [a-z][a-z0-9-]*`' "${DOCS[@]}" 2>/dev/null | tr -d '`' | awk '{print $2}')

# Fenced blocks: a line whose first word is `make`, inside ``` ... ```
fenced=$(awk '/^```/{inblock=!inblock; next} inblock && /^[[:space:]]*make[[:space:]]+[a-z]/{print $2}' \
         "${DOCS[@]}" 2>/dev/null)

named=$(printf '%s\n%s\n' "$inline" "$fenced" | grep -E '^[a-z][a-z0-9-]*$' | sort -u)

if [ -z "$named" ]; then
  printf '\033[33m%-10s\033[0m %s\n' "CMD001" "no make targets named in the docs (nothing to check yet)"
  exit 0
fi

for t in $named; do
  if ! echo "$targets" | grep -qx "$t"; then
    printf '\033[31m%s\033[0m  %s\n' "CMD001" "docs name \`make $t\`, which is not a documented Makefile target"
    fail=1
  fi
done

[ $fail -eq 0 ] && printf '\033[32m%-10s\033[0m %s\n' "CMD001" \
  "every command named in the docs resolves to a real target ($(echo "$named" | wc -w | tr -d ' ') checked)"
exit $fail
