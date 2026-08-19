#!/usr/bin/env bash
# Freeze the migrations a release ships, and refuse a release that would ship an unfrozen one.
#
# Gate MIG003 refuses to let a SHIPPED migration change, by sha256 against db/SHIPPED.lock. It can
# only do that for migrations somebody remembered to list — and nothing listed them. The lock file
# documented a one-liner to run on release day, which makes the rule's mechanism "somebody
# remembers", and by this repository's own governing rule that is a wish, not a gate (issue #14).
# The failure is silent and delayed: the lock stays empty, MIG003 reports `vacant` forever,
# everybody reads yellow as "not applicable yet", and a shipped migration gets edited months later
# with nothing objecting.
#
# So the freezing is a target and the remembering is a gate:
#
#   scripts/freeze-migrations.sh          append every migration not yet frozen  (make freeze-migrations)
#   scripts/freeze-migrations.sh --check  exit 1 if any migration is unfrozen    (gate MIG004)
#
# The order is deliberate: freeze, commit, THEN tag. Having the release workflow write the lock
# file instead would mean CI pushing to main, which is a larger hazard than the one being fixed —
# and it would freeze whatever happened to be on the branch rather than what a human released.
#
# Exit 0 = nothing to do. Exit 1 = a finding. Exit 2 = invoked wrongly.

set -uo pipefail
cd "$(dirname "$0")/.."

LOCK=db/SHIPPED.lock
DIR=db/migrations-sqlite

mode=write
case "${1:-}" in
  --check) mode=check ;;
  "")      ;;
  *)       echo "usage: $(basename "$0") [--check]" >&2; exit 2 ;;
esac

[ -f "$LOCK" ] || { echo "$LOCK is missing; it is where shipped migrations are frozen" >&2; exit 2; }

shopt -s nullglob
migrations=("$DIR"/*.sql)
shopt -u nullglob

if [ ${#migrations[@]} -eq 0 ]; then
  echo "no migrations in $DIR; nothing to freeze"
  exit 0
fi

# Paths the lock already names. Comments and blank lines are not entries; `shasum` writes
# "<sha256>  <path>", so the path is the second field.
listed() { grep -vE '^[[:space:]]*(#|$)' "$LOCK" | awk '{print $2}'; }

unfrozen=()
for f in "${migrations[@]}"; do
  listed | grep -qxF "$f" || unfrozen+=("$f")
done

if [ ${#unfrozen[@]} -eq 0 ]; then
  echo "all ${#migrations[@]} migration(s) are frozen in $LOCK"
  exit 0
fi

if [ "$mode" = check ]; then
  echo "MIG004: this release would ship a migration that is not frozen in $LOCK:" >&2
  printf '  %s\n' "${unfrozen[@]}" >&2
  echo >&2
  echo "Freeze them, commit the result, then tag:" >&2
  echo "    make freeze-migrations && git add $LOCK && git commit -s -m 'chore(db): freeze shipped migrations'" >&2
  exit 1
fi

# Append, never rewrite. A file already listed is left exactly as it is: if its hash no longer
# matches, that is MIG003's finding to report, and re-freezing it here would erase the evidence of
# precisely the edit both gates exist to catch.
for f in "${unfrozen[@]}"; do
  shasum -a 256 "$f" >> "$LOCK"
  echo "froze $f"
done
echo "${#unfrozen[@]} migration(s) added to $LOCK; commit it before tagging"
