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
#   scripts/freeze-migrations.sh --check  validate the lock, then exit 1 if any
#                                         migration is unfrozen        (gates MIG003 and MIG004)
#
# --check enforces BOTH halves, and it has to. Coverage alone — "every migration appears in the
# lock" — passes a tag that edited a migration already listed there, which is the exact invariant
# the lock exists to protect. It cannot be left to MIG003 in the normal gate run either, because
# ci.yml triggers on pull_request, merge_group and pushes to main, and NOT on tags: on the one
# event that makes a migration shipped, this script is the only thing that runs.
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

# Paths the lock already names. Comments and blank lines are not entries; `shasum` writes
# "<sha256>  <path>", so the path is the second field.
listed() { grep -vE '^[[:space:]]*(#|$)' "$LOCK" | awk '{print $2}'; }

# --- MIG003 — every entry the lock names still hashes to what it recorded ----------------------
# This runs FIRST, and it runs in both modes. A lock that no longer describes the files it names is
# not a lock, and everything below it — "is this one covered", "append the missing ones" — is built
# on the assumption that it does. Answering the coverage question over a lock whose contents have
# been edited is how a tag that rewrote a shipped migration gets waved through with a green tick.
#
# In write mode this refuses rather than appending: `make freeze-migrations` reporting "all frozen"
# while a shipped migration has been edited underneath it is precisely the reassuring lie both
# gates exist to prevent.
changed=()
missing=()
while read -r want file || [ -n "${want:-}" ]; do
  case "${want:-}" in ''|'#'*) continue ;; esac
  [ -z "${file:-}" ] && continue
  if [ ! -f "$file" ]; then
    missing+=("$file")
    continue
  fi
  got=$(shasum -a 256 "$file" | awk '{print $1}')
  [ "$got" = "$want" ] || changed+=("$file")
done < "$LOCK"

if [ ${#changed[@]} -gt 0 ] || [ ${#missing[@]} -gt 0 ]; then
  echo "MIG003: $LOCK no longer describes the migrations it names." >&2
  [ ${#changed[@]} -gt 0 ] && printf '  edited since it shipped: %s\n' "${changed[@]}" >&2
  [ ${#missing[@]} -gt 0 ] && printf '  listed but missing:      %s\n' "${missing[@]}" >&2
  echo >&2
  echo "A shipped migration has already run against the only copy of the production data. Editing" >&2
  echo "it changes what a FRESH database gets and nothing about the one in production, and there" >&2
  echo "is no down path that would notice. Restore the file and write a NEW migration instead." >&2
  exit 1
fi

# Only now is an empty directory harmless. Checked earlier it would exit 0 over a lock naming
# files that have all been DELETED, which is a shipped migration disappearing — the same invariant
# failing, in the one shape the coverage scan below can never see.
if [ ${#migrations[@]} -eq 0 ]; then
  echo "no migrations in $DIR; nothing to freeze"
  exit 0
fi

unfrozen=()
for f in "${migrations[@]}"; do
  listed | grep -qxF "$f" || unfrozen+=("$f")
done

if [ ${#unfrozen[@]} -eq 0 ]; then
  echo "all ${#migrations[@]} migration(s) are frozen in $LOCK and match their recorded hash"
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

# Append, never rewrite. Anything already listed was validated above, so this only ever adds lines.
for f in "${unfrozen[@]}"; do
  shasum -a 256 "$f" >> "$LOCK"
  echo "froze $f"
done
echo "${#unfrozen[@]} migration(s) added to $LOCK; commit it before tagging"
