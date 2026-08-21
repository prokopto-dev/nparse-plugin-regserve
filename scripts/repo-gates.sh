#!/usr/bin/env bash
# Repository gates. Each is a rule from docs/concepts/invariants.md with a mechanism behind it.
#
# A gate that cannot fire yet says so and exits 0 — it does NOT print a green tick it has not
# earned. A gate reporting success over an empty search space is how a rule quietly stops being
# enforced the moment the code it guards is written.
#
# Exit 1 = a finding. Exit 2 = the gate was invoked wrongly.

set -uo pipefail
cd "$(dirname "$0")/.."

fail=0
report() { printf '\033[31m%s\033[0m  %s\n' "$1" "$2"; fail=1; }
pass()   { printf '\033[32m%-10s\033[0m %s\n' "$1" "$2"; }
vacant() { printf '\033[33m%-10s\033[0m %s\n' "$1" "$2 (no code to check yet)"; }

go_files() { find ./cmd ./internal -name '*.go' -not -name '*_test.go' 2>/dev/null; }
has_go()   { [ -n "$(go_files)" ]; }

# --- PIN001 — GitHub Actions pinned to a 40-character SHA -------------------------------------
# Checks the SHAPE of a pin, not that the digest matches its trailing comment. A bare tag is the
# failure this catches; a lying comment is a review problem.
if compgen -G ".github/workflows/*.yml" >/dev/null; then
  bad=$(grep -hoE '^\s*-?\s*uses:\s*[^ ]+' .github/workflows/*.yml \
        | grep -vE '@[0-9a-f]{40}' | grep -vE 'uses:\s*\./' || true)
  if [ -n "$bad" ]; then report PIN001 "action not pinned to a 40-char SHA:"; echo "$bad"; \
  else pass PIN001 "every action is pinned to a 40-character SHA"; fi
else
  vacant PIN001 "workflows pinned to SHAs"
fi

# --- ACT001 / ACT002 — the GitHub Actions gates ------------------------------------------------
# The logic lives in scripts/act-gates.sh, which takes a DIRECTORY, so that test/repo/act_test.go
# can point it at deliberately broken fixtures and require it to fire. That is not tidiness: the
# first version of ACT001 inspected only `run: |` and reported green over a workflow that could
# have said `run: echo "${{ github.ref_name }}"` -- a caller's tag name substituted into a script
# before bash sees it, which is the one line the gate exists for.
#
# ACT001: an expression inside a shell script. GitHub substitutes the VALUE into the script text,
# so it is EXECUTED rather than read. The fix is always `env:` plus "$VAR", so the gate has no
# exceptions -- an exception list is a thing somebody appends to at 2am.
#
# ACT002: `bash -n` over every extracted script. Workflow shell is not compiled, not linted and not
# executed until a tag is pushed, so a broken script ships.
if compgen -G ".github/workflows/*.yml" >/dev/null; then
  if out=$(bash scripts/act-gates.sh expressions .github/workflows 2>&1); then
    pass ACT001 "no workflow interpolates an expression into a shell script"
  else
    report ACT001 "${out%%$'\n'*}"
    printf '%s\n' "${out#*$'\n'}"
  fi

  if out=$(bash scripts/act-gates.sh syntax .github/workflows 2>&1); then
    pass ACT002 "$out workflow shell script(s) parse"
  else
    report ACT002 "${out%%$'\n'*}"
    printf '%s\n' "${out#*$'\n'}"
  fi
else
  vacant ACT001 "workflows keep expressions out of shell scripts"
  vacant ACT002 "workflow shell scripts parse"
fi

# --- Go architectural gates live in test/repo/arch_test.go -------------------------------------
# CLOCK001, SQL001, NET001, ROUTE001 and SCHEMA002 parse the tree with go/ast rather than grepping
# it. Two failures drove that: a grep matches the rule's own name inside the comment explaining the
# rule, and a grep for `time.Now` misses `clk "time"` followed by `clk.Now()`. A gate with false
# positives gets disabled; one with false negatives is worse, because it is trusted.
#
# They run under `make test`, which `make check` runs. This script keeps the gates that inspect
# files Go cannot parse.
printf '\033[36m%-10s\033[0m %s\n' "go gates" "CLOCK001 SQL001 NET001 ROUTE001 SCHEMA002 -> test/repo/arch_test.go (run by \`make test\`)"

# --- MIG002 — migrations are forward-only -----------------------------------------------------
if compgen -G "db/migrations-sqlite/*.sql" >/dev/null; then
  for f in db/migrations-sqlite/*.sql; do
    grep -q -- '-- +goose Down' "$f" || continue
    awk '/-- \+goose Down/{d=1} d && /RAISE\(ABORT/{found=1} END{exit !found}' "$f" \
      || report MIG002 "Down block is not RAISE(ABORT, ...): $f"
  done
  [ $fail -eq 0 ] && pass MIG002 "every Down block aborts; migrations are forward-only"
else
  vacant MIG002 "migrations are forward-only"
fi

# --- MIG005 — a rebuild recreates the triggers it destroyed ------------------------------------
# SQLite cannot add a CHECK constraint in place, so Atlas rebuilds the table: create new, copy
# rows, DROP TABLE old, rename. SQLite drops a table's triggers WITH the table, and Atlas does not
# model triggers at all (db/schema.hcl says why), so the generated migration silently removes them.
#
# This happened. Adding release.notes with its size CHECK dropped `release_no_delete`, and release
# history — which ADR-0010 says the database keeps even though only `latest` ships — became
# deletable with nothing anywhere saying so. TestSchema_RefusedStatements caught it after the fact;
# this catches it before the push.
#
# The check: for every migration that DROPs a table, every trigger this repository has ever created
# on that table must be created again in the SAME migration.
if compgen -G "db/migrations-sqlite/*.sql" >/dev/null; then
  # Which triggers belong to which table, over the whole history.
  triggers=$(grep -hoE 'CREATE TRIGGER "[a-z_]+" (BEFORE|AFTER) [A-Z ]+ ON "[a-z_]+"' \
             db/migrations-sqlite/*.sql \
             | sed -E 's/CREATE TRIGGER "([a-z_]+)" .* ON "([a-z_]+)"/\2 \1/' | sort -u)

  if [ -z "$triggers" ]; then
    vacant MIG005 "a table rebuild recreates its triggers"
  else
    missing=""
    for f in db/migrations-sqlite/*.sql; do
      up=$(awk '/-- \+goose Down/{exit} {print}' "$f")
      dropped=$(printf '%s' "$up" | grep -oE 'DROP TABLE "[a-z_]+"' \
                | sed -E 's/DROP TABLE "([a-z_]+)"/\1/' | sort -u)
      [ -n "$dropped" ] || continue

      for table in $dropped; do
        # Only triggers that existed BEFORE this migration matter; one created in this same file is
        # the recreation itself.
        for name in $(printf '%s\n' "$triggers" | awk -v t="$table" '$1 == t {print $2}'); do
          printf '%s' "$up" | grep -q "CREATE TRIGGER \"$name\"" \
            || missing="$missing  $(basename "$f"): drops \"$table\" without recreating trigger \"$name\"\n"
        done
      done
    done

    if [ -n "$missing" ]; then
      report MIG005 "a table rebuild silently dropped a trigger:"
      printf "%b" "$missing"
      printf '  Recreate it by hand below the marked boundary in the migration. Atlas does not\n'
      printf '  model triggers, so it will never write this for you.\n'
    else
      pass MIG005 "every table rebuild recreates the triggers it dropped"
    fi
  fi
else
  vacant MIG005 "a table rebuild recreates its triggers"
fi

# --- MIG003 — a shipped migration is never edited ---------------------------------------------
# A migration that has shipped in a tagged release has already run on the only copy of the
# ownership records. Editing it changes what a FRESH database gets and nothing about the one in
# production, so the two diverge silently — and forward-only means there is no down path to notice.
#
# The lock file is empty until the first release is tagged, and an empty lock is reported VACANT
# rather than passed: a green tick for a check that compared nothing is exactly the tick people
# learn to trust and stop reading.
if [ -f db/SHIPPED.lock ] && compgen -G "db/migrations-sqlite/*.sql" >/dev/null; then
  checked=0
  while read -r want file; do
    case "${want:-}" in ''|'#'*) continue ;; esac
    [ -z "${file:-}" ] && continue
    checked=$((checked + 1))
    [ -f "$file" ] || { report MIG003 "shipped migration is missing: $file"; continue; }
    got=$(shasum -a 256 "$file" | awk '{print $1}')
    [ "$got" = "$want" ] || report MIG003 "shipped migration changed: $file"
  done < db/SHIPPED.lock
  if [ "$checked" -eq 0 ]; then
    vacant MIG003 "shipped migrations frozen by db/SHIPPED.lock"
  elif [ $fail -eq 0 ]; then
    pass MIG003 "$checked shipped migration(s) match db/SHIPPED.lock"
  fi
else
  vacant MIG003 "shipped migrations frozen by db/SHIPPED.lock"
fi

# --- MIG004 — a tagged release never ships an unfrozen migration -------------------------------
# MIG003 freezes what the lock file LISTS. This is the gate that makes sure everything is listed,
# at the one moment it matters: the commit a `v*` tag points at. Without it the lock stays empty,
# MIG003 reports `vacant` through the first release and every one after it, and the freeze nobody
# performed is indistinguishable from a freeze that had nothing to do (issue #14).
#
# Off a release commit this reports vacant rather than a tick it has not earned — a migration is
# legitimately editable right up until the tag that ships it. The release workflow runs the same
# check directly, because a shallow CI checkout may carry no tags for `git tag` to find.
if compgen -G "db/migrations-sqlite/*.sql" >/dev/null; then
  release_tag=$(git tag --points-at HEAD 2>/dev/null | grep -E '^v' | head -1)
  if [ -n "${release_tag:-}" ]; then
    if out=$(bash scripts/freeze-migrations.sh --check 2>&1); then
      pass MIG004 "every migration is frozen in db/SHIPPED.lock for $release_tag"
    else
      report MIG004 "$release_tag is not safe to ship; see the finding below"
      printf '%s\n' "$out"
    fi
  else
    vacant MIG004 "migrations frozen in db/SHIPPED.lock before a tagged release"
  fi
else
  vacant MIG004 "migrations frozen in db/SHIPPED.lock before a tagged release"
fi

exit $fail
