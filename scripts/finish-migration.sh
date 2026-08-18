#!/usr/bin/env bash
# Finish an Atlas-authored migration so it is something this project can ship.
#
# Atlas writes correct SQLite; it does not write OUR SQLite. Two edits are mechanical, and doing
# them by hand is how one eventually gets forgotten:
#
#   1. BACKTICK QUOTING. Atlas quotes every identifier with backticks. sqlc's SQLite parser does
#      not understand them and reports the table as not existing, which reads like a missing
#      migration rather than a quoting style. Double quotes are the SQL-standard form and both
#      tools accept them.
#
#   2. REDUNDANT `NULL` COLUMN CONSTRAINTS. Atlas spells a nullable column `text NULL`, which is
#      identical to `text` in SQLite -- but sqlc's SQLite parser stops resolving the type when it
#      meets the explicit keyword and falls back to `interface{}`. A generated struct full of
#      `interface{}` compiles, so nothing fails until somebody type-asserts one at runtime.
#
#   3. THE DOWN BLOCK. Atlas generates DROP statements. Migrations here are forward-only
#      (ADR-0006): a down path is code that runs exactly once, in an emergency, on data that
#      cannot be reproduced, written months earlier by somebody who never tested it. Recovery is
#      restoring the snapshot the deploy takes immediately before migrating. Gate MIG002 fails any
#      Down block that does not abort, so generating the compliant shape means the gate can only
#      ever be a confirmation.
#
# Idempotent: running it twice changes nothing. It rewrites every migration in the directory, not
# just the newest, so a file that predates this script is fixed the next time anything is authored.

set -euo pipefail
cd "$(dirname "$0")/.."

DIR=db/migrations-sqlite

if ! compgen -G "$DIR/*.sql" >/dev/null; then
  printf 'no migrations in %s; nothing to finish\n' "$DIR"
  exit 0
fi

for f in "$DIR"/*.sql; do
  python3 - "$f" <<'PY'
import re
import sys

path = sys.argv[1]
with open(path, encoding="utf-8") as fh:
    text = fh.read()

# 1. Backticks -> double quotes. DDL carries no string literals that could contain a backtick,
#    which is what makes a blanket replacement safe here and nowhere else.
text = text.replace("`", '"')

# 2. Drop the redundant NULL keyword. The regex requires a column TYPE immediately before it, so
#    `text NOT NULL` cannot match: after the type comes NOT, not NULL.
text = re.sub(r"\b(text|integer|real|blob|any)\s+NULL\b", r"\1", text, flags=re.IGNORECASE)

# 3. Replace everything from the Down marker onwards.
DOWN = """-- +goose Down
-- FORWARD-ONLY (ADR-0006). There is no down migration.
--
-- Recovery from a bad migration is restoring the snapshot the deploy takes immediately before it
-- runs: /opt/regserve/backups/pre-<timestamp>.db on the droplet. See docs/operations/deployment.md.
-- Rolling the image back is not enough on its own, because an older binary refuses a newer schema.
--
-- RAISE() is only legal inside a trigger body, so this statement cannot succeed by any route: it
-- fails to parse, goose rolls the transaction back, and the schema is untouched. The message is
-- here for the person reading the file, which is where they will be looking.
-- +goose StatementBegin
SELECT RAISE(ABORT, 'migrations are forward-only: restore the pre-migration snapshot from /opt/regserve/backups');
-- +goose StatementEnd
"""

marker = "-- +goose Down"
i = text.find(marker)
if i == -1:
    text = text.rstrip("\n") + "\n\n" + DOWN
else:
    text = text[:i] + DOWN

with open(path, "w", encoding="utf-8") as fh:
    fh.write(text)
PY
done

printf 'finished %s migration file(s) in %s\n' "$(ls "$DIR"/*.sql | wc -l | tr -d ' ')" "$DIR"
