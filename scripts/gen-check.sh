#!/usr/bin/env bash
# Gate GEN001 — checked-in generated code matches the source it is generated from.
#
# ADR-0006 names this drift class and then leaves it to CI, which was not checking it (issue #12):
#
#   > Bad, because generated code is checked in, so a stale `make gen` is a drift class CI has to
#   > catch rather than a thing that cannot happen.
#
# Two ways it drifts, and the second is the dangerous one:
#
#   - db/queries/*.sql edited without `make gen` — the bindings in internal/store/sqlitegen no
#     longer match the SQL they claim to be typed from. Or somebody hand-edits the bindings, which
#     the tests happily pass because the tests run the bindings, not the SQL.
#   - db/schema.hcl edited without `make migration` — schema.hcl is THE description of the
#     database, the file a reviewer reads to answer "what does this table look like", and it can
#     be wrong with every test green because nothing applies it. Migrations are what run.
#
# Regenerating and diffing is the only honest check: it compares against the generator, not against
# a rule about the generator.
#
# Exit 0 = no drift. Exit 1 = a finding. Exit 2 = the check could not be run.

set -uo pipefail
cd "$(dirname "$0")/.."

red()   { printf '\033[31m%s\033[0m  %s\n' "$1" "$2"; }
green() { printf '\033[32m%-10s\033[0m %s\n' "$1" "$2"; }

# A dirty tree makes every diff below meaningless: the check would report uncommitted work as
# generator drift and send somebody looking for a bug in sqlc. Refuse rather than mislead.
if [ -n "$(git status --porcelain)" ]; then
  red GEN001 "the working tree has uncommitted changes; commit or stash them first"
  git status --short
  exit 2
fi

restore() {
  # Safe precisely because the tree was asserted clean above.
  git checkout -- . >/dev/null 2>&1
  git clean -fdq db/migrations-sqlite >/dev/null 2>&1
}

drift() {
  red GEN001 "$1"
  echo
  git status --short
  echo
  echo "Regenerate and commit the result:"
  echo "    make gen           # the openapi document, the permissions page and the sqlc bindings"
  echo "    make gen-openapi   # the openapi document alone; needs no generator toolchain"
  echo "    make gen-authz     # the permissions page alone; needs no generator toolchain"
  echo "    make migration NAME=<snake_case>   # if db/schema.hcl changed"
  restore
  exit 1
}

# --- the OpenAPI document ----------------------------------------------------------------------
# openapi/openapi.json is generated from the route registry in internal/api. Hand-editing it is the
# drift that matters here: the document is the published contract — OperationIDs become SDK method
# names — so a spec that says something the server does not do is worse than no spec.
if ! go run ./cmd/regserve openapi --out openapi/openapi.json; then
  red GEN001 "generating the openapi document failed"
  restore
  exit 2
fi
[ -z "$(git status --porcelain)" ] || drift "openapi/openapi.json is stale or hand-edited: it does not match what internal/api registers"

# --- the permission catalogue's documentation --------------------------------------------------
# docs/reference/permissions.md is generated from internal/authz plus the route registry. Canonical
# §5 forbids a hand-written permission list ANYWHERE, and a docs page is exactly where one grows: a
# plugin author writing a CI job trusts the page, not the Go file.
if ! go run ./cmd/regserve authz --docs docs/reference/permissions.md; then
  red GEN001 "generating the permissions page failed"
  restore
  exit 2
fi
[ -z "$(git status --porcelain)" ] || drift "docs/reference/permissions.md is stale or hand-edited: it does not match the catalogue in internal/authz"

# --- the sqlc bindings ------------------------------------------------------------------------
if ! sqlc generate; then
  red GEN001 "sqlc generate failed"
  restore
  exit 2
fi
[ -z "$(git status --porcelain)" ] || drift "internal/store/sqlitegen is stale: db/queries has changed since the last \`make gen\`"

# --- the migration directory's own integrity ---------------------------------------------------
# atlas.sum is how a hand-edited migration is caught before it is ever applied.
if ! atlas migrate validate --dir "file://db/migrations-sqlite" --dir-format goose; then
  red GEN001 "db/migrations-sqlite does not validate against its atlas.sum; run: atlas migrate hash --dir file://db/migrations-sqlite"
  restore
  exit 1
fi

# --- db/schema.hcl against the migrations -------------------------------------------------------
# `migrate diff` writes a new migration when the two disagree and writes nothing when they agree,
# so "did it write anything" IS the check. The name is a marker: if this file ever survives, the
# failure message below is what says why.
if ! atlas migrate diff gen001_drift_probe \
      --dir "file://db/migrations-sqlite" --dir-format goose \
      --dev-url "sqlite://dev?mode=memory" --to "file://db/schema.hcl"; then
  red GEN001 "atlas migrate diff failed"
  restore
  exit 2
fi
[ -z "$(git status --porcelain)" ] || drift "db/schema.hcl describes a database no migration produces: it changed without \`make migration\`"

green GEN001 "generated code and migrations match their source"
