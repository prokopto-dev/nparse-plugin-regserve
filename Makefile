# nparse-plugin-regserve — build and verification targets.
#
# Targets that cannot do real work yet call `notyet` with the roadmap phase that fills them in, and
# exit 0 so `make check` and CI stay green through Phase 0. `make status` derives the list of what is
# still stubbed straight from those call sites — there is no hand-maintained progress list, and
# adding one would be a second place to forget.
#
# A target that CAN do real work must do it unconditionally. A guard that skips the work when its
# inputs are missing turns into a guard that hides a broken toolchain the moment the inputs exist,
# and a green `make check` that ran nothing is worse than a red one.

SHELL := /bin/bash
.DEFAULT_GOAL := help

GO        ?= go
PKG       := ./...
BIN       := regserve
BUILD_DIR := ./bin

# The local database `make migrate` and `make seed` act on. Never a path inside the container: the
# production database lives on a volume and is migrated by the server at boot, not from a laptop.
DB        ?= ./regserve.db

# The generators, pinned. ONE source of truth: `make tools` installs exactly these and CI runs
# `make tools`, so the version that produced the checked-in code and the version CI regenerates
# with cannot drift apart (gate GEN001, issue #12). Bumping either is a deliberate change whose
# diff is the regenerated output.
SQLC_VERSION  ?= v1.31.1
ATLAS_VERSION ?= v1.3.0

# notyet <phase> <what> — a target that is declared but not yet implemented.
# No leading '@': call sites add it, so this also works inside shell if/else blocks.
#
# NO COMMAS IN <what>. Make splits $(call ...) arguments on commas, so a comma silently truncates
# the message at the point it appears and hands the remainder to an argument nothing reads.
define notyet
printf '\033[33m  not yet implemented\033[0m  %s\n  lands in: %s\n' "$(2)" "$(1)"
endef

# require <tool> <why> — fail with something actionable instead of "command not found".
#
# Deliberately NOT a `notyet` and deliberately not a skip: these targets do real work, and a target
# that silently does nothing when its tool is missing is a target that reports success for a
# regeneration that never happened.
#
# NO COMMAS IN <why>, for the reason given above.
define require
command -v $(1) >/dev/null 2>&1 || { printf '\033[31mmissing tool\033[0m  %s\n  %s\n' "$(1)" "$(2)"; exit 1; }
endef

## help: list every documented target
.PHONY: help
help:
	@printf 'nparse-plugin-regserve — pre-1.0, scaffolding phase. Run `make status` for what is implemented.\n\n'
	@grep -hE '^## ' $(MAKEFILE_LIST) | sed 's/^## //' | awk -F': ' '{printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

## status: what is still stubbed, derived from notyet call sites
.PHONY: status
status:
	@printf 'Implemented targets run real work. The following are declared and stubbed:\n\n'
	@grep -nE '^\t@?\$$\(call notyet,' $(MAKEFILE_LIST) \
	  | sed -E 's/^([0-9]+):\t@?\$$\(call notyet,([^,]+),(.*)\)$$/  \2\t\3/' \
	  | sort | awk -F'\t' '{printf "  \033[33m%-10s\033[0m %s\n", $$1, $$2}'
	@printf '\nSee ROADMAP.md for what each phase contains.\n'

## setup-check: report which developer tools are missing, and why each is needed
.PHONY: setup-check
setup-check:
	@printf 'go              %s\n' "$$($(GO) version 2>/dev/null || echo 'MISSING — required')"
	@printf 'golangci-lint   %s\n' "$$(command -v golangci-lint >/dev/null 2>&1 && golangci-lint --version 2>/dev/null | head -1 || echo 'missing — CI runs it; local runs are skipped')"
	@printf 'gofumpt         %s\n' "$$(command -v gofumpt >/dev/null 2>&1 && echo present || echo 'missing — the pre-commit hook falls back to gofmt')"
	@printf 'lefthook        %s\n' "$$(command -v lefthook >/dev/null 2>&1 && echo present || echo 'missing — or use: git config core.hooksPath .githooks')"
	@# BuildKit is called out separately because the failure is silent: the legacy builder cannot
	@# parse $$BUILDPLATFORM or cache mounts, and it exits 0 while having built nothing.
	@printf 'docker buildx   %s\n' "$$(docker buildx version >/dev/null 2>&1 && docker buildx version 2>/dev/null | head -1 || echo 'MISSING — deploy/Dockerfile needs BuildKit; the legacy builder FAILS WHILE EXITING 0')"

## build: compile the binary
.PHONY: build
build:
	@mkdir -p $(BUILD_DIR)
	$(GO) build -trimpath -o $(BUILD_DIR)/$(BIN) ./cmd/$(BIN)

## fmt: format Go sources
.PHONY: fmt
fmt:
	$(GO) fmt $(PKG)

## vet: go vet over every package
.PHONY: vet
vet:
	$(GO) vet $(PKG)

## lint: run every linter in check mode
.PHONY: lint
lint: lint-repo lint-go

## lint-go: golangci-lint
# NOT a `notyet`: this target does real work the moment the tool is present, and CI always has it.
# A missing local binary is a missing local binary, not an unimplemented feature — conflating the
# two would put a permanent row in `make status` that never goes away and teach people to skim it.
.PHONY: lint-go
lint-go:
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint config verify && golangci-lint run; \
	 else printf '\033[33m  skipped\033[0m  golangci-lint is not on PATH; CI runs it (see .golangci.yml)\n'; fi

## lint-repo: file-shape gates (PIN001, MIG002, MIG003, MIG004); the Go gates run under `make test`
.PHONY: lint-repo
lint-repo:
	@bash scripts/repo-gates.sh

## docs-check: ADR shape and gate registration (ADR000-003, DOC001, DOC002)
.PHONY: docs-check
docs-check:
	@bash scripts/docs-check.sh

## verify-commands: every command named in AGENTS.md resolves to a real target
.PHONY: verify-commands
verify-commands:
	@bash scripts/verify-commands.sh

## test: run the test suite
.PHONY: test
test:
	$(GO) test -race -shuffle=on -count=1 $(PKG)

## gen: regenerate the permission catalogue, OpenAPI document and sqlc bindings
.PHONY: gen
gen: gen-openapi gen-authz
	@$(call require,sqlc,db/queries is typed into internal/store/sqlitegen by it — install it with: make tools)
	sqlc generate

## gen-openapi: regenerate openapi/openapi.json from the route registry
#
# Needs only the Go toolchain, unlike the rest of `make gen`, because the document is generated by
# the binary itself: the same registration code the server runs, so the spec cannot describe a
# route that is not served. Gate GEN001 runs this and fails on any diff.
.PHONY: gen-openapi
gen-openapi:
	@mkdir -p openapi
	$(GO) run ./cmd/$(BIN) openapi --out openapi/openapi.json

## gen-authz: regenerate docs/reference/permissions.md from the authz catalogue
#
# Needs only the Go toolchain, like gen-openapi and for the same reason: the page is rendered by
# the binary from the catalogue in internal/authz, with the "declared by" column taken from the
# route registry. Canonical §5 forbids a hand-written permission list anywhere, and gate GEN001
# regenerates this to fail on one.
.PHONY: gen-authz
gen-authz:
	@mkdir -p docs/reference
	$(GO) run ./cmd/$(BIN) authz --docs docs/reference/permissions.md --schema db/schema.hcl

## migration: author a migration from db/schema.hcl with Atlas (NAME=<snake_case>)
.PHONY: migration
migration: gen-authz
	@$(call require,atlas,db/schema.hcl is diffed into a migration by it — install it with: make tools)
	@[ -n "$(NAME)" ] || { printf 'NAME is required: make migration NAME=add_something\n'; exit 2; }
	atlas migrate diff $(NAME) --dir "file://db/migrations-sqlite" --dir-format goose \
	  --dev-url "sqlite://dev?mode=memory" --to "file://db/schema.hcl"
	@# Atlas writes correct SQLite that is not OUR SQLite: backtick quoting sqlc cannot parse, and a
	@# Down block full of DROP statements. See the script for what each fixup prevents.
	bash scripts/finish-migration.sh
	atlas migrate hash --dir "file://db/migrations-sqlite"
	@$(MAKE) --no-print-directory gen

## migrate: apply pending migrations to a local database (DB=./regserve.db)
.PHONY: migrate
migrate:
	$(GO) run ./cmd/$(BIN) migrate --db $(DB)

## seed: import ownership records from owners.json (OWNERS=./owners.json DB=./regserve.db)
#
# The CATALOGUE is not seeded here: it is imported at boot from --seed, once, into an empty
# database. This is the other half — the ownership records the static registry kept as GitHub
# handles, resolved to the numeric ids that survive a rename.
#
# It reaches GitHub once per handle, which is why it is a command an operator runs rather than
# something boot depends on.
#
# It migrates the database itself rather than depending on `migrate`: store.Open creates a missing
# file and applies nothing, so a fresh $(DB) would otherwise fail with "no such table: plugin" —
# and telling somebody to run another command first is a step they will forget on the day it
# matters. The server migrates at boot for the same reason.
.PHONY: seed
seed:
	@[ -n "$(OWNERS)" ] || { printf 'OWNERS is required: make seed OWNERS=./owners.json\n'; exit 2; }
	$(GO) run ./cmd/$(BIN) seed-owners --owners $(OWNERS) --db $(DB)

## docker: build the container image
.PHONY: docker
docker:
	@$(call notyet,Phase 4,docker buildx build -f deploy/Dockerfile)

## tools: install the pinned code generators (sqlc, atlas), verifying what they are
#
# Into $(GOBIN), which actions/setup-go already puts on PATH, so this works identically on a laptop
# and on a runner. Pinned rather than "latest": a generator that changes under you rewrites checked-in
# code in a PR that touched none of it, and the reviewer has no way to tell that from real drift.
#
# The two are fetched differently because only one of them comes with integrity checking. `go
# install` resolves through the Go checksum database, so the module is verified against a
# transparency log this repository does not have to maintain. Atlas is a bare binary over HTTPS
# with no signature and no attestation, so its bytes are pinned by sha256 in scripts/atlas.sums and
# verified BEFORE it is made executable — see scripts/install-atlas.sh. GEN001 is a required check
# and it believes whatever Atlas tells it, so an unverified Atlas is an unverified gate.
.PHONY: tools
tools:
	$(GO) install github.com/sqlc-dev/sqlc/cmd/sqlc@$(SQLC_VERSION)
	@bash scripts/install-atlas.sh "$(ATLAS_VERSION)" "$$($(GO) env GOPATH)/bin"
	@printf 'installed sqlc %s\n' "$(SQLC_VERSION)"

## gen-check: fail if generated code or db/schema.hcl drifted from their source (GEN001)
#
# Not part of `make check`: it needs the generators on PATH, and `make check` must stay runnable on
# a toolchain-free machine. CI runs it as its own job (issue #12).
.PHONY: gen-check
gen-check:
	@$(call require,sqlc,GEN001 regenerates the bindings to compare them — install it with: make tools)
	@$(call require,atlas,GEN001 re-diffs db/schema.hcl to compare it — install it with: make tools)
	@bash scripts/gen-check.sh

## freeze-migrations: record the migrations a release ships in db/SHIPPED.lock (MIG004)
#
# Run this, commit the result, THEN tag. Gate MIG004 refuses to build a release image for a tag
# whose migrations are not in the lock file.
.PHONY: freeze-migrations
freeze-migrations:
	@bash scripts/freeze-migrations.sh

## check: everything CI runs
.PHONY: check
check: verify-commands docs-check lint vet build test

## clean: remove build output
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
