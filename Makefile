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

# notyet <phase> <what> — a target that is declared but not yet implemented.
# No leading '@': call sites add it, so this also works inside shell if/else blocks.
#
# NO COMMAS IN <what>. Make splits $(call ...) arguments on commas, so a comma silently truncates
# the message at the point it appears and hands the remainder to an argument nothing reads.
define notyet
printf '\033[33m  not yet implemented\033[0m  %s\n  lands in: %s\n' "$(2)" "$(1)"
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

## lint-repo: file-shape gates (PIN001, MIG002, MIG003); the Go gates run under `make test`
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

## gen: regenerate the scope catalogue, OpenAPI document and sqlc bindings
.PHONY: gen
gen:
	@$(call notyet,Phase 1,regenerate the authz catalogue plus the OpenAPI document and sqlc bindings)

## migration: author a migration from db/schema.hcl with Atlas (NAME=<snake_case>)
.PHONY: migration
migration:
	@$(call notyet,Phase 1,atlas migrate diff against db/schema.hcl)

## migrate: apply pending migrations to a local database
.PHONY: migrate
migrate:
	@$(call notyet,Phase 1,goose up against the local database)

## seed: seed a local database with the current public catalogue
.PHONY: seed
seed:
	@$(call notyet,Phase 2,import the live index.json and owners.json as seed data)

## docker: build the container image
.PHONY: docker
docker:
	@$(call notyet,Phase 4,docker buildx build -f deploy/Dockerfile)

## check: everything CI runs
.PHONY: check
check: verify-commands docs-check lint vet build test

## clean: remove build output
.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
