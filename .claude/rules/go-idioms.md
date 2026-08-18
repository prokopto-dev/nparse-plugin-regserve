---
description: House Go conventions and the gates behind them
paths: ["**/*.go"]
---

# House Go

- **Errors** wrap with `%w` *and* context: `fmt.Errorf("rehash artifact %s: %w", id, err)`. Context
  is a lowercase noun phrase, no punctuation. Sentinels live in the owning package; compare with
  `errors.Is`/`errors.As`. `_ = f()` is a waiver needing a comment, not a default. No `panic`
  outside `main` wiring.
- **`ctx context.Context` is the first parameter** of anything doing I/O — including functions that
  "don't need it yet". Never store one in a struct. `context.Background()` only in `main` and
  `TestMain`.
- **The clock is injected.** `time.Now` outside `internal/clock` fails `CLOCK001`, an AST analyser,
  so aliasing the import does not help.
- **`crypto/rand`, never `math/rand`** — depguard-banned. Token secrets, OAuth `state` and PKCE
  verifiers have no non-cryptographic variant.
- **Logging is `slog`**, structured. Never log a token secret, a session id, an OAuth access token,
  a client secret, or the pepper. The 8-character public token prefix *is* loggable and is how a
  leaked token gets found.
- **Tests:** `TestThing_Condition_Expectation`, `t.Parallel()` everywhere, `t.Context()`,
  **`require` not `assert`** (depguard-banned — `assert` continues after failure and buries the
  first real failure). No database mocks; use real SQLite in `t.TempDir()`.
- **Banned:** naked returns, package-level mutable state, `any` in domain signatures, two types for
  one concept.

## Where code goes

`database/sql` only in `internal/store` (`SQL001`). Routes only in `internal/api` (`ROUTE001`).
Outbound HTTP only from `internal/identity/*` and `internal/artifact` (`NET001`) — plus
`cmd/regserve/healthcheck.go`, allowed by exact filename because it dials fixed loopback.

Adding a dependency is a human decision. `go.mod` and `go.sum` are edit-denied.
