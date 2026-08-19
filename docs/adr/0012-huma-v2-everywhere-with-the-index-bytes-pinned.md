# ADR-0012 — Huma v2 everywhere, with the index bytes pinned outside it

**Status:** accepted · **Date:** 2026-08-18 · **Deciders:** Courtney Caldwell

## Context and problem statement

`docs/design/00-canonical-conventions.md` §6 and AGENTS.md law 6 were written around Huma v2:
handlers return Huma error types, every operation sets an `OperationID`, and each declares
`Security` and `x-regserve-permission` with **coverage derived from the route registry**. None of
that existed — `internal/api` was `http.ServeMux` and hand-written handlers — so law 6 was a
convention nothing could satisfy (issue #1).

That is affordable while the only routes are the index endpoints and the health probes. It is not
affordable in Phase 2, where the permission-coverage test is the mechanism the whole authz story
rests on: without a registry to derive from, "every operation declares a permission" is a promise
kept by whoever remembers.

The complication is that one of those routes is `GET /index.json`, whose shape is owned by pydantic
models in released desktop clients we cannot patch. Putting it behind a framework's serializer puts
the one contract this project cannot change under someone else's defaults.

## Considered options

| Option | For | Against |
|---|---|---|
| A — Huma under `/api/v1` only; index and health stay hand-written | The pinned document never meets a framework | Two HTTP idioms in one package forever, and the coverage gate can only see half the routes — so a route added to the wrong half is invisible to it |
| B — Huma everywhere, default configuration | Idiomatic, one way to add a route | `huma.DefaultConfig` adds a `$schema` member to response bodies and negotiates format against a package-level map any import can add CBOR to. Both change the document a released client parses |
| C — Huma everywhere, hand-built config, index body as raw bytes | One idiom, one registry, and the index document never reaches a marshaller | The `[]byte` body is unusual, so it needs the comment and the gate that explain why |
| D — Amend the conventions to describe hand-written handlers | No dependency | Law 6's coverage cannot be derived from anything, so it becomes a review rule — the thing AGENTS.md calls a wish |

## Decision outcome

**Chosen: C.** Huma v2 (MIT, approved as a dependency) registers every route, including the index
endpoints. The configuration is built by hand rather than from `huma.DefaultConfig`: JSON is the
only registered format, no transformers are installed, and `/openapi.json`, `/docs` and `/schemas`
are not served. The index operations return `Body []byte` — bytes produced by
`registry.Index.Marshal`, which Huma writes verbatim without negotiating, transforming or
re-marshalling them.

`internal/registry` stays the only package that knows the format (SCHEMA002). Huma never learns it:
the OpenAPI document describes the index response as an opaque object and points at the upstream
schema URI rather than restating a shape this repository is not allowed to define twice.

**SCHEMA001 moved with it.** It used to validate `registry.NewIndex()`'s return value; it now reads
the bytes off a real HTTP response, through the whole stack, and validates those. That is the
difference between a gate that catches a renderer regression and one that catches a *serving*
regression — and the counterfactual was measured, not assumed. With a typed body, Huma's JSON
encoder (which disables HTML escaping and appends a newline) serves `">=1.0,<2"` where the bytes
this server sends today carry `"\u003e=1.0,\u003c2"`, and a request sending
`Accept: application/cbor` is answered in CBOR the moment any import registers that format.

### Consequences

- Good, because the OpenAPI document is generated from the same registration code that serves
  traffic, so it cannot describe a route that is not served or miss one that is.
- Good, because law 6 has a mechanism: `PERM001` walks the generated document, so an operation with
  no declared access is a red test rather than a missing one.
- Good, because the index endpoints are now *structurally* immune to content negotiation rather
  than configured to be — a raw-bytes body never consults `Accept`.
- **Bad, because the index endpoints are an exception inside the framework**, and an exception is
  something a later contributor "tidies up". The mitigation is a comment that names the failure and
  a gate that fails when the tidying happens, which is a mitigation and not a guarantee.
- **Bad, because a dependency now sits on the request path of the one contract we cannot change.**
  A Huma upgrade can alter defaults; the tests assert outcomes over real responses rather than
  configuration, so an upgrade that changes behaviour fails CI rather than production.
- **Bad, because `github.com/fxamacker/cbor/v2` is now in `go.sum`** — it is in Huma's module
  graph. Nothing imports it, and `TestNegotiation_*` fails if anything ever makes it reachable.

### Reversal cost

Low for the framework, high for the paths. Removing Huma means rewriting four handlers and deleting
the generated document; nothing persists it and no client depends on it yet. The index paths and
their bytes are unchanged by this decision and stay unchanged if it is reversed — that is the point
of the raw-bytes body.
