# Error codes

Every error response is an RFC 9457 `application/problem+json` document. The `code` member is the
part to switch on: `status` is too coarse to act on, and `detail` is prose that will be reworded.

```json
{
  "type": "https://github.com/prokopto-dev/nparse-plugin-regserve/blob/main/docs/api/errors.md#forbidden",
  "title": "Forbidden",
  "status": 403,
  "code": "forbidden",
  "detail": "you are not an owner of merchant-mode"
}
```

The enum is **closed**. Adding a code is a spec change and needs an entry on this page — gate
`DOC001` fails the build otherwise. Renaming or removing one breaks every client that handled it.

There is never a `200` carrying an error body. If the status says success, it succeeded.

---

## not_found

**404.** The resource does not exist, or is not visible to you.

A delisted plugin and a plugin that never existed return the same thing, deliberately: the
difference is not a client's business, and distinguishing them lets someone enumerate ids. A
malformed plugin id also lands here rather than on `invalid_request`, for the same reason — it
cannot name a real plugin, and reporting *why* it was rejected invites probing.

## invalid_request

**400.** The request was understood and is wrong: a missing field, a version that is not greater
than the current `latest`, a URL that is not `https`, a sha256 that is not 64 lowercase hex.

The `detail` names the specific problem. Fix and resend — retrying unchanged will not help.

## unauthorized

**401.** No credential, or a credential that is not valid.

Send `Authorization: Bearer nprs_pat_…`. **A token in a query string is rejected, with no
exception** — query strings land in access logs, proxy logs and browser history, and a leaked token
there is leaked to everyone who can read any of them.

## forbidden

**403.** The credential is valid and is not allowed to do this.

The usual causes: you are not an owner of the plugin, the token's scope does not cover the
operation, or the token is pinned to a different plugin. Also returned when a token attempts a
**capability-floor** operation — minting tokens, changing owners, setting trust — which are
session-only and carry no scope at all. There is no `admin:*` scope and no token that can grant
itself one.

## github_identity_required

**403.** Your account is authenticated but has no linked GitHub identity, and publishing requires
one.

This is separate from `forbidden` because the fix is completely different: you are not missing a
permission, you are missing an identity, and the `detail` names the endpoint that links one. Discord
and Google accounts can log in and browse; artifacts live on GitHub and ownership is checked against
it, so publishing needs a GitHub identity. See
[ADR-0004](../adr/0004-github-required-to-publish.md).

## conflict

**409.** The request collides with existing state.

Most often: the plugin id is already claimed — ids are first-come, permanent, and **never
recycled**, so a delisted plugin's id is still its owner's — or a release with that version already
exists for this plugin.

An `Idempotency-Key` replayed with a *different* body is also a conflict. The same key with the same
body returns the original result, which is the point of sending one.

## method_not_allowed

**405.** The path exists; the method does not. The `Allow` header lists what does.

## internal_error

**500.** A bug on our side. The response carries no detail worth acting on; the `X-Request-Id`
header is what to quote in a report.

One case worth naming: if a stored listing cannot be rendered into a valid index document, that is a
`500` rather than a partial index. Serving a document the client's parser would reject makes *every*
plugin disappear from the browser, so failing loudly for one request is the smaller harm.

## service_unavailable

**503.** The service is up but cannot serve this request yet — usually the database is unreachable
or a migration has not completed.

`/readyz` returns this with a `detail` naming the reason. `/healthz` deliberately does **not**: a
registry whose disk is briefly unavailable should not be restart-looped by an orchestrator when it
would recover on its own.
