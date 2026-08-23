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

The enum also covers the errors the HTTP framework raises before a handler runs — a body it could
not parse, a parameter that failed validation, a media type it cannot produce. Those have no code
of their own: a closed enum does not grow a member per framework status, and to a client they are
all the same instruction. Every such 4xx is `invalid_request` and every 5xx is `internal_error`,
with the status itself preserved.

---

## not_found

**404.** The resource does not exist, or is not visible to you.

A delisted plugin and a plugin that never existed return the same thing, deliberately: the
difference is not a client's business, and distinguishing them lets someone enumerate ids. A
malformed plugin id also lands here rather than on `invalid_request`, for the same reason — it
cannot name a real plugin, and reporting *why* it was rejected invites probing.

**Publishing draws no distinction either, and this is the one to be careful about.** A publish
refused for want of a grant returns the *same* document whether the id is unclaimed or held by
somebody else. It must: if the two differed, the generic answer would then *prove* the id is
somebody’s, and anybody with an unpinned `plugin:publish` token could classify a wordlist. Ids
are permanent and never recycled, so that list is exactly what a squatter wants.

`POST /api/v1/plugins` is **not** an equivalent oracle for free ids, and it is worth saying why,
because the argument is tempting and wrong: that endpoint’s "not taken" answer is a `201` that
**claims the id, permanently**, with an audit row. Nobody probes a wordlist with a request that
takes ownership of every hit. The public directory publishes only the *count* of
claimed-but-unlisted ids, never which.

What the refusal **does** say is how claiming works on the instance answering it: that it is a
separate session-only step no token can perform, and where to do it — or, on an instance running
without sign-in, that ids cannot be claimed there at all and ownership comes from its operator.
That varies with the *deployment*, which every caller can see anyway, and never with the id in the
path. It is the same sentence for every plugin id, which is what makes it safe to say and still
enough to unblock an author whose pipeline is answered `404` on every tag.

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

**Currently unreachable, deliberately retained.** GitHub is the only identity provider
([ADR-0011](../adr/0011-github-is-the-only-identity-provider.md)), so every account is created by a
GitHub login and every account has the identity this code says is missing. The code stays in the
closed enum because the enum is public API — removing one breaks every client that handled it — and
because the condition returns the moment a second, non-publishing provider is added, which the
`can_publish` `CHECK` is still written to allow.

It is separate from `forbidden` because the fix would be completely different: you are not missing a
permission, you are missing an identity, and the `detail` would name the endpoint that links one.
Artifacts live on GitHub and ownership is checked against it, so publishing needs a GitHub identity.
See [ADR-0004](../adr/0004-github-required-to-publish.md).

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

The `detail` is a fixed sentence, deliberately. When a handler fails with something that is not
already a problem document, the framework offers the underlying error for inclusion — a driver
message, a file path, a query — and this endpoint is unauthenticated. The cause goes to the log,
where the person who can act on it is looking; the response says only which request it was.

One case worth naming: if a stored listing cannot be rendered into a valid index document, that is a
`500` rather than a partial index. Serving a document the client's parser would reject makes *every*
plugin disappear from the browser, so failing loudly for one request is the smaller harm.

## service_unavailable

**503.** The service is up but cannot serve this request yet — usually the database is unreachable
or a migration has not completed.

`/readyz` returns this with a `detail` naming the reason. `/healthz` deliberately does **not**: a
registry whose disk is briefly unavailable should not be restart-looped by an orchestrator when it
would recover on its own.
