# Permissions and scopes

**Generated from `internal/authz/catalogue.go` — do not edit.** Run `make gen` after changing the
catalogue; gate `GEN001` regenerates this page in CI and fails on any difference.

A **permission** narrows a role and is spelled `<resource>.<action>`. A **scope** narrows a token
and is spelled `<family>:<verb>`. They are deliberately different vocabularies at different
granularities, and effective capability is the intersection of the two — plus, for anything
touching a plugin, the account's ownership at the moment of the request
([ADR-0005](../adr/0005-pats-scoped-to-plugins.md)).

## The capability floor

Some operations carry **no scope at all** and are session-only, because a token that could perform
one would be equivalent to the account. There is no `admin:*` and no all-powerful token: a leaked
publish token cannot mint a second token, and that is the property that makes the containment
real.

A floor operation declares `x-regserve-pat-forbidden: true` in the OpenAPI document. That is a
different statement from an operation that simply has no scope yet, and the two are spelled
differently on purpose — an absence cannot be told from a refusal.

## Permissions

| Permission | Scopes that satisfy it | Declared by | What it allows |
|---|---|---|---|
| `plugin.read` | `plugin:read` | *nothing yet* | Read a plugin's registry state, including releases that are pending review and therefore absent from the public index. |
| `plugin.publish` | `plugin:publish` | `POST /api/v1/plugins/{id}/releases` | Submit a release of a plugin. A new plugin id always goes to human review; a version bump of an approved plugin may publish automatically. |
| `plugin.manage` | `plugin:manage` | *nothing yet* | Change a listing's name, description, author or homepage, and delist it. Delisting keeps the id claimed — ids are never recycled. |
| `token.mint` | **none — capability floor** | `POST /account/tokens` | Mint a personal access token. |
| `token.read` | **none — capability floor** | `GET /account` | List the account's personal access tokens. Secrets are shown once at mint time and never again — this lists prefixes, scopes and dates. |
| `token.revoke` | **none — capability floor** | `POST /account/tokens/{id}/revoke` | Revoke a personal access token. |
| `plugin.claim` | **none — capability floor** | `POST /api/v1/plugins` | Register a new plugin id. Ids are first-come, permanent and never recycled, and the first release of a new id always goes to human review. |
| `owner.manage` | **none — capability floor** | `GET /plugins/{id}/settings`<br>`POST /plugins/{id}/owners` | Add, remove or transfer a plugin's owners. |
| `trust.set` | **none — capability floor** | `PUT /api/v1/accounts/{id}/trust` | Set an account's trust level. |
| `release.review` | **none — capability floor** | `GET /api/v1/releases/pending`<br>`GET /review`<br>`GET /review/releases/{id}`<br>`POST /api/v1/releases/{id}/approve`<br>`POST /api/v1/releases/{id}/reject`<br>`POST /api/v1/releases/{id}/reverify`<br>`POST /review/releases/{id}/decide` | Approve or reject a release that is waiting for review. |
| `session.end` | **none — capability floor** | `POST /auth/logout` | End the browser session it is called with. |

## Scopes

Every scope a personal access token may carry. A mint request naming anything else is rejected
rather than stored: a token whose scope matches no permission would look narrow on the account
page and be exactly as powerless in practice.

| Scope | Grants |
|---|---|
| `plugin:read` | `plugin.read` |
| `plugin:publish` | `plugin.publish` |
| `plugin:manage` | `plugin.manage` |

## Operations that declare no permission

Public ones. They declare `x-regserve-public: true` and an explicitly empty `security` list, so
"anyone may call this" is a decision somebody wrote down rather than the absence of one.

- `GET /`
- `GET /auth/{provider}/callback`
- `GET /auth/{provider}/login`
- `GET /healthz`
- `GET /index.json`
- `GET /plugins/{id}`
- `GET /plugins/{id}/index.json`
- `GET /readyz`
