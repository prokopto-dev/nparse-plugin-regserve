---
description: The schema-v1 index document and the rules that protect it
paths: ["internal/registry/**", "internal/api/index.go", "internal/plugin/**"]
---

# The wire format is not ours

`GET /index.json` is parsed by nParse+ installs already in the field, using the pydantic models in
`nparseplus.core.plugins.registry`. We cannot patch those installs.

- **`schema_version` stays `1`.** A client that reads a higher number refuses the entire index and
  tells the user to update. Bumping it strands every release that has ever shipped.
- **Adding a field is safe** (the client ignores unknown keys). Renaming or removing one is not.
- **Only `internal/registry` may know the field names.** Gate `SCHEMA002` (in `test/repo/arch_test.go`)
  fails a string literal containing `schema_version`, `requires_sdk` or `min_app_version` anywhere
  else.
- **Never edit `internal/registry/testdata/index-v1.schema.json`.** It is generated upstream by
  `tools/gen_registry_schema.py` in `nparse-plus`. If `SCHEMA001` fails, the renderer drifted from
  the client — fix the renderer.

Client budgets, which are limits rather than preferences: body **< 5 MiB**, **15 s** timeout, at
most **5 redirect hops and every one `https`**. `SIZE001` guards the first.

Two shapes that must not regress, both covered by tests:

- An empty catalogue marshals as `"plugins":[]`, never `null` — pydantic rejects `null` for a list,
  so a fresh instance would report as malformed rather than empty.
- Plugins are sorted by `id`. The client renders in array order, so unstable ordering reshuffles the
  browse list on every refresh.

Never serve a partial catalogue on error. A truncated index is indistinguishable from "those plugins
were delisted", so users watch plugins silently disappear. Fail the request instead.
