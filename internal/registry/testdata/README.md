# Vendored upstream artifacts

`index-v1.schema.json` is **generated upstream** and copied here verbatim. It is produced by
`tools/gen_registry_schema.py` in [`prokopto-dev/nparse-plus`](https://github.com/prokopto-dev/nparse-plus)
from the pydantic models in `nparseplus.core.plugins.registry` — the models a released desktop
client actually parses the index with.

**Do not edit it to make a test pass.** `SCHEMA001` compares what `internal/registry` renders
against this file; a mismatch means the renderer drifted from the client, which is the exact failure
the gate exists to catch. Editing the schema makes the gate agree with the bug.

To update it: regenerate upstream (`uv run python tools/gen_registry_schema.py`), copy the result
here, and read the diff carefully. A change to `schema_version` is a breaking change for every
nParse+ release in the field — see [ADR-0009](../../../docs/adr/0009-serve-schema-v1-at-a-stable-path.md).

Retrieved from `prokopto-dev/nparseplus-plugins@main:schema/index-v1.schema.json` on 2026-08-18.
