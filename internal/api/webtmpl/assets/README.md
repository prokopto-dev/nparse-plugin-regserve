# Vendored upstream artifacts

`nparseplus-mark.svg` is the **nParse+ application mark**, copied here verbatim from
[`prokopto-dev/nparse-plus`](https://github.com/prokopto-dev/nparse-plus) at
`data/assets/icon.svg`. Upstream it is the source of truth every shipped icon is rasterised from
by `tools/gen_icons.py`, and every colour in it is a real value from `src/nparseplus/ui/skins.py`
— which is why the palette in `layout.html` and this file agree without anybody keeping them in
step by hand.

**Do not edit it.** Not to change a colour, not to strip the comment, not to add a `class`. It is
somebody else's generated artifact and the only safe operation is replacing it wholesale with a
newer copy — the same rule `internal/registry/testdata/index-v1.schema.json` is under, and for the
same reason: a local edit makes this repository's copy diverge from the thing it is a copy of, with
nothing anywhere saying so.

It is **inlined into the page** rather than served as a file. `layout.html` calls it with
`{{template "nparseplus-mark.svg" .}}`: `html/template` parses it as a template whose body is
literal markup, so the SVG is emitted verbatim with no `template.HTML` anywhere (AGENTS.md forbids
that value appearing at all) and no second copy of the markup to keep in step. The upstream file's
long provenance comment does not reach the browser — `html/template` elides HTML comments — so the
page carries about 1.3 KB of the 5.2 KB on disk, and the reasoning stays where somebody editing it
will read it.

The comment inside the file explains why it **must begin with the `<svg>` tag**: `gdk-pixbuf`
sniffs the format from the first bytes and a leading comment or XML declaration makes librsvg
report "Unrecognized image file format", which once killed an upstream release build. Preserve that
property if this is ever re-vendored.

To update it: copy the newer `data/assets/icon.svg` over this file, run `make check` — the contrast
and no-gold-fields gates in `internal/api/brand_internal_test.go` read the stylesheet, not the mark,
so also look at the rendered header — and record the new commit below.

Retrieved from `prokopto-dev/nparse-plus@9434507fd6c82fd5526e2bb2c9526c00f0f59f54:data/assets/icon.svg`
(committed 2026-08-13) on 2026-08-20.
