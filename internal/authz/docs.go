package authz

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

// docsPath is where the generated page lives. It is named here rather than only in the Makefile so
// that the page itself can say where it came from and how to regenerate it, which is the first
// thing somebody does after editing it by hand and watching gate GEN001 fail.
const docsPath = "docs/reference/permissions.md"

// Usage maps a permission onto the operations that declare it, as `METHOD /path` strings.
//
// It is supplied by the CALLER rather than computed here, and that is not squeamishness about
// layering: internal/api imports this package, so this package importing internal/api would be a
// cycle. The generator command sits above both and hands the answer down, which also means the
// usage column is derived from the same route registry PERM001 walks — an operation cannot be
// listed on this page and absent from the served document.
type Usage map[Permission][]string

// RenderDocs renders docs/reference/permissions.md.
//
// The page is generated because canonical §5 forbids a hand-written permission list anywhere,
// including in the documentation: a docs page that drifts from the catalogue is worse than no page
// at all, because a plugin author writing a CI job trusts it.
func RenderDocs(usage Usage) ([]byte, error) {
	var b bytes.Buffer

	b.WriteString("# Permissions and scopes\n\n")
	b.WriteString("**Generated from `internal/authz/catalogue.go` — do not edit.** Run `make gen`" +
		" after changing the\ncatalogue; gate `GEN001` regenerates this page in CI and fails on" +
		" any difference.\n\n")

	b.WriteString("A **permission** narrows a role and is spelled `<resource>.<action>`. A" +
		" **scope** narrows a token\nand is spelled `<family>:<verb>`. They are deliberately" +
		" different vocabularies at different\ngranularities, and effective capability is the" +
		" intersection of the two — plus, for anything\ntouching a plugin, the account's" +
		" ownership at the moment of the request\n([ADR-0005](../adr/0005-pats-scoped-to-plugins.md)).\n\n")

	b.WriteString("## The capability floor\n\n")
	b.WriteString("Some operations carry **no scope at all** and are session-only, because a" +
		" token that could perform\none would be equivalent to the account. There is no" +
		" `admin:*` and no all-powerful token: a leaked\npublish token cannot mint a second" +
		" token, and that is the property that makes the containment\nreal.\n\n")
	b.WriteString("A floor operation declares `x-regserve-pat-forbidden: true` in the OpenAPI" +
		" document. That is a\ndifferent statement from an operation that simply has no scope" +
		" yet, and the two are spelled\ndifferently on purpose — an absence cannot be told from a" +
		" refusal.\n\n")

	b.WriteString("## Permissions\n\n")
	b.WriteString("| Permission | Scopes that satisfy it | Declared by | What it allows |\n")
	b.WriteString("|---|---|---|---|\n")
	for _, e := range Catalogue() {
		if err := writeRow(&b, e, usage); err != nil {
			return nil, err
		}
	}

	b.WriteString("\n## Scopes\n\n")
	b.WriteString("Every scope a personal access token may carry. A mint request naming anything" +
		" else is rejected\nrather than stored: a token whose scope matches no permission would" +
		" look narrow on the account\npage and be exactly as powerless in practice.\n\n")
	b.WriteString("| Scope | Grants |\n|---|---|\n")
	for _, s := range Scopes() {
		granted := make([]string, 0, 2)
		for _, e := range Catalogue() {
			for _, es := range e.Scopes {
				if es == s {
					granted = append(granted, "`"+e.Permission.String()+"`")
				}
			}
		}
		fmt.Fprintf(&b, "| `%s` | %s |\n", s, strings.Join(granted, ", "))
	}

	b.WriteString("\n## Operations that declare no permission\n\n")
	b.WriteString("Public ones. They declare `x-regserve-public: true` and an explicitly empty" +
		" `security` list, so\n\"anyone may call this\" is a decision somebody wrote down rather" +
		" than the absence of one.\n\n")
	for _, op := range sortedUnique(usage[""]) {
		fmt.Fprintf(&b, "- `%s`\n", op)
	}

	return b.Bytes(), nil
}

// DocsPath is where RenderDocs's output belongs.
func DocsPath() string { return docsPath }

func writeRow(b *bytes.Buffer, e Entry, usage Usage) error {
	if !e.Permission.Valid() {
		return fmt.Errorf("catalogue entry %q is not spelled <resource>.<action>", e.Permission)
	}

	scopes := "**none — capability floor**"
	if !e.Floor {
		if len(e.Scopes) == 0 {
			scopes = "*none yet — session only*"
		} else {
			names := make([]string, 0, len(e.Scopes))
			for _, s := range e.Scopes {
				if !s.Valid() {
					return fmt.Errorf("catalogue entry %q names scope %q, which is not spelled "+
						"<family>:<verb>", e.Permission, s)
				}
				names = append(names, "`"+s.String()+"`")
			}
			scopes = strings.Join(names, ", ")
		}
	}

	declared := "*nothing yet*"
	if ops := sortedUnique(usage[e.Permission]); len(ops) > 0 {
		quoted := make([]string, 0, len(ops))
		for _, op := range ops {
			quoted = append(quoted, "`"+op+"`")
		}
		declared = strings.Join(quoted, "<br>")
	}

	fmt.Fprintf(b, "| `%s` | %s | %s | %s |\n", e.Permission, scopes, declared, e.Summary)
	return nil
}

// sortedUnique makes the page deterministic. GEN001 regenerates it and fails on any diff, so a
// column whose order came from a map would report drift on every second run and teach everybody to
// re-run the generator until it agreed with itself.
func sortedUnique(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}
