// Package repo_test holds tests about the repository itself, not about the product.
//
// These are the architectural gates named in docs/concepts/invariants.md. They parse the tree with
// go/ast rather than grepping it, for two reasons that both bit us: a grep matches the rule's name
// inside the comment explaining the rule, and a grep for `time.Now` misses `clk "time"` followed by
// `clk.Now()`. A gate with false positives gets disabled; a gate with false negatives is worse,
// because it is trusted.
package repo_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// scanned are the trees these gates cover. Test files are excluded: a test may legitimately dial a
// local httptest server or open a database, and holding tests to the production rules would push
// people towards testing less.
var scanned = []string{"../../cmd", "../../internal"}

type goFile struct {
	path string
	file *ast.File
	fset *token.FileSet
	// imports maps an import path to the local name it is bound to in this file, so an alias
	// cannot defeat a check.
	imports map[string]string
}

// rel returns the repository-relative path, so a failure names a file you can open.
func (g goFile) rel() string {
	p := filepath.ToSlash(g.path)
	if i := strings.Index(p, "../../"); i == 0 {
		return strings.TrimPrefix(p, "../../")
	}
	return p
}

func (g goFile) inTree(prefixes ...string) bool {
	r := g.rel()
	for _, p := range prefixes {
		if strings.HasPrefix(r, p) {
			return true
		}
	}
	return false
}

// localName returns the identifier importPath is bound to in this file, and whether it is imported.
func (g goFile) localName(importPath string) (string, bool) {
	n, ok := g.imports[importPath]
	return n, ok
}

func parseTree(t *testing.T) []goFile {
	t.Helper()

	var out []goFile
	for _, root := range scanned {
		if _, err := os.Stat(root); os.IsNotExist(err) {
			continue
		}
		err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, parser.ParseComments)
			if perr != nil {
				return perr
			}
			imports := map[string]string{}
			for _, spec := range f.Imports {
				p, uerr := strconv.Unquote(spec.Path.Value)
				if uerr != nil {
					return uerr
				}
				name := p[strings.LastIndex(p, "/")+1:]
				if spec.Name != nil {
					name = spec.Name.Name
				}
				imports[p] = name
			}
			out = append(out, goFile{path: path, file: f, fset: fset, imports: imports})
			return nil
		})
		require.NoError(t, err, "walk %s", root)
	}
	return out
}

// requireNotVacant fails when a gate had nothing to inspect.
//
// A gate reporting success over an empty tree is how a rule silently stops being enforced: the tick
// is green, nobody looks again, and the first file that breaks the rule sails through.
func requireNotVacant(t *testing.T, files []goFile, gate string) {
	t.Helper()
	require.NotEmpty(t, files, "%s inspected no files; the gate is vacant, not passing", gate)
}

// selectorCalls yields every `x.Sel(...)` call in the file, with the name of x when x is a plain
// identifier.
func selectorCalls(f *ast.File, fn func(recv, sel string, pos token.Pos)) {
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		ident, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		fn(ident.Name, sel.Sel.Name, call.Pos())
		return true
	})
}

// --- CLOCK001 ---------------------------------------------------------------------------------

// TestCLOCK001_TimeNow_OnlyInInternalClock — the clock is injected, always.
//
// A service that reads the wall clock directly cannot be tested at a boundary: token expiry,
// quarantine windows and publish ordering all have edges, and a test that cannot place itself on
// one either sleeps or asserts nothing.
func TestCLOCK001_TimeNow_OnlyInInternalClock(t *testing.T) {
	t.Parallel()

	files := parseTree(t)
	requireNotVacant(t, files, "CLOCK001")

	var bad []string
	for _, g := range files {
		if g.inTree("internal/clock/") {
			continue
		}
		local, ok := g.localName("time")
		if !ok {
			continue
		}
		selectorCalls(g.file, func(recv, sel string, pos token.Pos) {
			if recv == local && sel == "Now" {
				bad = append(bad, g.fset.Position(pos).String())
			}
		})
	}
	require.Empty(t, bad, "CLOCK001: time.Now outside internal/clock — inject a clock.Clock instead")
}

// --- SQL001 -----------------------------------------------------------------------------------

// TestSQL001_DatabaseSQL_OnlyInInternalStore — *sql.DB is held in one place.
//
// Once a second package can open a connection, transaction boundaries stop being reviewable: the
// question "does this run in a transaction" becomes a search rather than a look at one file.
func TestSQL001_DatabaseSQL_OnlyInInternalStore(t *testing.T) {
	t.Parallel()

	files := parseTree(t)
	requireNotVacant(t, files, "SQL001")

	var bad []string
	for _, g := range files {
		if g.inTree("internal/store/") {
			continue
		}
		if _, ok := g.localName("database/sql"); ok {
			bad = append(bad, g.rel())
		}
	}
	require.Empty(t, bad, "SQL001: database/sql imported outside internal/store")
}

// --- NET001 -----------------------------------------------------------------------------------

// TestNET001_OutboundHTTP_OnlyFromIdentityAndArtifact — outbound requests come from two packages.
//
// Both go through a client whose dialer refuses private, link-local, loopback and cloud-metadata
// addresses, because the URLs are user-supplied by design (ADR-0008). A request built anywhere else
// bypasses that, and SSRF is the failure mode this service is most exposed to.
//
// This is one package wider than the sibling projects' rule. The widening is deliberate and
// recorded; do not widen it again without the same treatment.
func TestNET001_OutboundHTTP_OnlyFromIdentityAndArtifact(t *testing.T) {
	t.Parallel()

	files := parseTree(t)
	requireNotVacant(t, files, "NET001")

	allowed := []string{
		"internal/identity/",
		"internal/artifact/",
		// The container image is FROM scratch and has no curl, so the HEALTHCHECK is the binary
		// probing itself. It dials a fixed loopback address that no request can influence, which
		// is the opposite of the SSRF this gate exists to prevent. It is the ONLY exception, and
		// it is by exact filename so a second outbound call cannot hide behind it.
		"cmd/regserve/healthcheck.go",
	}
	banned := map[string]bool{"Get": true, "Post": true, "Head": true, "PostForm": true}

	var bad []string
	for _, g := range files {
		if g.inTree(allowed...) {
			continue
		}
		httpName, hasHTTP := g.localName("net/http")
		netName, hasNet := g.localName("net")

		if hasHTTP {
			selectorCalls(g.file, func(recv, sel string, pos token.Pos) {
				if recv == httpName && banned[sel] {
					bad = append(bad, g.fset.Position(pos).String()+" (http."+sel+")")
				}
			})
			// http.Client{...} — constructing a client outside the guarded trees means a client
			// without the guarded dialer.
			ast.Inspect(g.file, func(n ast.Node) bool {
				lit, ok := n.(*ast.CompositeLit)
				if !ok {
					return true
				}
				sel, ok := lit.Type.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if ok && ident.Name == httpName && sel.Sel.Name == "Client" {
					bad = append(bad, g.fset.Position(lit.Pos()).String()+" (http.Client literal)")
				}
				return true
			})
		}
		if hasNet {
			selectorCalls(g.file, func(recv, sel string, pos token.Pos) {
				if recv == netName && strings.HasPrefix(sel, "Dial") {
					bad = append(bad, g.fset.Position(pos).String()+" (net."+sel+")")
				}
			})
		}
	}
	require.Empty(t, bad,
		"NET001: outbound request built outside internal/identity/* and internal/artifact")
}

// --- ROUTE001 ---------------------------------------------------------------------------------

// TestROUTE001_Routes_OnlyInInternalAPI — every route is declared in one tree.
//
// The coverage tests that assert each operation declares a permission walk the route registry. A
// route registered somewhere they do not look is a route with no permission and no test saying so.
func TestROUTE001_Routes_OnlyInInternalAPI(t *testing.T) {
	t.Parallel()

	files := parseTree(t)
	requireNotVacant(t, files, "ROUTE001")

	// Heuristic by receiver name, because resolving *http.ServeMux would need full type
	// information. It catches the shapes actually used here; it is not a proof.
	registrars := map[string]bool{"Handle": true, "HandleFunc": true, "Register": true}
	receivers := map[string]bool{"mux": true, "huma": true, "http": true, "api": true, "r": true}

	var bad []string
	for _, g := range files {
		if g.inTree("internal/api/") {
			continue
		}
		selectorCalls(g.file, func(recv, sel string, pos token.Pos) {
			if registrars[sel] && receivers[recv] {
				bad = append(bad, g.fset.Position(pos).String()+" ("+recv+"."+sel+")")
			}
		})
	}
	require.Empty(t, bad, "ROUTE001: HTTP route registered outside internal/api")
}

// --- SCHEMA002 --------------------------------------------------------------------------------

// TestSCHEMA002_WireFormat_OnlyInInternalRegistry — one package knows the index document.
//
// The format belongs to a parser we do not own: a released nParse+ client reads it with pydantic
// models we cannot patch. Two packages that both know the shape will disagree eventually, and the
// thing that breaks is a plugin browser on a version already in the field.
//
// Struct tags and string literals are inspected via the AST, so the prose in this comment — which
// names the very fields being banned — does not trip the gate.
func TestSCHEMA002_WireFormat_OnlyInInternalRegistry(t *testing.T) {
	t.Parallel()

	files := parseTree(t)
	requireNotVacant(t, files, "SCHEMA002")

	wireFields := []string{"schema_version", "requires_sdk", "min_app_version"}

	var bad []string
	for _, g := range files {
		if g.inTree("internal/registry/") {
			continue
		}
		ast.Inspect(g.file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			for _, f := range wireFields {
				if strings.Contains(lit.Value, f) {
					bad = append(bad, g.fset.Position(lit.Pos()).String()+" ("+f+")")
				}
			}
			return true
		})
	}
	require.Empty(t, bad,
		"SCHEMA002: wire-format field name outside internal/registry — that package renders the index")
}
