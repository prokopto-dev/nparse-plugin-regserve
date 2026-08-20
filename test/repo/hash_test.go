package repo_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// --- HASH001 ----------------------------------------------------------------------------------
//
// A STORED SHA256 WAS COMPUTED BY THE SERVER.
//
// This was the one row in docs/concepts/invariants.md with no mechanism, labelled "a review rule
// wearing a table row's clothes". It is the most consequential rule in the repository: the hash
// this registry publishes is what the nParse+ installer verifies an archive against BEFORE
// extracting it, so a submitted value stored there would have every client verifying perfectly
// against exactly the bytes an attacker chose (ADR-0008).
//
// There are four mechanisms, and this file is the third. They are listed here because each covers
// a hole the others do not:
//
//  1. THE TYPE. artifact.Digest has an unexported field and no exported constructor, so outside
//     internal/artifact the only way to obtain one is to hash bytes that were fetched. That is the
//     compiler, not a convention: a composite literal naming an unexported field from another
//     package does not build.
//  2. THE DOOR. artifact.StoredHash is the only function that renders a Digest for the column, and
//     it takes a Digest — so a SubmittedDigest cannot be passed to it, in any spelling.
//  3. THIS GATE. The types make the RIGHT value easy to produce; they cannot stop a caller writing
//     a raw string into the column around the side. This fails that.
//  4. THE DATABASE. release_a_stored_hash_was_verified_or_imported holds for writes that never go
//     through Go at all — a migration, a later phase, a hand-run UPDATE during an incident.
//
// THE RULE THIS GATE ENFORCES, precisely:
//
//	An assignment to a field named ArtifactSha256 must have `<artifact>.StoredHash(...)` as its
//	right-hand side, UNLESS the same composite literal also sets Source to "import".
//
// The exception is not a filename allowlist and that is deliberate. The seed importer writes
// hashes this server did not compute — they came from the static registry, where a human reviewed
// them in a pull request — and `source = 'import'` is the machine-readable statement of exactly
// that. So the only way to store a hash the server did not compute is TO SAY SO, in the row, in
// the same breath. A publish path that tried to sneak a submitted hash through would have to label
// its rows as imports, which is a change no reviewer would miss and which the index's own
// provenance reporting would reflect.

// hashColumnField is the generated field name for release.artifact_sha256. It comes from sqlc, so
// it changes only if the column is renamed — which is a migration, not a refactor.
const hashColumnField = "ArtifactSha256"

// storedHashFunc is the one door. Named as a constant so the failure message and the check cannot
// describe different functions.
const storedHashFunc = "StoredHash"

// artifactImportPath is resolved to its local name per file, so an aliased import does not defeat
// the check — the lesson CLOCK001 learned when `clk "time"` walked past a grep.
const artifactImportPath = "github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"

// TestHASH001_AStoredHash_ComesOnlyFromTheHasher — the gate.
func TestHASH001_AStoredHash_ComesOnlyFromTheHasher(t *testing.T) {
	t.Parallel()

	files := parseTree(t)
	requireNotVacant(t, files, "HASH001")

	var inspected int
	var bad []string
	for _, g := range files {
		// internal/store/sqlitegen is generated: it DECLARES the field and never assigns one to a
		// value of its own. Excluding it by tree rather than by filename because sqlc decides how
		// many files it writes.
		if g.inTree("internal/store/sqlitegen/") {
			continue
		}
		local, _ := g.localName(artifactImportPath)

		for _, finding := range hashAssignments(g, local) {
			inspected++
			if finding.ok {
				continue
			}
			bad = append(bad, finding.where+": "+finding.why)
		}
	}

	require.NotZero(t, inspected,
		"HASH001 found no assignment to %s anywhere; the gate is vacant, not passing — either the "+
			"publish path has gone, or the column has been renamed and this gate now inspects nothing",
		hashColumnField)
	require.Empty(t, bad,
		"HASH001: a stored sha256 must come from artifact.%s, which takes a digest only the "+
			"hasher can produce (ADR-0008). A row whose hash this server did not compute must "+
			"declare Source: \"import\" in the same literal", storedHashFunc)
}

// TestHASH001_FiresOnADeliberatelyBrokenAssignment — the gate has been watched failing.
//
// docs/concepts/invariants.md, "Adding a gate": a gate nobody has seen fail is a gate nobody knows
// works. Each shape below is a way somebody could plausibly store the wrong value, and every one
// of them must be rejected by the SAME judgement the real gate applies — not by a second copy of
// it written to agree.
func TestHASH001_FiresOnADeliberatelyBrokenAssignment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		want bool // true: this shape must be REJECTED
	}{
		{
			name: "the real thing",
			src: `params := sqlitegen.InsertPublishReleaseParams{
				ArtifactSha256: artifact.StoredHash(res.Digest),
			}`,
			want: false,
		},
		{
			name: "an import declaring itself one",
			src: `_ = sqlitegen.InsertReleaseParams{
				Source:         "import",
				ArtifactSha256: &sha,
			}`,
			want: false,
		},
		{
			// The bug this whole mechanism exists to prevent, in its most direct form.
			name: "the submitted hash, stored",
			src: `_ = sqlitegen.InsertPublishReleaseParams{
				ArtifactSha256: &submitted,
			}`,
			want: true,
		},
		{
			name: "the submitted hash, stored by assignment rather than in a literal",
			src:  `params.ArtifactSha256 = &submitted`,
			want: true,
		},
		{
			// The production shape. The assignment IS the call, which is what lets a gate with no
			// type information see where the value came from -- and is why StoredHash returns
			// *string rather than (string, error).
			name: "the door, as a two-value assignment",
			src:  `params.ArtifactSha256, err = artifact.StoredHash(res.Digest)`,
			want: false,
		},
		{
			// The same two-value shape with the wrong source. Splitting the call out into a
			// variable first is exactly the refactor that would blind the gate, so it must not be
			// accepted just because a StoredHash call appears somewhere in the function.
			name: "a call to the door, then a bare identifier assigned",
			src: `stored, _ := artifact.StoredHash(res.Digest)
				_ = stored
				params.ArtifactSha256 = maybeSomethingElse`,
			want: true,
		},
		{
			// `source` is what makes an unhashed value legitimate. A publish row claiming the
			// exemption without taking the label is the loophole, closed.
			name: "a raw hash on a row that says it is a publish",
			src: `_ = sqlitegen.InsertPublishReleaseParams{
				Source:         "publish",
				ArtifactSha256: &submitted,
			}`,
			want: true,
		},
		{
			name: "a raw hash on a row that names no source at all",
			src: `_ = sqlitegen.InsertPublishReleaseParams{
				Version:        "1.0.0",
				ArtifactSha256: &submitted,
			}`,
			want: true,
		},
		{
			// A function that happens to be called StoredHash, on something that is not the
			// artifact package. The check resolves the import path to its local name, so a
			// same-named helper next door does not satisfy it.
			name: "a lookalike StoredHash from another package",
			src: `_ = sqlitegen.InsertPublishReleaseParams{
				ArtifactSha256: shady.StoredHash(whatever),
			}`,
			want: true,
		},
		{
			name: "a bare string literal",
			src: `_ = sqlitegen.InsertPublishReleaseParams{
				ArtifactSha256: &fixedHash,
			}`,
			want: true,
		},
		{
			// The genuinely sneaky one: the right function, called on a value derived from the
			// submitted digest. It is rejected by the COMPILER rather than here — StoredHash takes
			// an artifact.Digest and a SubmittedDigest is a different type with no conversion — so
			// this asserts the gate lets it through, and that the type system is what catches it.
			// A gate that also tried to judge the ARGUMENT would need type information it does not
			// have, and would be guessing.
			name: "the right door, whose argument the compiler is what checks",
			src: `_ = sqlitegen.InsertPublishReleaseParams{
				ArtifactSha256: artifact.StoredHash(anything),
			}`,
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			g := parseSnippet(t, tc.src)
			findings := hashAssignments(g, "artifact")
			require.NotEmpty(t, findings,
				"the snippet contains no assignment to %s; the case tests nothing", hashColumnField)

			rejected := false
			for _, f := range findings {
				if !f.ok {
					rejected = true
				}
			}
			require.Equal(t, tc.want, rejected,
				"HASH001 judged this shape wrongly:\n%s", tc.src)
		})
	}
}

// hashFinding is one assignment to the hash column and the gate's judgement of it.
type hashFinding struct {
	where string
	why   string
	ok    bool
}

// hashAssignments finds every assignment to the hash column in a file and judges each.
//
// `artifactLocal` is the name internal/artifact is bound to in this file, empty when it is not
// imported — in which case NOTHING in the file can satisfy the rule, which is the correct reading:
// a package writing that column without importing the package that computes hashes is not getting
// its value from the hasher.
func hashAssignments(g goFile, artifactLocal string) []hashFinding {
	var out []hashFinding

	ast.Inspect(g.file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CompositeLit:
			// A struct literal: judge the hash field, and let a sibling `Source: "import"` excuse
			// a value that did not come from the hasher.
			var hashValue ast.Expr
			var hashPos token.Pos
			isImport := false
			for _, elt := range node.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch key.Name {
				case hashColumnField:
					hashValue, hashPos = kv.Value, kv.Pos()
				case "Source":
					if lit, ok := kv.Value.(*ast.BasicLit); ok &&
						lit.Kind == token.STRING && strings.Contains(lit.Value, "import") {
						isImport = true
					}
				}
			}
			if hashValue == nil {
				return true
			}
			out = append(out, judgeHashValue(g, artifactLocal, hashValue, hashPos, isImport))

		case *ast.AssignStmt:
			// `x.ArtifactSha256 = ...`. There is no sibling Source to excuse it, so the only
			// acceptable right-hand side is the door.
			for i, lhs := range node.Lhs {
				sel, ok := lhs.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != hashColumnField || i >= len(node.Rhs) {
					continue
				}
				out = append(out, judgeHashValue(g, artifactLocal, node.Rhs[i], node.Pos(), false))
			}
		}
		return true
	})
	return out
}

// judgeHashValue applies the rule to one right-hand side.
func judgeHashValue(
	g goFile, artifactLocal string, value ast.Expr, pos token.Pos, isImport bool,
) hashFinding {
	where := g.fset.Position(pos).String()

	if isStoredHashCall(artifactLocal, value) {
		return hashFinding{where: where, ok: true}
	}
	if isImport {
		return hashFinding{where: where, ok: true}
	}
	return hashFinding{
		where: where,
		why: "the value is not artifact." + storedHashFunc +
			"(...) and the row does not declare Source: \"import\"",
	}
}

// isStoredHashCall reports whether value is `<artifactLocal>.StoredHash(...)`.
//
// The receiver is compared against the LOCAL NAME the artifact package is bound to in this file,
// resolved from its import path. A file that aliases the import still passes; a file that defines
// its own StoredHash, or imports a different package under the name `artifact`, does not.
func isStoredHashCall(artifactLocal string, value ast.Expr) bool {
	if artifactLocal == "" {
		return false
	}
	call, ok := value.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != storedHashFunc {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)
	return ok && ident.Name == artifactLocal
}

// parseSnippet wraps a fragment in a file so the gate's own judgement can be run over it.
//
// The FIRES test uses this rather than a second implementation of the rule, so the two cannot
// disagree: what rejects the broken shapes below is the same function that walks the tree above.
func parseSnippet(t *testing.T, body string) goFile {
	t.Helper()

	src := "package snippet\n\nfunc f() {\n" + body + "\n}\n"
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "snippet.go", src, parser.ParseComments)
	require.NoError(t, err, "the snippet does not parse:\n%s", src)

	return goFile{
		path: "snippet.go",
		file: f,
		fset: fset,
		// The snippet is treated as though it imports internal/artifact as `artifact`, which is
		// the shape the real publish path has. A case that wants the lookalike uses another name.
		imports: map[string]string{artifactImportPath: "artifact"},
	}
}
