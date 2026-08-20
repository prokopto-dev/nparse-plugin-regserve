package artifact_test

import (
	"crypto/sha256"
	"encoding/hex"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"
)

// The two digest types exist so that "a stored sha256 was computed by the server" is a statement
// the compiler can check rather than one a reviewer has to. These tests are about the SHAPE of the
// types, not about their arithmetic: a shape that admits the mistake is the bug.

// TestDigest_TheZeroValue_CannotBeStored — a hash for bytes nobody read is never stored.
//
// The zero Digest is what "we never computed anything" looks like. Storing it would put an empty
// string, or worse a plausible-looking one, in the column every installed client verifies against.
func TestDigest_TheZeroValue_CannotBeStored(t *testing.T) {
	t.Parallel()

	var never artifact.Digest
	require.False(t, never.Computed())
	require.Empty(t, never.Hex())

	stored, err := artifact.StoredHash(never)
	require.ErrorIs(t, err, artifact.ErrDigestNotComputed)
	require.Nil(t, stored)
}

// TestStoredHash_ReturnsTheComputedValue — the door works when it should.
func TestStoredHash_ReturnsTheComputedValue(t *testing.T) {
	t.Parallel()

	body := []byte("PK\x03\x04 an artifact")
	srv, f := tlsServer(t, serveBytes(body), artifact.Config{})

	got, err := f.Fetch(t.Context(), srv.URL+"/plugin.whl")
	require.NoError(t, err)

	stored, err := artifact.StoredHash(got.Digest)
	require.NoError(t, err)
	require.NotNil(t, stored)

	want := sha256.Sum256(body)
	require.Equal(t, hex.EncodeToString(want[:]), *stored)

	// The pointer is to a copy. A caller mutating what it stored must not reach back into the
	// Digest it was derived from — nothing does that today, and a value type is how it stays true.
	*stored = "0000000000000000000000000000000000000000000000000000000000000000"
	require.Equal(t, hex.EncodeToString(want[:]), got.Digest.Hex())
}

// TestParseSubmittedDigest_RefusesAnythingThatIsNotASHA256 — hostile input, at the edge.
//
// It is refused here as well as by the column's CHECK, because a publish that is going to be
// rejected should be rejected before the server spends forty-five seconds downloading fifty
// megabytes on the submitter's behalf.
func TestParseSubmittedDigest_RefusesAnythingThatIsNotASHA256(t *testing.T) {
	t.Parallel()

	valid := strings.Repeat("a", 64)

	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"lowercase hex", valid, true},
		{"uppercase hex is lowered rather than refused", strings.ToUpper(valid), true},
		{"surrounding whitespace is trimmed", "  " + valid + "\n", true},
		{"empty", "", false},
		{"one character short", strings.Repeat("a", 63), false},
		{"one character long", strings.Repeat("a", 65), false},
		{"not hex", strings.Repeat("z", 64), false},
		{"a sha1", strings.Repeat("a", 40), false},
		{"the sha256: prefix some tools emit", "sha256:" + valid, false},
		{"hex with a null in it", strings.Repeat("a", 63) + "\x00", false},
		{"unicode digits", strings.Repeat("１", 64), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := artifact.ParseSubmittedDigest(tc.in)
			if !tc.want {
				require.ErrorIs(t, err, artifact.ErrInvalidDigest)
				require.False(t, got.Present())
				return
			}
			require.NoError(t, err)
			require.True(t, got.Present())
			require.Equal(t, strings.ToLower(strings.TrimSpace(tc.in)), got.String())
		})
	}
}

// TestSubmittedDigest_Matches_IsTheOnlyAnswerItGives — compared, then discarded.
//
// The answer a caller can get out of a SubmittedDigest is a BOOLEAN. That is the shape of the type
// and it is the shape of ADR-0008: the submitted value is a cross-check, never a source.
func TestSubmittedDigest_Matches_IsTheOnlyAnswerItGives(t *testing.T) {
	t.Parallel()

	body := []byte("the real bytes")
	srv, f := tlsServer(t, serveBytes(body), artifact.Config{})

	computed, err := f.Fetch(t.Context(), srv.URL+"/plugin.whl")
	require.NoError(t, err)

	truth, err := artifact.ParseSubmittedDigest(computed.Digest.Hex())
	require.NoError(t, err)
	require.True(t, truth.Matches(computed.Digest))

	// The same digest with one character changed. This is what a tampered artifact looks like from
	// here: the submitter's CI hashed one thing and this server fetched another.
	lie, err := artifact.ParseSubmittedDigest(flipOneHexDigit(computed.Digest.Hex()))
	require.NoError(t, err)
	require.False(t, lie.Matches(computed.Digest))

	// Neither half of an absent comparison is a match. "We have nothing to compare" must not
	// resolve to "they agree".
	var nothingSubmitted artifact.SubmittedDigest
	require.False(t, nothingSubmitted.Matches(computed.Digest))

	var nothingComputed artifact.Digest
	require.False(t, truth.Matches(nothingComputed))
	require.False(t, nothingSubmitted.Matches(nothingComputed))
}

func flipOneHexDigit(s string) string {
	b := []byte(s)
	if b[0] == 'a' {
		b[0] = 'b'
	} else {
		b[0] = 'a'
	}
	return string(b)
}

// TestSubmittedDigest_OffersNoWayToBecomeAStoredHash — the mechanism, asserted on the API.
//
// This is the half a behavioural test cannot reach. The rule is not "the publish path happens to
// store the right value today"; it is that there is NO EXPRESSION a caller can write that turns a
// submitted digest into a stored one. StoredHash takes a Digest, a Digest cannot be built outside
// this package, and SubmittedDigest exposes no conversion in either direction.
//
// It reads the package's own source rather than reflecting, because what is being asserted is the
// absence of a method — and a method that does not exist has no reflect.Type to ask about.
func TestSubmittedDigest_OffersNoWayToBecomeAStoredHash(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "digest.go", nil, parser.ParseComments)
	require.NoError(t, err)

	// Every method on SubmittedDigest, with the types it returns.
	returns := map[string][]string{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		if receiverName(fn.Recv.List[0].Type) != "SubmittedDigest" {
			continue
		}
		var out []string
		if fn.Type.Results != nil {
			for _, r := range fn.Type.Results.List {
				out = append(out, exprName(r.Type))
			}
		}
		returns[fn.Name.Name] = out
	}

	require.NotEmpty(t, returns, "no methods on SubmittedDigest were found; the gate is vacant")

	for name, out := range returns {
		for _, typ := range out {
			require.NotEqual(t, "Digest", typ,
				"SubmittedDigest.%s returns a Digest: a claimed hash must never become a computed "+
					"one, in either direction", name)
		}
	}

	// And nothing constructs a Digest from a SubmittedDigest by another route.
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv != nil || fn.Type.Params == nil {
			continue
		}
		takesSubmitted := false
		for _, p := range fn.Type.Params.List {
			if exprName(p.Type) == "SubmittedDigest" {
				takesSubmitted = true
			}
		}
		if !takesSubmitted || fn.Type.Results == nil {
			continue
		}
		for _, r := range fn.Type.Results.List {
			require.NotEqual(t, "Digest", exprName(r.Type),
				"%s turns a SubmittedDigest into a Digest", fn.Name.Name)
		}
	}
}

// TestDigest_CannotBeConstructedOutsideThisPackage — stated for the reader; enforced by the
// compiler.
//
// Digest's only field is unexported, so `artifact.Digest{hex: "..."}` in another package does not
// build — it is a compile error, not a test failure, which is the strongest form this can take.
// What this asserts is that the property still holds: that no exported function anywhere in the
// package hands back a Digest built from a caller-supplied string.
func TestDigest_CannotBeConstructedOutsideThisPackage(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir(".")
	require.NoError(t, err)

	fset := token.NewFileSet()
	var producers []string
	inspected := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, perr := parser.ParseFile(fset, name, nil, parser.ParseComments)
		require.NoError(t, perr)
		inspected++

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || !fn.Name.IsExported() || fn.Type.Results == nil {
				continue
			}
			for _, r := range fn.Type.Results.List {
				if exprName(r.Type) == "Digest" {
					producers = append(producers, name+":"+fn.Name.Name)
				}
			}
		}
	}
	require.NotZero(t, inspected, "no source files were inspected; the gate is vacant, not passing")

	// Fetch returns a Result, which CONTAINS a Digest; no exported function returns a bare one.
	// If that ever changes, this is where the argument for it gets written down.
	require.Empty(t, producers,
		"an exported function returns a Digest directly; the only way to obtain one must remain "+
			"hashing bytes through Fetch")
}

// receiverName returns the type name of a method receiver, pointer or value.
func receiverName(e ast.Expr) string {
	if star, ok := e.(*ast.StarExpr); ok {
		return exprName(star.X)
	}
	return exprName(e)
}

// exprName returns the identifier at the heart of a type expression.
func exprName(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return exprName(t.X)
	case *ast.SelectorExpr:
		return t.Sel.Name
	}
	return ""
}
