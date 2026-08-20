package repo_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/require"
)

// --- QRY001 -----------------------------------------------------------------------------------

// TestQRY001_QueryFiles_AreASCII — sqlc mangles a query file that is not.
//
// This is not a style rule. sqlc v1.31.1 computes the extent of each query from the parser's
// character positions and slices the file with them as BYTE offsets, so a single multi-byte
// character earlier in the file shifts every query after it. The generated Go still compiles; the
// SQL inside it does not parse. Observed, in this repository, with an em dash in a comment:
//
//	const deleteExpiredSessions = `-- name: DeleteExpiredSessions :exec
//	C;
//
//	DELETE FROM session WHERE expires_at
//	`
//
// The failure surfaces at RUNTIME, as `SQL logic error: near "C": syntax error`, from a query
// nobody edited — and the worse version of it is a rotation that still parses. Every other prose
// file in this repository uses em dashes and typographic quotes freely, which is exactly why this
// needs a gate rather than a note: the next person writing a comment here will write one too.
//
// The fix is always the same: rewrite the comment in ASCII. Nothing in a query file needs more.
func TestQRY001_QueryFiles_AreASCII(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob("../../db/queries/*.sql")
	require.NoError(t, err)
	require.NotEmpty(t, files, "QRY001 inspected no query files; the gate is vacant, not passing")

	var findings []string
	for _, path := range files {
		src, err := os.ReadFile(path) //nolint:gosec // a path this repository owns
		require.NoError(t, err)
		findings = append(findings, nonASCIIFindings(filepath.Base(path), string(src))...)
	}

	require.Empty(t, findings,
		"QRY001: a non-ASCII character in db/queries scrambles the SQL sqlc generates, and the "+
			"result fails at runtime rather than at generation. Rewrite the comment in ASCII")
}

// TestQRY001_FiresOnANonASCIIComment — the gate has been seen to fail.
//
// The em dash below is the exact character that caused the failure this gate exists to prevent.
func TestQRY001_FiresOnANonASCIIComment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		src  string
		want bool
	}{
		{
			name: "an em dash in a comment",
			src:  "-- name: Thing :exec\n-- a comment — with an em dash\nDELETE FROM t WHERE x < ?;\n",
			want: true,
		},
		{
			name: "a typographic quote",
			src:  "-- the client’s parser\n-- name: Thing :one\nSELECT 1;\n",
			want: true,
		},
		{
			name: "a non-breaking space, which is invisible in a diff",
			src:  "-- name: Thing :one\nSELECT 1;\n",
			want: true,
		},
		{
			name: "plain ascii",
			src:  "-- name: Thing :exec\n-- a comment, with a comma\nDELETE FROM t WHERE x < ?;\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			findings := nonASCIIFindings("probe.sql", tt.src)
			if tt.want {
				require.NotEmpty(t, findings,
					"QRY001 must reject this file; it accepted it, so the gate is not checking "+
						"what it claims to")
				return
			}
			require.Empty(t, findings)
		})
	}
}

// nonASCIIFindings reports every non-ASCII rune in src, by line, with the character named.
//
// The position matters more than usual here: the character that breaks the generation is often
// nowhere near the query that comes out wrong, because the offsets shift for everything after it.
func nonASCIIFindings(name, src string) []string {
	var found []string
	for i, line := range strings.Split(src, "\n") {
		for _, r := range line {
			if r >= utf8.RuneSelf {
				found = append(found, fmt.Sprintf("%s:%d: %q (U+%04X)", name, i+1, r, r))
				break
			}
		}
	}
	return found
}
