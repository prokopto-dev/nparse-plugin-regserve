package authz

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// The markers around the generated CHECK in db/schema.hcl.
//
// Canonical §4 makes the Go constants the source for every enum the database CHECKs, written into
// the schema between markers by `make gen`. This is the first of those: a scope the database
// accepts but the catalogue does not know would grant nothing while looking like it grants
// something, and the only way to be sure they agree is for one to be written from the other.
const (
	scopeMarkerBegin = "# GENERATED: authz scopes"
	scopeMarkerEnd   = "# END GENERATED"
)

// ErrNoScopeMarkers is a schema file with nowhere to write.
//
// It is an error rather than an append: a generator that writes a CHECK somewhere new when it
// cannot find its markers produces a schema with two of them, and the second is the one nobody
// notices.
var ErrNoScopeMarkers = fmt.Errorf("db/schema.hcl has no %q ... %q block", scopeMarkerBegin, scopeMarkerEnd)

// scopeBlockRe matches the marked block and captures the indentation, so the rewritten expression
// lands at the depth the surrounding HCL is written at rather than at column zero.
var scopeBlockRe = regexp.MustCompile(
	`(?s)([ \t]*)` + regexp.QuoteMeta(scopeMarkerBegin) + `\n.*?[ \t]*` + regexp.QuoteMeta(scopeMarkerEnd))

// WriteScopeCheck rewrites the generated scope CHECK in an HCL schema file.
//
// It returns the whole file, so the caller compares and writes rather than this deciding to. Gate
// GEN001 runs it and fails on any difference, which is what makes "do not hand-edit inside the
// markers" a mechanism rather than a request.
func WriteScopeCheck(schema []byte) ([]byte, error) {
	if !scopeBlockRe.Match(schema) {
		return nil, ErrNoScopeMarkers
	}

	quoted := make([]string, 0, len(Scopes()))
	for _, s := range Scopes() {
		if !s.Valid() {
			return nil, fmt.Errorf("scope %q is not spelled <family>:<verb>", s)
		}
		quoted = append(quoted, "'"+s.String()+"'")
	}

	var out bytes.Buffer
	replaced := scopeBlockRe.ReplaceAllStringFunc(string(schema), func(block string) string {
		indent := scopeBlockRe.FindStringSubmatch(block)[1]
		out.Reset()
		out.WriteString(indent + scopeMarkerBegin + "\n")
		fmt.Fprintf(&out, "%sexpr = \"scope IN (%s)\"\n", indent, strings.Join(quoted, ", "))
		out.WriteString(indent + scopeMarkerEnd)
		return out.String()
	})
	return []byte(replaced), nil
}
