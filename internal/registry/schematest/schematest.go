// Package schematest compiles the vendored upstream schema so a test can validate real bytes
// against it.
//
// It exists as a package rather than a helper in one test file because two suites need the same
// compiled schema and they cannot share a file: gate SCHEMA001 now validates the bytes a client
// receives over HTTP (internal/api), while the tests that prove the schema still REJECTS malformed
// documents live next to the renderer (internal/registry). A second copy of the compile step is a
// second thing to keep in step, and the failure mode of it drifting is a gate that validates
// against a schema nobody is looking at.
//
// The schema is generated upstream by tools/gen_registry_schema.py in nparse-plugin/nparse-plus
// from the pydantic models a released client parses with, and vendored here. Editing it to make a
// test pass inverts the point of the gate.
package schematest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

// URI is the $id the vendored document declares. The compiler resolves references by URI, so this
// has to match what is in the file rather than being a path — and it is the same constant the
// OpenAPI document points readers at, so the two cannot name different schemas.
const URI = registry.SchemaURI

// Path returns the vendored schema's location, resolved from this file rather than from the
// working directory: the callers live in different packages, so a relative path would be right for
// exactly one of them.
func Path() string {
	_, self, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(self), "..", "testdata", "index-v1.schema.json")
}

// Compile returns the compiled vendored schema.
func Compile(t *testing.T) *jsonschema.Schema {
	t.Helper()

	f, err := os.Open(Path())
	require.NoError(t, err, "open the vendored upstream schema")
	defer func() { _ = f.Close() }()

	doc, err := jsonschema.UnmarshalJSON(f)
	require.NoError(t, err, "parse the vendored upstream schema")

	c := jsonschema.NewCompiler()
	require.NoError(t, c.AddResource(URI, doc), "register the schema resource")

	s, err := c.Compile(URI)
	require.NoError(t, err, "compile the vendored upstream schema")
	return s
}

// ValidateBytes validates raw JSON — the literal bytes, not a Go value re-marshalled — against the
// vendored schema.
//
// Taking []byte rather than an already-decoded value is the point: a field that marshals
// differently than it reads, a body a framework added a key to, or a list that serialised as null
// is only visible in the bytes.
func ValidateBytes(t *testing.T, s *jsonschema.Schema, raw []byte) error {
	t.Helper()

	var generic any
	require.NoError(t, json.Unmarshal(raw, &generic), "re-parse the document under test")
	return s.Validate(generic)
}
