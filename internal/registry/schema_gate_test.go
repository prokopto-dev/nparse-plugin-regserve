package registry_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// These tests are about SCHEMA001 itself, not about the renderer.
//
// A validator that accepts everything passes every test in index_test.go while checking nothing,
// and the failure is invisible: the suite stays green as the renderer drifts away from the client.
// So each case below feeds the compiled schema a document that MUST be rejected. If one of these
// starts passing validation, SCHEMA001 has stopped being a gate.

func TestSchemaGate_InvalidDocuments_AreRejected(t *testing.T) {
	t.Parallel()

	validRelease := map[string]any{
		"version": "1.0.0",
		"url":     "https://example.com/x.zip",
		"sha256":  strings.Repeat("a", 64),
	}

	tests := []struct {
		name string
		doc  map[string]any
		why  string
	}{
		{
			name: "schema_version above 1",
			doc: map[string]any{
				"schema_version": 2,
				"plugins":        []any{},
			},
			why: "the schema caps schema_version at 1; a client refuses anything higher",
		},
		{
			name: "plugin id with uppercase",
			doc: map[string]any{
				"schema_version": 1,
				"plugins": []any{map[string]any{
					"id": "Not-Valid", "name": "x", "latest": validRelease,
				}},
			},
			why: "the id pattern is ^[a-z][a-z0-9_-]{1,39}$",
		},
		{
			name: "plugin id starting with a digit",
			doc: map[string]any{
				"schema_version": 1,
				"plugins": []any{map[string]any{
					"id": "9lives", "name": "x", "latest": validRelease,
				}},
			},
			why: "the id pattern requires a leading letter",
		},
		{
			name: "http url",
			doc: map[string]any{
				"schema_version": 1,
				"plugins": []any{map[string]any{
					"id": "ok", "name": "x", "latest": map[string]any{
						"version": "1.0.0", "url": "http://example.com/x.zip",
						"sha256": strings.Repeat("a", 64),
					},
				}},
			},
			why: "the url pattern requires https",
		},
		{
			name: "uppercase sha256",
			doc: map[string]any{
				"schema_version": 1,
				"plugins": []any{map[string]any{
					"id": "ok", "name": "x", "latest": map[string]any{
						"version": "1.0.0", "url": "https://example.com/x.zip",
						"sha256": strings.Repeat("A", 64),
					},
				}},
			},
			why: "the sha256 pattern is lowercase hex only",
		},
		{
			name: "missing latest",
			doc: map[string]any{
				"schema_version": 1,
				"plugins":        []any{map[string]any{"id": "ok", "name": "x"}},
			},
			why: "latest is required",
		},
		{
			name: "missing name",
			doc: map[string]any{
				"schema_version": 1,
				"plugins":        []any{map[string]any{"id": "ok", "latest": validRelease}},
			},
			why: "name is required",
		},
	}

	s := compiledSchema(t)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw, err := json.Marshal(tt.doc)
			require.NoError(t, err)

			var generic any
			require.NoError(t, json.Unmarshal(raw, &generic))

			require.Error(t, s.Validate(generic),
				"SCHEMA001 must reject this document: %s", tt.why)
		})
	}
}

// TestSchemaGate_LiveIndexShape_Validates guards against the opposite failure: a schema so strict
// that the catalogue actually in production would not pass. This is the literal shape served at
// https://prokopto-dev.github.io/nparseplus-plugins/index.json, kept as a fixture so that "would
// the real registry validate" is answerable without network access.
func TestSchemaGate_LiveIndexShape_Validates(t *testing.T) {
	t.Parallel()

	const live = `{
	  "schema_version": 1,
	  "plugins": [
	    {
	      "id": "merchant-mode",
	      "name": "Merchant Mode",
	      "description": "Turn your inventory into linkable WTS auction macros.",
	      "author": "prokopto-dev",
	      "homepage": "https://github.com/prokopto-dev/nparseplus-merchantmode",
	      "latest": {
	        "version": "0.5.0",
	        "url": "https://github.com/prokopto-dev/nparseplus-merchantmode/releases/download/v0.5.0/merchant_mode.zip",
	        "sha256": "87478a4fa3463cd831e5157a5b3f6e3c8fe6e6ff321f777162f6ab06cfccc742",
	        "requires_sdk": ">=1.0,<2",
	        "min_app_version": "2.1.0"
	      }
	    }
	  ]
	}`

	var generic any
	require.NoError(t, json.Unmarshal([]byte(live), &generic))
	require.NoError(t, compiledSchema(t).Validate(generic),
		"the catalogue currently in production must validate; if it does not, the vendored schema is wrong")
}
