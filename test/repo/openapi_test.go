package repo_test

import (
	"fmt"
	"go/token"
	"regexp"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
)

// The gates over the route registry.
//
// AGENTS.md law 6: "Every operation declares Security and x-regserve-permission. Coverage is
// derived from the route registry, so a new uncovered route is a red test, not a missing one."
// These are what "derived" means. api.Spec() runs the same registration code the server runs, so
// an operation appears in the document the moment it is registered — declared or not — and the
// loops below inspect whatever is there rather than a list somebody remembered to extend.

// operation is one entry in the document, with enough context for a failure to name it.
type operation struct {
	path   string
	method string
	op     *huma.Operation
}

func (o operation) String() string { return o.method + " " + o.path }

func operations(t *testing.T) []operation {
	t.Helper()

	spec := api.Spec()
	require.NotNil(t, spec, "api.Spec() must build a document")

	var out []operation
	for path, item := range spec.Paths {
		for method, op := range map[string]*huma.Operation{
			"GET": item.Get, "PUT": item.Put, "POST": item.Post, "DELETE": item.Delete,
			"OPTIONS": item.Options, "HEAD": item.Head, "PATCH": item.Patch, "TRACE": item.Trace,
		} {
			if op != nil {
				out = append(out, operation{path: path, method: method, op: op})
			}
		}
	}
	return out
}

// --- PERM001 ----------------------------------------------------------------------------------

// TestPERM001_EveryOperation_DeclaresItsAccess — an operation says who may call it, or it fails.
//
// The failure this prevents is not a wrong permission, it is an ABSENT one: a route added in a
// hurry, shipped, and only noticed to be unauthenticated when somebody calls it. Being explicit
// about "public" is the point — public has to be a decision that was written down, and `security`
// has to be present and empty rather than absent, because an absent `security` inherits whatever
// the document-level default happens to be.
func TestPERM001_EveryOperation_DeclaresItsAccess(t *testing.T) {
	t.Parallel()

	ops := operations(t)
	require.NotEmpty(t, ops, "PERM001 inspected no operations; the gate is vacant, not passing")

	schemes := declaredSchemes(t)
	for _, o := range ops {
		t.Run(o.String(), func(t *testing.T) {
			t.Parallel()
			require.Empty(t, accessFindings(o, schemes),
				"PERM001: %s does not declare its access. Register it through the helper in "+
					"internal/api/routes.go with an Access — Public(), Requires() or Floor()", o)
		})
	}
}

// TestPERM001_FiresOnADeliberatelyBrokenOperation — the gate has been seen to fail.
//
// A gate nobody has watched fail is a gate nobody knows works, and this one is easy to get wrong
// in the direction that reports success: every case below is a shape that MUST produce a finding,
// so a refactor that quietly stops checking one is a red test rather than a green tick over
// nothing. The undeclared case is the first row on purpose — it is the whole point of law 6.
func TestPERM001_FiresOnADeliberatelyBrokenOperation(t *testing.T) {
	t.Parallel()

	schemes := map[string]bool{api.SchemePAT: true, api.SchemeSession: true}
	sessionOnly := []map[string][]string{{api.SchemeSession: {}}}

	tests := []struct {
		name string
		op   huma.Operation
		// path defaults to a non-plugin route; the plugin-pin case overrides it.
		path string
	}{
		{
			name: "declares nothing at all",
			op:   huma.Operation{OperationID: "newRoute", Security: sessionOnly},
		},
		{
			name: "no security declaration",
			op: huma.Operation{
				OperationID: "newRoute",
				Extensions:  map[string]any{api.ExtPermission: "plugin.publish"},
			},
		},
		{
			name: "both public and a permission",
			op: huma.Operation{
				OperationID: "newRoute",
				Security:    []map[string][]string{},
				Extensions: map[string]any{
					api.ExtPublic: true, api.ExtPermission: "plugin.publish",
				},
			},
		},
		{
			name: "public but requires a credential",
			op: huma.Operation{
				OperationID: "newRoute",
				Security:    sessionOnly,
				Extensions:  map[string]any{api.ExtPublic: true},
			},
		},
		{
			name: "a permission but no credential accepted",
			op: huma.Operation{
				OperationID: "newRoute",
				Security:    []map[string][]string{},
				Extensions:  map[string]any{api.ExtPermission: "plugin.publish"},
			},
		},
		{
			name: "a permission spelled as a scope",
			op: huma.Operation{
				OperationID: "newRoute",
				Security:    sessionOnly,
				Extensions:  map[string]any{api.ExtPermission: "plugin:publish"},
			},
		},
		{
			name: "a scheme the document does not define",
			op: huma.Operation{
				OperationID: "newRoute",
				Security:    []map[string][]string{{"basic": {}}},
				Extensions:  map[string]any{api.ExtPermission: "plugin.publish"},
			},
		},
		{
			name: "a scope spelled as a permission",
			op: huma.Operation{
				OperationID: "newRoute",
				Security:    []map[string][]string{{api.SchemePAT: {"plugin.publish"}}},
				Extensions:  map[string]any{api.ExtPermission: "plugin.publish"},
			},
		},
		{
			name: "acts on a plugin with a token and declares no plugin parameter",
			op: huma.Operation{
				OperationID: "publishRelease",
				Security: []map[string][]string{
					{api.SchemePAT: {"plugin:publish"}}, {api.SchemeSession: {}},
				},
				Extensions: map[string]any{api.ExtPermission: "plugin.publish"},
			},
			path: "/api/v1/plugins/{id}/releases",
		},
		{
			name: "capability floor that still takes a token",
			op: huma.Operation{
				OperationID: "newRoute",
				Security:    []map[string][]string{{api.SchemePAT: {"owner:manage"}}},
				Extensions: map[string]any{
					api.ExtPermission: "owner.manage", api.ExtPATForbidden: true,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			path := tt.path
			if path == "" {
				path = "/api/v1/new"
			}
			o := operation{path: path, method: "POST", op: &tt.op}
			require.NotEmpty(t, accessFindings(o, schemes),
				"PERM001 must reject this operation; it accepted it, so the gate is not checking "+
					"what it claims to")
		})
	}
}

// patCallable reports whether any security requirement admits a personal access token.
func patCallable(security []map[string][]string) bool {
	for _, req := range security {
		if _, ok := req[api.SchemePAT]; ok {
			return true
		}
	}
	return false
}

// declaredSchemes is the set of security schemes the document defines. A requirement naming
// anything else is a document that cannot be satisfied, which reads to a client author as "the
// auth is broken" rather than "the spec is wrong".
func declaredSchemes(t *testing.T) map[string]bool {
	t.Helper()

	spec := api.Spec()
	require.NotNil(t, spec.Components, "the document must declare its components")

	out := map[string]bool{}
	for name := range spec.Components.SecuritySchemes {
		out[name] = true
	}
	require.NotEmpty(t, out, "the document declares no security schemes")
	return out
}

// accessFindings returns everything wrong with one operation's access declaration, and is the
// whole of PERM001's judgement. It returns findings rather than asserting so that the gate and the
// test that proves the gate fires can run the same code over different inputs.
func accessFindings(o operation, schemes map[string]bool) []string {
	var found []string
	add := func(format string, args ...any) { found = append(found, fmt.Sprintf(format, args...)) }

	perm, hasPerm := o.op.Extensions[api.ExtPermission]
	public, isPublic := o.op.Extensions[api.ExtPublic]

	switch {
	case hasPerm && isPublic:
		add("declares both %s and %s; it is one or the other", api.ExtPermission, api.ExtPublic)
	case !hasPerm && !isPublic:
		add("declares neither %s nor %s", api.ExtPermission, api.ExtPublic)
	}

	// An ABSENT security declaration is the subtle one: in OpenAPI it inherits the document-level
	// default, so an operation that simply forgot becomes authenticated, or not, depending on a
	// setting in another file. `security: []` is how an operation says it needs nothing.
	if o.op.Security == nil {
		add("has no security declaration; use `security: []` to say it needs no credential")
	}

	if isPublic {
		if public != true {
			add("%s is %v rather than true", api.ExtPublic, public)
		}
		if len(o.op.Security) > 0 {
			add("is public and still carries a security requirement")
		}
		if _, floor := o.op.Extensions[api.ExtPATForbidden]; floor {
			add("is public; forbidding PATs on it says nothing")
		}
		return found
	}

	name, ok := perm.(string)
	if !ok {
		if hasPerm {
			add("declares a non-string permission %v", perm)
		}
		return found
	}
	if !authz.Permission(name).Valid() {
		add("declares %q, which is not spelled <resource>.<action>", name)
	}
	if len(o.op.Security) == 0 {
		add("requires %s but accepts no credential", name)
	}

	_, floor := o.op.Extensions[api.ExtPATForbidden]

	// A token-callable operation that acts on a plugin must say WHICH path parameter names it, or
	// a token's plugin pin has nothing to be compared against — and an unenforced pin fails open,
	// silently, behaving exactly like no pin at all. ADR-0005's containment argument rests on it.
	if !floor && strings.Contains(o.path, "/plugins/{") && patCallable(o.op.Security) {
		if _, ok := o.op.Extensions[api.ExtPluginParam].(string); !ok {
			add("acts on a plugin and is callable with a token, but declares no %s; "+
				"a token pinned to one plugin could use it on another", api.ExtPluginParam)
		}
	}

	for _, req := range o.op.Security {
		for scheme, scopes := range req {
			if !schemes[scheme] {
				add("requires the %q scheme, which components.securitySchemes does not define",
					scheme)
			}
			// The capability floor: minting tokens, changing owners, setting trust. A token that
			// could perform one would be equivalent to the account, so no scope reaches it.
			if floor && scheme == api.SchemePAT {
				add("is capability-floor and still accepts a PAT")
			}
			for _, s := range scopes {
				if !authz.Scope(s).Valid() {
					add("names scope %q, which is not spelled <family>:<verb>", s)
				}
			}
		}
	}
	return found
}

// TestPERM001_RouteRegistration_GoesThroughTheAccessDeclaringHelper — the other half.
//
// The document-walking test above can only see operations that were registered. It cannot see one
// registered around the side of the helper, because such a route would still appear in the
// document — with no extensions, which the test above WOULD catch — or, worse, be registered on
// the mux directly and appear in no document at all. This closes the second case: within
// internal/api, huma is called from exactly one file, the one whose signature demands an Access.
func TestPERM001_RouteRegistration_GoesThroughTheAccessDeclaringHelper(t *testing.T) {
	t.Parallel()

	var apiFiles []goFile
	for _, g := range parseTree(t) {
		if g.inTree("internal/api/") {
			apiFiles = append(apiFiles, g)
		}
	}
	requireNotVacant(t, apiFiles, "PERM001")

	// The helper. Huma is called from here and nowhere else in the package.
	const helper = "internal/api/routes.go"

	registrars := map[string]bool{
		"Register": true, "AutoRegister": true, "Handle": true,
		"Get": true, "Post": true, "Put": true, "Patch": true, "Delete": true,
	}

	var bad []string
	for _, g := range apiFiles {
		if g.rel() == helper {
			continue
		}
		local, ok := g.localName("github.com/danielgtaylor/huma/v2")
		if !ok {
			continue
		}
		selectorCalls(g.file, func(recv, sel string, pos token.Pos) {
			if recv == local && registrars[sel] {
				bad = append(bad, g.fset.Position(pos).String()+" ("+recv+"."+sel+")")
			}
		})
	}
	require.Empty(t, bad,
		"PERM001: a route registered without going through register() in "+helper+", which is "+
			"the only signature that requires an Access declaration")
}

// --- OAPI001 ----------------------------------------------------------------------------------

// operationIDRe is lowerCamelCase: a leading lowercase letter and no separators.
var operationIDRe = regexp.MustCompile(`^[a-z][a-zA-Z0-9]*$`)

// TestOAPI001_OperationIDs_AreUniqueLowerCamelCase — an OperationID is public API.
//
// The generated SDK's method name derives from it, so renaming one breaks every caller that
// upgrades, silently, at compile time in their language rather than ours. Duplicates are worse: a
// generator either overwrites one method with another or fails, and which of those you get depends
// on the generator.
func TestOAPI001_OperationIDs_AreUniqueLowerCamelCase(t *testing.T) {
	t.Parallel()

	ops := operations(t)
	require.NotEmpty(t, ops, "OAPI001 inspected no operations; the gate is vacant, not passing")

	seen := map[string]string{}
	for _, o := range ops {
		require.NotEmpty(t, o.op.OperationID,
			"OAPI001: %s has no OperationID; the SDK method name is derived from it", o)
		require.Regexp(t, operationIDRe, o.op.OperationID,
			"OAPI001: %s has OperationID %q, which is not lowerCamelCase (canonical §6)",
			o, o.op.OperationID)

		if prev, dup := seen[o.op.OperationID]; dup {
			require.Failf(t, "duplicate OperationID",
				"OAPI001: %q is used by both %s and %s", o.op.OperationID, prev, o)
		}
		seen[o.op.OperationID] = o.String()
	}
}

// TestOAPI001_PinnedPaths_AreInTheDocument — the two URLs ADR-0009 makes permanent.
//
// They are asserted against the document rather than against the constants, because the constants
// being right is not the same as the routes being registered at them. A refactor that moved either
// under BasePath would strand every install that recorded it as provenance and every published
// plugin that compiled it into PluginMeta.update_url.
func TestOAPI001_PinnedPaths_AreInTheDocument(t *testing.T) {
	t.Parallel()

	paths := map[string]bool{}
	for _, o := range operations(t) {
		paths[o.path] = true
	}

	for _, pinned := range []string{"/index.json", "/plugins/{id}/index.json"} {
		require.True(t, paths[pinned],
			"OAPI001: %s is a permanent URL (ADR-0009) and is not in the document", pinned)
		require.False(t, strings.HasPrefix(pinned, api.BasePath),
			"OAPI001: %s must stay OUTSIDE the versioned API; its shape is pinned by a parser "+
				"we do not own", pinned)
	}
}
