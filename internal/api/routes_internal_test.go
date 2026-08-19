package api

import (
	"context"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
)

// Every route this service serves today is public, so the authenticated halves of Access — the
// scoped PAT requirement and the capability floor — would otherwise be code with no caller until
// Phase 2 lands identity on top of them. These register synthetic operations through the same
// helper the real routes use and read back what the document says, so the rendering is exercised
// now rather than discovered to be wrong by the first endpoint that depends on it.
//
// An internal test because Access renders through unexported methods. The gate that reads the
// result lives in test/repo/openapi_test.go and sees only the document.

func synthetic(t *testing.T, access Access, id string) *huma.Operation {
	t.Helper()

	api := newHumaAPI(http.NewServeMux())
	register(api, access, huma.Operation{
		OperationID: id,
		Method:      http.MethodPost,
		Path:        BasePath + "/synthetic",
		Summary:     "A route that exists only in this test",
	}, func(context.Context, *struct{}) (*struct{}, error) { return nil, nil })

	item := api.OpenAPI().Paths[BasePath+"/synthetic"]
	require.NotNil(t, item, "the operation must be in the document")
	require.NotNil(t, item.Post)
	return item.Post
}

func TestRegister_Public_DeclaresNoCredentialExplicitly(t *testing.T) {
	t.Parallel()

	op := synthetic(t, Public(), "syntheticPublic")

	require.Equal(t, true, op.Extensions[ExtPublic])
	require.NotContains(t, op.Extensions, ExtPermission)
	require.NotNil(t, op.Security, "an absent security list inherits the document default")
	require.Empty(t, op.Security, "public means the requirement list is present and empty")
}

func TestRegister_Requires_AcceptsAScopedTokenOrASession(t *testing.T) {
	t.Parallel()

	op := synthetic(t, Requires("plugin.publish", "plugin:publish"), "syntheticPublish")

	require.Equal(t, "plugin.publish", op.Extensions[ExtPermission])
	require.NotContains(t, op.Extensions, ExtPublic)
	require.NotContains(t, op.Extensions, ExtPATForbidden)

	// Two alternatives, not one requirement with two schemes: a caller satisfies either.
	require.Equal(t, []map[string][]string{
		{SchemePAT: {"plugin:publish"}},
		{SchemeSession: {}},
	}, op.Security)
}

func TestRegister_RequiresWithoutScopes_IsSessionOnlyByOmission(t *testing.T) {
	t.Parallel()

	op := synthetic(t, Requires("release.approve"), "syntheticApprove")

	require.Equal(t, "release.approve", op.Extensions[ExtPermission])
	require.NotContains(t, op.Extensions, ExtPATForbidden,
		"no scope names this operation yet, which is not the same as refusing tokens forever")
	require.Equal(t, []map[string][]string{{SchemeSession: {}}}, op.Security)
}

// TestRegister_Floor_RefusesTokensOutLoud — the capability floor.
//
// Minting tokens, changing owners and setting trust are session-only because a token that could
// perform one would be equivalent to the account. The refusal is declared rather than implied by
// the absence of a scope: "there is no scope for this yet" and "no token may ever do this" look
// identical in a document that only omits things, and they are opposite promises.
func TestRegister_Floor_RefusesTokensOutLoud(t *testing.T) {
	t.Parallel()

	op := synthetic(t, Floor("owner.manage"), "syntheticTransferOwner")

	require.Equal(t, "owner.manage", op.Extensions[ExtPermission])
	require.Equal(t, true, op.Extensions[ExtPATForbidden])
	require.Equal(t, []map[string][]string{{SchemeSession: {}}}, op.Security)
	for _, req := range op.Security {
		require.NotContains(t, req, SchemePAT)
	}
}

// TestRegister_FloorWithScopes_StillRefusesTokens — scopes passed to Floor cannot re-open it.
//
// Floor takes no scopes, so this is really a test that the two constructors cannot be combined
// into something that says "capability floor" and accepts a token anyway. If that ever became
// representable, the gate in test/repo would catch it — but a type that cannot express it is
// better than a test that catches it.
func TestRegister_FloorWithScopes_StillRefusesTokens(t *testing.T) {
	t.Parallel()

	a := Floor("token.mint")
	a.scopes = []authz.Scope{"token:mint"}

	require.NotContains(t, a.security()[0], SchemePAT,
		"a capability-floor operation accepts a session and nothing else, whatever scopes are set")
}
