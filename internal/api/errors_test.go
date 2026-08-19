package api_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

// Adopting a framework means it now raises errors of its own — a body it could not parse, a
// parameter that failed validation, a panic it recovered. Those responses reach clients too, so
// they have to be the same closed-enum problem document our handlers return. These tests are about
// the errors WE never wrote.

// TestErrors_HumaGeneratedError_IsAProblemWithACode — huma.NewError is replaced, so an error Huma
// raises is a Problem and carries a code from the closed enum rather than Huma's own model.
func TestErrors_HumaGeneratedError_IsAProblemWithACode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		status   int
		wantCode api.Code
	}{
		{name: "not found", status: http.StatusNotFound, wantCode: api.CodeNotFound},
		{name: "unauthorized", status: http.StatusUnauthorized, wantCode: api.CodeUnauthorized},
		{name: "forbidden", status: http.StatusForbidden, wantCode: api.CodeForbidden},
		{name: "conflict", status: http.StatusConflict, wantCode: api.CodeConflict},
		{
			name:     "method not allowed",
			status:   http.StatusMethodNotAllowed,
			wantCode: api.CodeMethodNotAllowed,
		},
		{
			name:     "service unavailable",
			status:   http.StatusServiceUnavailable,
			wantCode: api.CodeServiceUnavailable,
		},
		// The framework's own 4xx have no code of their own, and the enum is closed rather than
		// growing one per framework status. They are all the same thing to a client: understood,
		// wrong, fix it and resend.
		{name: "validation failed", status: 422, wantCode: api.CodeInvalidRequest},
		{name: "payload too large", status: 413, wantCode: api.CodeInvalidRequest},
		{name: "unsupported media type", status: 415, wantCode: api.CodeInvalidRequest},
		{name: "not acceptable", status: 406, wantCode: api.CodeInvalidRequest},
		{name: "bad gateway", status: 502, wantCode: api.CodeInternalError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := huma.NewError(tt.status, "something went wrong")

			var p *api.Problem
			require.True(t, errors.As(err, &p),
				"huma.NewError must build our Problem, or a framework error would be shaped "+
					"differently from every error our handlers return")
			require.Equal(t, tt.wantCode, p.Code)
			require.Equal(t, tt.status, p.GetStatus())
			require.Equal(t, "application/problem+json", p.ContentType("application/json"))
		})
	}
}

// TestErrors_ServerError_NeverEchoesTheCause is the one that matters for disclosure.
//
// When a handler returns something that is not a StatusError, Huma calls the error constructor
// with the underlying error attached: `NewErrorWithContext(ctx, 500, "unexpected error occurred",
// err)`. That error is ours — a driver message, a file path, a query — and the response goes to an
// unauthenticated caller. A 500 says nothing but the request id.
func TestErrors_ServerError_NeverEchoesTheCause(t *testing.T) {
	t.Parallel()

	err := huma.NewError(http.StatusInternalServerError, "unexpected error occurred",
		errors.New("open /var/lib/regserve/regserve.db: permission denied"))

	var p *api.Problem
	require.True(t, errors.As(err, &p))
	require.Equal(t, api.CodeInternalError, p.Code)
	require.NotContains(t, p.Detail, "regserve.db")
	require.NotContains(t, p.Detail, "permission denied")
	require.Contains(t, p.Detail, "X-Request-Id",
		"a 500 with no detail at all leaves the reporter nothing to quote")
}

// TestErrors_ProblemDocument_HasTheDocumentedShape — the members docs/api/errors.md shows, and no
// others. A client that switches on `code` is switching on a member that has to be there.
func TestErrors_ProblemDocument_HasTheDocumentedShape(t *testing.T) {
	t.Parallel()

	srv := serve(t, fakeCatalogue{err: errors.New("database is on fire")})
	resp := fetch(t, srv, api.PathIndex, "")

	require.Equal(t, http.StatusInternalServerError, resp.status)
	require.Equal(t, "application/problem+json", resp.header.Get("Content-Type"))

	var members map[string]any
	require.NoError(t, json.Unmarshal(resp.body, &members))

	for _, member := range []string{"type", "title", "status", "code", "detail"} {
		require.Contains(t, members, member)
	}
	require.Len(t, members, 5, "an unexpected member is a shape change: %v", members)

	require.Equal(t, "internal_error", members["code"])
	require.Equal(t, float64(http.StatusInternalServerError), members["status"])
	require.Contains(t, members["type"], "docs/api/errors.md#internal_error",
		"RFC 9457's type must resolve to the page documenting the code")
	require.NotContains(t, string(resp.body), "on fire",
		"an internal error's detail must not leak the underlying failure to the public index")
}

// TestErrors_HandlerProblem_SetsTheStatusItDeclares — the handler returns an error and never
// touches an http.ResponseWriter (canonical §6), so the status on the wire comes from the problem
// document. If those two could disagree, "never 200 with an error body" would be a hope.
func TestErrors_HandlerProblem_SetsTheStatusItDeclares(t *testing.T) {
	t.Parallel()

	srv := serve(t, fakeCatalogue{plugins: []registry.Plugin{testPlugin("alpha")}})
	resp := fetch(t, srv, "/plugins/never-existed/index.json", "")

	var p api.Problem
	require.NoError(t, json.Unmarshal(resp.body, &p))
	require.Equal(t, p.Status, resp.status,
		"the status line and the document's status member must be the same number")
	require.Equal(t, http.StatusNotFound, resp.status)
}
