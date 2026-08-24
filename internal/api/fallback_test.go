package api_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
)

// GATE ROUTE002: a path this service does not route answers 404, and one it routes by another
// method answers 405 — both as problem documents.
//
// THIS GATE EXISTS BECAUSE ITS ABSENCE SHIPPED, AND WAS MEASURED ON THE LIVE DEPLOYMENT. `GET /`
// is a Go ServeMux CATCH-ALL, so registering the public directory at `/` quietly made every
// unrouted GET answer 200 with the home page:
//
//	/definitely-not-a-page-xyz -> 200, the directory
//	/openapi.json              -> 200, the directory
//	/docs                      -> 200, the directory
//	/tokens                    -> 200, the directory
//
// Only the paths whose middleware refused first — `/review`, `/account` — told the truth. That is
// the confident mistake AGENTS.md names, and its cost is not aesthetic: while it was live, nobody
// investigating the deployment could tell a route that is missing from a route that is there, so
// "is the review surface deployed?" had no answer from the outside.
//
// The 405 half is [issue #18], open since before the directory existed: net/http's own 404 and 405
// bodies are `text/plain`, which docs/api/errors.md says no error response is, and which left
// `method_not_allowed` in the closed enum unreachable by any request at all.
//
// [issue #18]: https://github.com/prokopto-dev/nparse-plugin-regserve/issues/18

// routedServer is a build with EVERY route registered, which is what this gate needs: a fallback
// is only correct relative to the whole set of patterns it sits behind, and a server missing the
// directory would pass the 404 assertions for the wrong reason — there would be no catch-all to
// shadow.
func routedServer(t *testing.T) *httptest.Server {
	t.Helper()

	dir := &fakeDirectory{fakeCatalogue: fakeCatalogue{plugins: []registry.Plugin{testPlugin("merchant-mode")}}}
	srv := httptest.NewServer(api.New(api.Config{
		Catalogue: dir,
		Directory: dir,
		Readiness: failingReady{},
		Authn:     &fakeAuthn{},
		Login:     &fakeLogin{},
		Sessions:  &fakeSessions{},
		Providers: identity.NewRegistry(stubProvider{}),
		Tokens:    &fakeTokens{},
		Ownership: &fakeOwnership{},
		Claimer:   unreachableDeps{},
		Publisher: unreachableDeps{},
		Queue:     &fakeQueue{},
		Reviewers: &fakeReviewers{},
		Trust:     unreachableDeps{},
	}))
	t.Cleanup(srv.Close)
	return srv
}

// unreachableDeps stands in for the three services no request in this file reaches. They are wired
// because a route is only registered when its dependency is present, and this gate is about the
// WHOLE pattern set — a build missing the publish route would pass the 405 assertion for it by
// answering 404 instead.
type unreachableDeps struct{}

func (unreachableDeps) Publish(context.Context, release.Request) (release.Outcome, error) {
	return release.Outcome{}, errUnreachableDep
}

func (unreachableDeps) ClaimID(context.Context, ownership.Claim, string) error {
	return errUnreachableDep
}

func (unreachableDeps) SetTrust(context.Context, string, release.Trust, string, string) error {
	return errUnreachableDep
}

func (unreachableDeps) TrustOf(context.Context, string) (release.Trust, error) {
	return "", errUnreachableDep
}

// errUnreachableDep is returned by the stubs above. Reaching it means this gate stopped testing
// routing and started testing a handler, which is a different file's job.
var errUnreachableDep = errors.New("this gate reaches routing, never a handler")

// do sends one request and reads the whole response. Not `fetch`, because this gate is about
// methods as much as paths.
func do(t *testing.T, srv *httptest.Server, method, path string) response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, srv.URL+path, nil)
	require.NoError(t, err)

	// This server's own client, never a bare &http.Client{}.
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return response{status: resp.StatusCode, header: resp.Header.Clone(), body: body}
}

func TestROUTE002_APathThisServiceDoesNotRoute_Is404AndNotTheHomePage(t *testing.T) {
	t.Parallel()

	srv := routedServer(t)

	// The exact paths measured returning 200 on the live deployment, plus the two shapes that
	// would come back if `/` were a catch-all again: something below a real page, and a real page
	// with a trailing slash.
	for _, path := range []string{
		"/definitely-not-a-page-xyz",
		"/openapi.json",
		"/api/v1/openapi.json",
		"/docs",
		"/tokens",
		"/schemas/Problem.json",
		"/review/",
		"/account/nothing-here",
		"/plugins/merchant-mode/nothing-here",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			resp := do(t, srv, http.MethodGet, path)

			require.Equal(t, http.StatusNotFound, resp.status,
				"%s is not a route and must not be answered; body was %s", path, resp.body)

			// The body assertion is the one that would have caught the defect. A 404 status with
			// the directory in the body would be a different, quieter version of the same lie.
			require.NotContains(t, string(resp.body), "<html",
				"an unrouted path must not be answered with a page")

			p := problemOf(t, resp)
			require.Equal(t, api.CodeNotFound, p.Code)
		})
	}
}

// TestROUTE002_TheRootItself_IsStillTheDirectory is the other side of the boundary.
//
// A fallback that answered 404 to everything would pass the test above while taking the front page
// down, so the root and one page below it are asserted in the same run.
func TestROUTE002_TheRootItself_IsStillTheDirectory(t *testing.T) {
	t.Parallel()

	srv := routedServer(t)

	for _, path := range []string{"/", "/plugins/merchant-mode", api.PathIndex, "/healthz"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			require.Equal(t, http.StatusOK, do(t, srv, http.MethodGet, path).status,
				"%s is a route and must still answer", path)
		})
	}
}

// TestROUTE002_AHeadRequest_IsStillServedFromTheGetRoute pins the part of the fix that is easiest
// to break silently.
//
// The home page is registered on the mux as `/{$}` rather than `/`, and a rewrite that got the
// pattern wrong would show up first as HEAD failing — Go serves HEAD from a GET pattern, and every
// uptime check in front of this service uses it.
func TestROUTE002_AHeadRequest_IsStillServedFromTheGetRoute(t *testing.T) {
	t.Parallel()

	srv := routedServer(t)

	for _, path := range []string{"/", api.PathIndex, "/healthz"} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, http.StatusOK, do(t, srv, http.MethodHead, path).status)
		})
	}
}

// TestROUTE002_ARoutedPathWithTheWrongMethod_Is405WithAllow closes issue #18's half.
func TestROUTE002_ARoutedPathWithTheWrongMethod_Is405WithAllow(t *testing.T) {
	t.Parallel()

	srv := routedServer(t)

	tests := []struct {
		name      string
		method    string
		path      string
		wantAllow string
	}{
		{
			name: "the index is read-only", method: http.MethodPost, path: api.PathIndex,
			// HEAD is named even though nothing declared it: Go's ServeMux serves a HEAD request
			// from a GET pattern, so an Allow that omitted it would describe a rule the router
			// does not follow.
			wantAllow: "GET, HEAD",
		},
		{
			name: "publishing is a POST", method: http.MethodGet,
			path: api.BasePath + "/plugins/merchant-mode/releases", wantAllow: "POST",
		},
		{
			name: "the root is read-only", method: http.MethodDelete, path: "/",
			wantAllow: "GET, HEAD",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp := do(t, srv, tc.method, tc.path)

			require.Equal(t, http.StatusMethodNotAllowed, resp.status,
				"body was %s", resp.body)
			require.Equal(t, tc.wantAllow, resp.header.Get("Allow"),
				"RFC 9110 requires Allow, and it is the only actionable part of a 405")

			p := problemOf(t, resp)
			require.Equal(t, api.CodeMethodNotAllowed, p.Code,
				"method_not_allowed is in the closed enum and must be reachable by a request")
		})
	}
}
