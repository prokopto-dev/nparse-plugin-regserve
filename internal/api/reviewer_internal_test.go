package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
)

// The reviewer check's failure paths, over HTTP.
//
// An INTERNAL test because it registers a synthetic reviewer-only route through the unexported
// helper. api.New refuses to register the real queue without a reviewer check, which is the FIRST
// defence; what is asserted here is the SECOND — that the middleware itself refuses rather than
// allows when it cannot answer the question. Both are needed, because the first one is a
// convention about how one function is written and the second is what happens if somebody adds a
// route that slips past it.

// failingReviewers cannot answer. A database that has gone away looks exactly like this.
type failingReviewers struct{ err error }

func (f failingReviewers) IsReviewer(context.Context, string) (bool, error) { return false, f.err }

// alwaysReviewers answers yes, for the case that proves a refusal is about the check and not about
// the route being unreachable.
type alwaysReviewers struct{}

func (alwaysReviewers) IsReviewer(context.Context, string) (bool, error) { return true, nil }

func TestReviewerCheck_WhenItCannotAnswer_TheRequestIsRefused(t *testing.T) {
	t.Parallel()

	principal := auth.Principal{
		AccountID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", DisplayName: "somebody",
		SessionID: "a-session",
	}

	tests := []struct {
		name      string
		reviewers ReviewerCheck
		want      int
	}{
		{
			// A reviewer-only route on a build with no way to decide who reviews. 503 because the
			// honest statement is "this instance cannot serve this", exactly as for a nil
			// Authenticator — and emphatically NOT 200.
			name:      "no reviewer check wired",
			reviewers: nil,
			want:      http.StatusServiceUnavailable,
		},
		{
			// "We could not check" must never resolve to "allow". The cause goes to the log; the
			// caller gets the fixed sentence.
			name:      "the check itself fails",
			reviewers: failingReviewers{err: errCheckFailed},
			want:      http.StatusInternalServerError,
		},
		{
			// The other side of the boundary: a check that answers yes lets the request through,
			// so the refusals above are about the check rather than about an unreachable route.
			name:      "the check answers yes",
			reviewers: alwaysReviewers{},
			// 204 rather than 200: the synthetic handler returns an empty body, and Huma renders
			// that as No Content. What matters is that it REACHED the handler.
			want: http.StatusNoContent,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv := reviewerServer(t, principal, tc.reviewers)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				srv.URL+"/api/v1/synthetic-review", nil)
			require.NoError(t, err)

			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			defer func() { require.NoError(t, resp.Body.Close()) }()

			require.Equal(t, tc.want, resp.StatusCode)
		})
	}
}

var errCheckFailed = &Problem{Code: CodeInternalError, Detail: "the database is not answering"}

// reviewerServer serves one synthetic reviewer-only route.
func reviewerServer(t *testing.T, principal auth.Principal, reviewers ReviewerCheck) *httptest.Server {
	t.Helper()

	mux := http.NewServeMux()
	api := newHumaAPI(mux)
	api.UseMiddleware(authMiddleware(api, pinnedAuthn{principal: principal}, reviewers))

	register(api, Floor("release.review").Reviewer(), huma.Operation{
		OperationID: "syntheticReview",
		Method:      http.MethodGet,
		Path:        "/api/v1/synthetic-review",
		Summary:     "A reviewer-only route that exists only in this test",
	}, func(context.Context, *struct{}) (*struct{}, error) { return &struct{}{}, nil })

	srv := httptest.NewServer(RefuseTokenInQuery(mux))
	t.Cleanup(srv.Close)
	return srv
}
