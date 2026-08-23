package api_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
)

// The review pages.
//
// What is left to get wrong once internal/review is covered in its own package is the surface: who
// may reach these pages, whether a form post without a session-bound token is refused before
// anything is read from it, and whether the page tells a reviewer the things they need in order
// not to approve something they should not.
//
// The first of those is the one that matters most. Moderation decides what every installed client
// downloads, and there are three ways to get it wrong: letting a token in, letting any signed-in
// account in, and letting nobody in at all — the last of which passes the first two tests while
// being a broken deployment.

// testReleaseID is a well-formed ULID: 26 Crockford base32 characters, first below '8' so the
// timestamp fits 128 bits. It has to be real, because the decide handler parses it before putting
// it in a Location header — an id assembled into a redirect from unvalidated input is a header
// somebody else gets to write.
const testReleaseID = "01JCX0MPZZZZZZZZZZZZZZZZZZ"

// fakeQueue is api.ReviewQueue with the answers set per test, recording what it was asked.
type fakeQueue struct {
	waiting []review.Waiting
	detail  review.Detail

	listErr   error
	detailErr error
	decideErr error
	verified  bool

	sawApprove []string
	sawReject  []string
	sawReverify
}

// sawReverify is embedded rather than a field so a test can read it without the struct growing a
// fourth slice for a call that takes no note.
type sawReverify struct{ reverified []string }

func (f *fakeQueue) List(context.Context) ([]review.Waiting, error) {
	return f.waiting, f.listErr
}

func (f *fakeQueue) Detail(_ context.Context, id string) (review.Detail, error) {
	if f.detailErr != nil {
		return review.Detail{}, f.detailErr
	}
	d := f.detail
	d.ReleaseID = id
	return d, nil
}

func (f *fakeQueue) Approve(_ context.Context, id, _, note string) (review.Decision, error) {
	f.sawApprove = append(f.sawApprove, id+"|"+note)
	return review.Decision{ReleaseID: id}, f.decideErr
}

func (f *fakeQueue) Reject(_ context.Context, id, _, reason string) (review.Decision, error) {
	f.sawReject = append(f.sawReject, id+"|"+reason)
	return review.Decision{ReleaseID: id}, f.decideErr
}

func (f *fakeQueue) Reverify(_ context.Context, id, _ string) (review.Verification, error) {
	f.reverified = append(f.reverified, id)
	return review.Verification{ReleaseID: id, Verified: f.verified}, f.decideErr
}

// fakeReviewers answers the two questions the surfaces ask: whether this account may review, and
// whether anybody may.
type fakeReviewers struct {
	yes bool
	err error

	// unconfigured is the deployment with REGSERVE_REVIEWERS empty. It is a separate field rather
	// than being derived from `yes`, because "you are not a reviewer" and "there are no reviewers"
	// are exactly the two states these pages have to be able to tell apart.
	unconfigured bool
}

func (f *fakeReviewers) IsReviewer(context.Context, string) (bool, error) { return f.yes, f.err }

func (f *fakeReviewers) Configured() bool { return !f.unconfigured }

// reviewHarness is a running review surface plus the fakes behind it.
type reviewHarness struct {
	srv       *httptest.Server
	authn     *fakeAuthn
	sessions  *fakeSessions
	queue     *fakeQueue
	reviewers *fakeReviewers
}

func newReviewHarness(t *testing.T, mutate ...func(h *reviewHarness)) *reviewHarness {
	t.Helper()

	h := &reviewHarness{
		authn:     &fakeAuthn{principal: signedIn()},
		sessions:  &fakeSessions{},
		reviewers: &fakeReviewers{yes: true},
		queue: &fakeQueue{
			waiting: []review.Waiting{{
				ReleaseID: testReleaseID, PluginID: "merchant-mode", PluginName: "Merchant Mode",
				Version: "1.0.0", ArtifactURL: "https://example.com/mm.zip",
				SHA256: strings.Repeat("c", 64), Verified: true, FirstRelease: true,
				SubmittedAt: time.Unix(1, 0).UTC(), Note: "awaiting human review",
			}},
			detail: review.Detail{
				Waiting: review.Waiting{
					PluginID: "merchant-mode", PluginName: "Merchant Mode", Version: "1.0.0",
					ArtifactURL: "https://example.com/mm.zip", SHA256: strings.Repeat("c", 64),
					Verified: true, FirstRelease: true, SubmittedAt: time.Unix(1, 0).UTC(),
					Note: "2 reasons: ...",
				},
				State:      "pending",
				Source:     "publish",
				Quarantine: []string{"the submitted sha256 does not match the artifact this server fetched"},
				Events: []review.Event{{
					At: time.Unix(1, 0).UTC(), Action: "plugin.publish", Actor: "prokopto-dev",
					Detail: `{"verified":true}`,
				}},
			},
		},
	}
	for _, m := range mutate {
		m(h)
	}

	h.srv = httptest.NewServer(api.New(api.Config{
		Authn:     h.authn,
		Login:     &fakeLogin{},
		Sessions:  h.sessions,
		Providers: identity.NewRegistry(stubProvider{}),
		Tokens:    &fakeTokens{},
		Ownership: &fakeOwnership{},
		Queue:     h.queue,
		Reviewers: h.reviewers,
	}))
	t.Cleanup(h.srv.Close)
	return h
}

func (h *reviewHarness) csrf() string { return h.sessions.CSRFToken(signedIn()) }

func (h *reviewHarness) do(t *testing.T, method, path string, form url.Values) response {
	t.Helper()

	body := strings.NewReader("")
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(t.Context(), method, h.srv.URL+path, body)
	require.NoError(t, err)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	client := h.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	raw := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, rerr := resp.Body.Read(buf)
		raw = append(raw, buf[:n]...)
		if rerr != nil {
			break
		}
	}
	return response{status: resp.StatusCode, header: resp.Header.Clone(), body: raw}
}

// reviewRoutes is every page on this surface, so a test that walks them cannot miss one that was
// added later without a matching access declaration.
func reviewRoutes() []struct {
	method string
	path   string
	form   url.Values
} {
	return []struct {
		method string
		path   string
		form   url.Values
	}{
		{method: http.MethodGet, path: "/review"},
		{method: http.MethodGet, path: "/review/releases/" + testReleaseID},
		{
			method: http.MethodPost,
			path:   "/review/releases/" + testReleaseID + "/decide",
			form:   url.Values{"action": {"approve"}},
		},
	}
}

// TestReviewPages_AreSessionOnlyAndReviewerOnly — the three ways this could be wrong.
func TestReviewPages_AreSessionOnlyAndReviewerOnly(t *testing.T) {
	t.Parallel()

	t.Run("a token carrying every scope is refused at the floor", func(t *testing.T) {
		t.Parallel()

		h := newReviewHarness(t, func(h *reviewHarness) {
			h.authn.principal = auth.Principal{
				AccountID: "acct", TokenID: "tok", Scopes: authz.Scopes(),
			}
		})

		for _, r := range reviewRoutes() {
			resp := h.do(t, r.method, r.path, r.form)
			require.Equal(t, http.StatusForbidden, resp.status, "%s %s", r.method, r.path)

			// Refused BEFORE the reviewer question is asked. A token belonging to a reviewer must
			// be refused for being a token, not for belonging to the wrong person — moderation
			// delegated to a CI credential is the failure, whoever minted it.
			require.Contains(t, string(resp.body), "session-only", "%s %s", r.method, r.path)
		}
		require.Empty(t, h.queue.sawApprove, "no token may reach the queue at all")
	})

	t.Run("a signed-in account that is not a reviewer is refused", func(t *testing.T) {
		t.Parallel()

		h := newReviewHarness(t, func(h *reviewHarness) { h.reviewers.yes = false })

		for _, r := range reviewRoutes() {
			resp := h.do(t, r.method, r.path, r.form)
			require.Equal(t, http.StatusForbidden, resp.status, "%s %s", r.method, r.path)
			require.Contains(t, string(resp.body), "operates the deployment", "%s %s", r.method, r.path)
		}
		require.Empty(t, h.queue.sawApprove)
	})

	t.Run("nobody at all is refused", func(t *testing.T) {
		t.Parallel()

		h := newReviewHarness(t, func(h *reviewHarness) { h.authn.err = auth.ErrNoCredential })
		for _, r := range reviewRoutes() {
			require.Equal(t, http.StatusUnauthorized, h.do(t, r.method, r.path, r.form).status,
				"%s %s", r.method, r.path)
		}
	})

	t.Run("a reviewer's session reaches every page", func(t *testing.T) {
		t.Parallel()

		h := newReviewHarness(t)
		for _, r := range reviewRoutes() {
			resp := h.do(t, r.method, r.path, withCSRF(r.form, h.csrf()))
			require.Contains(t, []int{http.StatusOK, http.StatusSeeOther}, resp.status,
				"a middleware that refused everybody would pass every test above: %s %s",
				r.method, r.path)
		}
	})
}

// withCSRF adds the session's token to a form, leaving a nil form nil.
func withCSRF(form url.Values, token string) url.Values {
	if form == nil {
		return nil
	}
	out := url.Values{}
	for k, v := range form {
		out[k] = v
	}
	out.Set(auth.CSRFFieldName, token)
	return out
}

// TestReviewQueuePage_ShowsWhatIsWaiting.
func TestReviewQueuePage_ShowsWhatIsWaiting(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t)
	resp := h.do(t, http.MethodGet, "/review", nil)

	require.Equal(t, http.StatusOK, resp.status)
	require.Equal(t, "text/html; charset=utf-8", resp.header.Get("Content-Type"))
	require.Equal(t, "private, no-store", resp.header.Get("Cache-Control"),
		"a moderation page must never be held by a shared cache")

	body := string(resp.body)
	require.Contains(t, body, "merchant-mode")
	require.Contains(t, body, "first release of this id",
		"the first appearance of an id is the strongest signal in the queue")
	require.Contains(t, body, "/review/releases/"+testReleaseID)
}

// TestReviewQueuePage_AnUnverifiableRelease_IsCalledOut — the one a reviewer must not wave through.
func TestReviewQueuePage_AnUnverifiableRelease_IsCalledOut(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t, func(h *reviewHarness) {
		h.queue.waiting[0].Verified = false
		h.queue.waiting[0].SHA256 = ""
	})

	body := string(h.do(t, http.MethodGet, "/review", nil).body)
	require.Contains(t, body, "never checked")
}

// TestReviewReleasePage_ShowsWhyItIsHere — the page's whole job.
func TestReviewReleasePage_ShowsWhyItIsHere(t *testing.T) {
	t.Parallel()

	const claimed = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	h := newReviewHarness(t, func(h *reviewHarness) {
		h.queue.detail.SubmittedSHA256 = claimed
		h.queue.detail.Notes = "Fixed the price graph."
	})

	body := string(h.do(t, http.MethodGet, "/review/releases/"+testReleaseID, nil).body)

	require.Contains(t, body, "the submitted sha256 does not match",
		"every quarantine rule that fired must be on the page")
	require.Contains(t, body, strings.Repeat("c", 64), "the hash this server computed")
	require.Contains(t, body, claimed, "the hash the submitter claimed, because they disagree")
	require.Contains(t, body, "This is not the hash above")
	require.Contains(t, body, "Fixed the price graph.",
		"a reviewer sees the notes that will be published to every client")
	require.Contains(t, body, "plugin.publish", "the audit trail is on the page")
}

// TestReviewReleasePage_WithNoMismatch_ShowsNoSubmittedHash.
func TestReviewReleasePage_WithNoMismatch_ShowsNoSubmittedHash(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t)
	body := string(h.do(t, http.MethodGet, "/review/releases/"+testReleaseID, nil).body)

	require.NotContains(t, body, "Submitted sha256",
		"the claimed hash is kept only on a mismatch; a row for it otherwise would be a row with "+
			"nothing in it")
}

// TestReviewReleasePage_AnUnverifiedRelease_DoesNotOfferApproval.
//
// The database refuses to approve a release with no hash, so offering the button would send a
// reviewer into a constraint violation. The page says why instead.
func TestReviewReleasePage_AnUnverifiedRelease_DoesNotOfferApproval(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t, func(h *reviewHarness) {
		h.queue.detail.Verified = false
		h.queue.detail.SHA256 = ""
	})

	body := string(h.do(t, http.MethodGet, "/review/releases/"+testReleaseID, nil).body)
	require.Contains(t, body, "the artifact was never fetched")
	require.Contains(t, body, `value="approve" disabled`)
	require.Contains(t, body, `value="reverify"`, "re-verification is the way out")
}

// TestReviewReleasePage_ADecidedRelease_OffersNothing.
func TestReviewReleasePage_ADecidedRelease_OffersNothing(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t, func(h *reviewHarness) { h.queue.detail.State = "approved" })

	body := string(h.do(t, http.MethodGet, "/review/releases/"+testReleaseID, nil).body)
	require.NotContains(t, body, `value="approve"`)
	require.NotContains(t, body, `value="reject"`)
	require.Contains(t, body, "nothing left to decide")
}

// TestReviewReleasePage_AnUnknownRelease_IsNotFound.
func TestReviewReleasePage_AnUnknownRelease_IsNotFound(t *testing.T) {
	t.Parallel()

	t.Run("an id that names nothing", func(t *testing.T) {
		t.Parallel()

		h := newReviewHarness(t, func(h *reviewHarness) {
			h.queue.detailErr = review.ErrNoSuchRelease
		})
		require.Equal(t, http.StatusNotFound,
			h.do(t, http.MethodGet, "/review/releases/"+testReleaseID, nil).status)
	})

	t.Run("an id that is not an id", func(t *testing.T) {
		t.Parallel()

		h := newReviewHarness(t)
		require.Equal(t, http.StatusNotFound,
			h.do(t, http.MethodGet, "/review/releases/not-a-ulid", nil).status)
		require.Empty(t, h.queue.sawApprove)
	})
}

// TestReviewDecide_EachActionReachesTheQueue.
func TestReviewDecide_EachActionReachesTheQueue(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t, func(h *reviewHarness) { h.queue.verified = true })
	path := "/review/releases/" + testReleaseID + "/decide"

	resp := h.do(t, http.MethodPost, path, url.Values{
		auth.CSRFFieldName: {h.csrf()}, "action": {"approve"}, "note": {"looks fine"},
	})
	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Equal(t, "/review/releases/"+testReleaseID+"?msg=release_decided",
		resp.header.Get("Location"), "post/redirect/get, back to the page that was acted on")
	require.Equal(t, []string{testReleaseID + "|looks fine"}, h.queue.sawApprove)

	h.do(t, http.MethodPost, path, url.Values{
		auth.CSRFFieldName: {h.csrf()}, "action": {"reject"}, "note": {"not a plugin"},
	})
	require.Equal(t, []string{testReleaseID + "|not a plugin"}, h.queue.sawReject)

	h.do(t, http.MethodPost, path, url.Values{
		auth.CSRFFieldName: {h.csrf()}, "action": {"reverify"},
	})
	require.Equal(t, []string{testReleaseID}, h.queue.reverified)
}

// TestReviewDecide_WithoutTheSessionsToken_IsRefusedBeforeAnythingIsRead.
//
// A session cookie plus a form post is the classic hole. The token is the half that is ours, and
// it is checked before the action is even looked at — a handler that validated input first would
// already have done work on behalf of a request it was about to refuse.
func TestReviewDecide_WithoutTheSessionsToken_IsRefusedBeforeAnythingIsRead(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		form url.Values
	}{
		{name: "no token at all", form: url.Values{"action": {"approve"}}},
		{
			name: "somebody else's token",
			form: url.Values{auth.CSRFFieldName: {"csrf-for-another-session"}, "action": {"approve"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newReviewHarness(t)
			resp := h.do(t, http.MethodPost,
				"/review/releases/"+testReleaseID+"/decide", tt.form)

			require.Equal(t, http.StatusForbidden, resp.status)
			require.Empty(t, h.queue.sawApprove, "nothing may be decided by a forged form")
		})
	}
}

// TestReviewDecide_AnUnknownAction_IsRefused.
func TestReviewDecide_AnUnknownAction_IsRefused(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t)
	resp := h.do(t, http.MethodPost, "/review/releases/"+testReleaseID+"/decide", url.Values{
		auth.CSRFFieldName: {h.csrf()}, "action": {"delete"},
	})

	require.Equal(t, http.StatusBadRequest, resp.status)
	require.Empty(t, h.queue.sawApprove)
	require.Empty(t, h.queue.sawReject)
	require.Empty(t, h.queue.reverified)
}

// TestReviewDecide_AReverifyThatStillCannotFetch_IsNotReportedAsSuccess.
//
// The whole project is designed against a confident mistake, and this is where one would live: a
// re-verification that failed leaves the release exactly as it was, and "done" over the top of
// that is the server claiming it checked something it did not.
func TestReviewDecide_AReverifyThatStillCannotFetch_IsNotReportedAsSuccess(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t, func(h *reviewHarness) { h.queue.verified = false })

	resp := h.do(t, http.MethodPost, "/review/releases/"+testReleaseID+"/decide", url.Values{
		auth.CSRFFieldName: {h.csrf()}, "action": {"reverify"},
	})

	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Equal(t, "/review/releases/"+testReleaseID+"?msg=release_still_unverified",
		resp.header.Get("Location"))

	// And the page that redirect lands on says so as a problem, not as a notice.
	body := string(h.do(t, http.MethodGet,
		"/review/releases/"+testReleaseID+"?msg=release_still_unverified", nil).body)
	require.Contains(t, body, "still could not be fetched")
	require.Contains(t, body, "notice problem")
}

// TestReviewDecide_AQueueRefusal_ExplainsItself.
func TestReviewDecide_AQueueRefusal_ExplainsItself(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "somebody else decided it", err: review.ErrNotPending, want: "release_not_pending"},
		{name: "never verified", err: review.ErrNotVerified, want: "release_not_verified"},
		{name: "already verified", err: review.ErrAlreadyVerified, want: "release_already_verified"},
		{name: "no reason given", err: review.ErrNoReason, want: "release_no_reason"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			h := newReviewHarness(t, func(h *reviewHarness) { h.queue.decideErr = tt.err })
			resp := h.do(t, http.MethodPost, "/review/releases/"+testReleaseID+"/decide",
				url.Values{auth.CSRFFieldName: {h.csrf()}, "action": {"approve"}})

			require.Equal(t, http.StatusSeeOther, resp.status)
			require.Equal(t, "/review/releases/"+testReleaseID+"?msg="+tt.want,
				resp.header.Get("Location"))
		})
	}
}

// TestAccountPage_OffersTheQueueOnlyToAReviewer — how a reviewer finds the queue at all.
func TestAccountPage_OffersTheQueueOnlyToAReviewer(t *testing.T) {
	t.Parallel()

	t.Run("a reviewer sees the link", func(t *testing.T) {
		t.Parallel()

		h := newReviewHarness(t)
		require.Contains(t, string(h.do(t, http.MethodGet, "/account", nil).body),
			`href="/review"`)
	})

	t.Run("everybody else does not", func(t *testing.T) {
		t.Parallel()

		h := newReviewHarness(t, func(h *reviewHarness) { h.reviewers.yes = false })
		require.NotContains(t, string(h.do(t, http.MethodGet, "/account", nil).body),
			`href="/review"`)
	})

	t.Run("a check that fails is not a link", func(t *testing.T) {
		t.Parallel()

		h := newReviewHarness(t, func(h *reviewHarness) {
			h.reviewers.err = context.DeadlineExceeded
		})
		resp := h.do(t, http.MethodGet, "/account", nil)

		require.Equal(t, http.StatusOK, resp.status,
			"a failed reviewer check must not break somebody's account page")
		require.NotContains(t, string(resp.body), `href="/review"`,
			`"we could not check" must never resolve to "yes"`)
	})
}

// TestAccountPage_ARegistryWithNoReviewers_SaysSoInsteadOfLookingLikeAnEmptyQueue.
//
// THE THREE STATES THIS SURFACE HAD TWO ANSWERS FOR. "You may not moderate" and "NOBODY may
// moderate" both rendered as an account page with no queue link, and only the second is a fault:
// `REGSERVE_REVIEWERS` is defaulted empty in the compose file, so an instance where every
// submission waits for ever and no human can act on any of it is one unset variable away and looks
// exactly like an instance whose queue happens to be empty.
//
// The assertion that matters is the last one in each case: the three pages must differ from each
// other. A warning that appeared on all of them would be as useless as one that appeared on none.
func TestAccountPage_ARegistryWithNoReviewers_SaysSoInsteadOfLookingLikeAnEmptyQueue(t *testing.T) {
	t.Parallel()

	page := func(t *testing.T, yes, unconfigured bool) string {
		t.Helper()

		h := newReviewHarness(t, func(h *reviewHarness) {
			h.reviewers.yes = yes
			h.reviewers.unconfigured = unconfigured
		})
		resp := h.do(t, http.MethodGet, "/account", nil)
		require.Equal(t, http.StatusOK, resp.status)
		return string(resp.body)
	}

	const warning = "no reviewers configured"

	t.Run("a reviewer is offered the queue and told about no fault", func(t *testing.T) {
		t.Parallel()

		body := page(t, true, false)
		require.Contains(t, body, `href="/review"`)
		require.NotContains(t, body, warning)
	})

	t.Run("a non-reviewer on a moderated registry is told nothing", func(t *testing.T) {
		t.Parallel()

		// The quiet case, and deliberately quiet: somebody can approve, it is simply not this
		// account. There is nothing here for the reader to act on.
		body := page(t, false, false)
		require.NotContains(t, body, `href="/review"`)
		require.NotContains(t, body, warning)
	})

	t.Run("a registry nobody can moderate says so, and says what fixes it", func(t *testing.T) {
		t.Parallel()

		body := page(t, false, true)
		require.NotContains(t, body, `href="/review"`)
		require.Contains(t, body, warning)
		require.Contains(t, body, review.EnvVar(),
			"a warning that does not name the variable is a warning nobody can act on")

		// Never the handles and never the count. That a registry can approve nothing is the safe
		// state and is worth saying; who may approve is a list of people to work through.
		require.NotContains(t, body, "themaintainer")
	})
}

// TestReviewQueue_ANonReviewerAndAReviewerWithNothingToDo_DoNotSeeTheSamePage.
//
// The other half of the same ambiguity, one level down. An operator who typed /review directly had
// no way to tell "this account may not" from "there is nothing waiting", and those need different
// actions from them.
func TestReviewQueue_ANonReviewerAndAReviewerWithNothingToDo_DoNotSeeTheSamePage(t *testing.T) {
	t.Parallel()

	empty := newReviewHarness(t, func(h *reviewHarness) { h.queue.waiting = nil })
	refused := newReviewHarness(t, func(h *reviewHarness) { h.reviewers.yes = false })

	idle := empty.do(t, http.MethodGet, api.PathReviewQueue, nil)
	require.Equal(t, http.StatusOK, idle.status)
	require.Contains(t, string(idle.body), "Nothing is waiting",
		"a reviewer with an empty queue must be told the queue is empty")

	denied := refused.do(t, http.MethodGet, api.PathReviewQueue, nil)
	require.Equal(t, http.StatusForbidden, denied.status)
	p := problemOf(t, denied)
	require.Equal(t, api.CodeForbidden, p.Code)
	require.Contains(t, p.Detail, "operates the deployment",
		"the refusal has to say where the authority comes from; it is not something to request here")
}
