package api_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/plugin"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// THE REVIEW QUEUE, END TO END, WITH NOTHING FAKED BETWEEN THE SUBMISSION AND THE INDEX.
//
// The queue has unit coverage in internal/review, and the pages have surface coverage in
// reviewweb_test.go against a fake queue and a fake reviewer check. Neither answers the question an
// operator actually asks — "if I publish something, can a human make it appear?" — because the
// thing most likely to be wrong is not any one layer but the joins between them: whether the
// reviewer set built from an environment variable resolves the account a session belongs to,
// whether the page a browser posts reaches the queue that writes the row, and whether that row
// changes what `GET /index.json` serves.
//
// A BROKEN REVIEW QUEUE AND AN EMPTY ONE LOOK IDENTICAL FROM OUTSIDE, which is why this is not
// covered by "nothing has ever been rejected". It is the whole chain: a real SQLite database, the
// real publisher over a real socket to a real artifact server, the real reviewer set built from
// the handles an operator would type, a real session cookie, the real form post, and the real
// index bytes at the end.
//
// The negative halves are in the same run for the reason the capability-floor test gives: a server
// that let everybody moderate would pass the positive half on its own.

// reviewE2E is every real component the path touches.
type reviewE2E struct {
	srv *httptest.Server
	db  *store.DB

	tokens   *auth.Tokens
	sessions *auth.Sessions
	authn    *auth.Authenticator

	pluginID     string
	owner        string
	reviewer     string
	bystander    string
	artifactURL  string
	artifactBody []byte

	publishToken string
}

// newReviewE2E wires the same objects cmd/regserve wires, against a real database.
//
// `handles` is what an operator put in REGSERVE_REVIEWERS, passed through the same parser the serve
// command uses — so a test can reproduce the unset variable exactly rather than approximating it.
func newReviewE2E(t *testing.T, handles string) *reviewE2E {
	t.Helper()

	now := time.Date(2026, 8, 21, 3, 46, 0, 0, time.UTC)
	clk := clock.Fixed{T: now}
	db := storetest.New(t)

	w := &reviewE2E{
		db:           db,
		pluginID:     "merchant-mode",
		artifactBody: []byte("not a real wheel, but real bytes"),
	}

	// TLS, because the fetcher re-asserts https on every hop. Serving the bytes for real is what
	// makes "verified" mean the server hashed something rather than believed something.
	artifacts := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write(w.artifactBody)
	}))
	t.Cleanup(artifacts.Close)
	w.artifactURL = artifacts.URL + "/merchant-mode-1.0.0.whl"

	pool := x509.NewCertPool()
	pool.AddCert(artifacts.Certificate())
	fetcher, err := artifact.NewFetcher(clk, artifact.Config{
		Timeout:        5 * time.Second,
		PermitLoopback: true,
		RootCAs:        pool,
	})
	require.NoError(t, err)

	// Three accounts, each with a GitHub identity, because the reviewer set matches on a handle
	// somebody has PROVED they hold. The bystander is what makes the refusal below mean something.
	w.owner = insertAccountWithHandle(t, db, now, "prokopto-dev")
	w.reviewer = insertAccountWithHandle(t, db, now, "themaintainer")
	w.bystander = insertAccountWithHandle(t, db, now, "somebody-else")
	insertClaimedPlugin(t, db, now, w.pluginID, w.owner)

	pepper := core.NewSecret("a pepper that is not the production one")
	sessions, err := auth.NewSessions(db, clk, pepper)
	require.NoError(t, err)
	tokens, err := auth.NewTokens(db, clk, pepper)
	require.NoError(t, err)
	w.sessions, w.tokens = sessions, tokens
	w.authn = auth.NewAuthenticator(sessions, tokens)

	catalogue := plugin.NewCatalogue(db)
	owners := ownership.New(db, clk)
	publisher := release.NewPublisher(db, clk, fetcher)
	login, err := auth.NewOAuth(db, clk, pepper, identity.NewRegistry(stubProvider{}))
	require.NoError(t, err)

	w.srv = httptest.NewServer(api.New(api.Config{
		Clock:     clk,
		Catalogue: catalogue,
		Directory: catalogue,
		Authn:     w.authn,
		Login:     login,
		Sessions:  sessions,
		Providers: identity.NewRegistry(stubProvider{}),
		Tokens:    tokens,
		Ownership: owners,
		Claimer:   owners,
		Publisher: publisher,
		// THE SAME Publisher, wired twice. A tier is read by the publish path and written by a
		// reviewer, and two objects over one table would be two places to change when the rule
		// changes -- which is exactly how the reviewer's decision would stop reaching the publish
		// that comes after it.
		Trust: publisher,
		// The two objects the operator's configuration actually produces. ParseHandleList is the
		// same call cmd/regserve makes on os.Getenv(review.EnvVar()), so "the variable is unset"
		// is reproduced here rather than described.
		Queue:     review.NewQueue(db, clk, fetcher),
		Reviewers: review.NewReviewers(db, review.ParseHandleList(handles)),
	}))
	t.Cleanup(w.srv.Close)

	minted, err := tokens.Mint(t.Context(), auth.MintRequest{
		AccountID: w.owner,
		Name:      "the plugin's release workflow",
		Scopes:    []authz.Scope{"plugin:publish"},
		PluginID:  w.pluginID,
	})
	require.NoError(t, err)
	w.publishToken = minted.Secret

	return w
}

// sessionFor signs an account in and returns the cookie value and its CSRF token, which is what a
// browser holds after the OAuth callback.
func (w *reviewE2E) sessionFor(t *testing.T, accountID string) (cookie, csrf string) {
	t.Helper()

	created, err := w.sessions.Create(t.Context(), accountID)
	require.NoError(t, err)

	// Through the resolver rather than from the creation, because the CSRF token is keyed on the
	// session id and the principal is what the handler will be holding.
	p, err := w.authn.Resolve(t.Context(), auth.Credentials{SessionCookie: created.Secret})
	require.NoError(t, err)
	return created.Secret, w.sessions.CSRFToken(p)
}

// publish submits a release the way a plugin's CI does: a bearer token, over the socket.
func (w *reviewE2E) publish(t *testing.T, version string) publishedRelease {
	t.Helper()

	sum := sha256.Sum256(w.artifactBody)
	body, err := json.Marshal(map[string]any{
		"version":         version,
		"artifact_url":    w.artifactURL,
		"artifact_sha256": hex.EncodeToString(sum[:]),
		"sdk_specifier":   ">=1.0,<2",
	})
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		w.srv.URL+api.BasePath+"/plugins/"+w.pluginID+"/releases", strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+w.publishToken)
	req.Header.Set("Idempotency-Key", "workflow-run-"+version)

	resp := w.send(t, req)
	require.Equal(t, http.StatusCreated, resp.status, "body was %s", resp.body)

	var got publishedRelease
	require.NoError(t, json.Unmarshal(resp.body, &got), "body was %s", resp.body)
	return got
}

// browse performs a GET carrying a session cookie, as a signed-in browser would.
func (w *reviewE2E) browse(t *testing.T, cookie, path string) response {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, w.srv.URL+path, nil)
	require.NoError(t, err)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: cookie})
	}
	return w.send(t, req)
}

// decide posts the review form, which is the only way a human can act on the queue: moderation is
// capability-floor, so it is session-only, so it is browser-only.
func (w *reviewE2E) decide(t *testing.T, cookie, csrf, releaseID, action, note string) response {
	t.Helper()

	form := url.Values{}
	form.Set(auth.CSRFFieldName, csrf)
	form.Set("action", action)
	form.Set("note", note)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		w.srv.URL+"/review/releases/"+releaseID+"/decide", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: cookie})
	return w.send(t, req)
}

// setTrust posts the trust form, which is the only way a human can set a tier: it is
// capability-floor, so it is session-only, so it is browser-only.
func (w *reviewE2E) setTrust(t *testing.T, cookie, csrf, accountID, level, note string) response {
	t.Helper()

	form := url.Values{}
	form.Set(auth.CSRFFieldName, csrf)
	form.Set("level", level)
	form.Set("note", note)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		w.srv.URL+"/review/accounts/"+accountID+"/trust", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: cookie})
	return w.send(t, req)
}

func (w *reviewE2E) send(t *testing.T, req *http.Request) response {
	t.Helper()

	// This server's own client, never a bare &http.Client{}: a shared transport plus
	// httptest.Server.Close is how one parallel test severs another's connection.
	client := w.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return response{status: resp.StatusCode, header: resp.Header.Clone(), body: raw}
}

// index reads what a released nParse+ client would read.
func (w *reviewE2E) index(t *testing.T) string {
	t.Helper()

	resp := w.browse(t, "", api.PathIndex)
	require.Equal(t, http.StatusOK, resp.status)
	return string(resp.body)
}

// TestReviewQueue_APublishedRelease_ReachesTheIndexOnlyAfterAReviewerApprovesIt is the whole path.
func TestReviewQueue_APublishedRelease_ReachesTheIndexOnlyAfterAReviewerApprovesIt(t *testing.T) {
	t.Parallel()

	w := newReviewE2E(t, "themaintainer")
	cookie, csrf := w.sessionFor(t, w.reviewer)

	published := w.publish(t, "1.0.0")

	t.Run("it lands pending, verified, and out of the index", func(t *testing.T) {
		require.Equal(t, release.StatePending.String(), published.State,
			"a plugin's first release always gets a human, whatever the submitter's trust")
		require.True(t, published.Verified,
			"the artifact was not fetched and hashed, so it could not be approved: %s", published.Review)
		require.NotContains(t, w.index(t), w.pluginID,
			"a pending release must not be in the index a client parses")
	})

	t.Run("the reviewer sees it waiting", func(t *testing.T) {
		resp := w.browse(t, cookie, api.PathReviewQueue)

		require.Equal(t, http.StatusOK, resp.status, "body was %s", resp.body)
		require.Contains(t, string(resp.body), published.ReleaseID,
			"the release is in the database and not on the page a reviewer works from")
		require.Contains(t, string(resp.body), "first release of this id")
	})

	t.Run("approving it from the page puts it in the index", func(t *testing.T) {
		resp := w.decide(t, cookie, csrf, published.ReleaseID, "approve", "looks like what it says")
		require.Equal(t, http.StatusSeeOther, resp.status, "body was %s", resp.body)

		body := w.index(t)
		require.Contains(t, body, w.pluginID)
		require.Contains(t, body, `"version":"1.0.0"`)

		// The hash in the index is the one the SERVER computed. The submitted value is compared and
		// then discarded (ADR-0008), so this is the one assertion that reaches all the way from
		// the bytes on the socket to the bytes a client will verify against.
		sum := sha256.Sum256(w.artifactBody)
		require.Contains(t, body, hex.EncodeToString(sum[:]))
	})

	t.Run("and the queue is empty afterwards", func(t *testing.T) {
		resp := w.browse(t, cookie, api.PathReviewQueue)
		require.Equal(t, http.StatusOK, resp.status)
		require.Contains(t, string(resp.body), "Nothing is waiting")
	})
}

// TestReviewQueue_AnAccountThatIsNotAConfiguredReviewer_IsRefused is the negative half.
//
// Same server, same session machinery, same queue with something in it — and a handle that is not
// in REGSERVE_REVIEWERS. Without this the test above would pass on a build that let every signed-in
// account moderate, which is one of the three ways AGENTS.md names to get this wrong.
func TestReviewQueue_AnAccountThatIsNotAConfiguredReviewer_IsRefused(t *testing.T) {
	t.Parallel()

	w := newReviewE2E(t, "themaintainer")
	published := w.publish(t, "1.0.0")
	cookie, csrf := w.sessionFor(t, w.bystander)

	queue := w.browse(t, cookie, api.PathReviewQueue)
	require.Equal(t, http.StatusForbidden, queue.status)

	decided := w.decide(t, cookie, csrf, published.ReleaseID, "approve", "")
	require.Equal(t, http.StatusForbidden, decided.status,
		"the form post is refused by the same declaration the page is, not by the page hiding it")

	require.NotContains(t, w.index(t), w.pluginID,
		"a refused approval must not have changed what clients download")
}

// TestReviewQueue_AnUnsetReviewerVariable_RefusesEverybodyAndTheAccountPageSaysSo reproduces the
// deployment the compose file's `REGSERVE_REVIEWERS:-` default produces.
//
// It is CORRECT BEHAVIOUR and a broken deployment at the same time: nothing is admitted, which is
// the only safe reading of a missing value, and nothing can ever be published either. The part that
// was a defect is the last assertion — until it existed, this state and "your queue is empty" were
// the same page, so the operator could not tell which one they were in.
func TestReviewQueue_AnUnsetReviewerVariable_RefusesEverybodyAndTheAccountPageSaysSo(t *testing.T) {
	t.Parallel()

	w := newReviewE2E(t, "")
	w.publish(t, "1.0.0")

	for _, account := range []struct {
		name string
		id   string
	}{
		{"the account an operator would have named", w.reviewer},
		{"the plugin's own owner", w.owner},
	} {
		t.Run(account.name, func(t *testing.T) {
			cookie, _ := w.sessionFor(t, account.id)
			require.Equal(t, http.StatusForbidden,
				w.browse(t, cookie, api.PathReviewQueue).status,
				"an empty reviewer set must never read as everybody")
		})
	}

	t.Run("and the account page says why, naming the variable", func(t *testing.T) {
		cookie, _ := w.sessionFor(t, w.reviewer)
		resp := w.browse(t, cookie, api.PathAccountPage)

		require.Equal(t, http.StatusOK, resp.status)
		require.Contains(t, string(resp.body), "no reviewers configured")
		require.Contains(t, string(resp.body), review.EnvVar())
	})
}

// insertAccountWithHandle creates an account with a GitHub identity holding `handle`.
//
// The handle is the point: only GitHub identities may publish (ADR-0011), and review.Reviewers
// matches a configured name against an identity somebody has PROVED they hold rather than against
// a display name. An account without one would fail both checks for reasons unrelated to this
// test.
func insertAccountWithHandle(t *testing.T, db *store.DB, now time.Time, handle string) string {
	t.Helper()

	accountID, err := core.NewULID(now)
	require.NoError(t, err)
	identityID, err := core.NewULID(now)
	require.NoError(t, err)

	require.NoError(t, db.Tx(t.Context(), func(q *store.Queries) error {
		if err := q.InsertAccount(t.Context(), sqlitegen.InsertAccountParams{
			ID:          accountID.String(),
			DisplayName: handle,
			CreatedAt:   core.MicrosFromTime(now).Int64(),
			UpdatedAt:   core.MicrosFromTime(now).Int64(),
		}); err != nil {
			return err
		}
		return q.InsertIdentity(t.Context(), sqlitegen.InsertIdentityParams{
			ID:           identityID.String(),
			AccountID:    accountID.String(),
			ProviderKind: "github",
			Subject:      "sub-" + handle,
			Handle:       handle,
			LinkedAt:     core.MicrosFromTime(now).Int64(),
			RefreshedAt:  core.MicrosFromTime(now).Int64(),
		})
	}))
	return accountID.String()
}

// TestReviewQueue_EveryReleaseWaitsUntilAReviewerTrustsTheAccount is the reported bug, end to end.
//
// WHAT IT LOOKED LIKE: "every push waits for approval even after the id has been approved -- like
// it thinks every time is the first time." WHAT IT WAS: the account was at the floor, which is the
// default for an account nobody has assessed, and a tier is never raised automatically. So a clean
// version bump of an already-listed plugin queued exactly as designed, and no surface said why --
// the release's note read "awaiting human review", the queue showed no tier, the account page
// showed no tier, and the only way to set one was to copy a session cookie into curl because there
// was no form.
//
// This walks the whole of it: the bump that waits and NAMES the tier as the reason, the reviewer
// setting the tier from the page, and the next bump reaching the index with no human involved.
func TestReviewQueue_EveryReleaseWaitsUntilAReviewerTrustsTheAccount(t *testing.T) {
	t.Parallel()

	w := newReviewE2E(t, "themaintainer")
	cookie, csrf := w.sessionFor(t, w.reviewer)

	// The id's first appearance always gets a human, whatever the tier. Approved, so the plugin is
	// listed and every rule below has something to compare against.
	first := w.publish(t, "1.0.0")
	require.Equal(t, release.StatePending.String(), first.State)
	require.Equal(t, http.StatusSeeOther,
		w.decide(t, cookie, csrf, first.ReleaseID, "approve", "the first release of a new id").status)
	require.Contains(t, w.index(t), `"version":"1.0.0"`)

	t.Run("a clean version bump still waits, and says the tier is why", func(t *testing.T) {
		bump := w.publish(t, "1.1.0")

		require.Equal(t, release.StatePending.String(), bump.State)
		require.True(t, bump.Verified)
		require.Empty(t, bump.Reasons,
			"no rule fired: the id is listed, the host has not moved, the version advances")
		require.Contains(t, bump.Review, "has not marked the submitting account trusted",
			"THE ANSWER TO THE REPORT. Without this the workflow is told only that it is waiting")
		require.Contains(t, w.index(t), `"version":"1.0.0"`, "the listing has not moved")
	})

	t.Run("the queue shows the tier, so the pattern is visible", func(t *testing.T) {
		resp := w.browse(t, cookie, api.PathReviewQueue)

		require.Equal(t, http.StatusOK, resp.status, "body was %s", resp.body)
		require.Contains(t, string(resp.body), "trust: new")
		require.Contains(t, string(resp.body), "prokopto-dev", "the submitter, as a person")
	})

	t.Run("the reviewer sets the tier from the page", func(t *testing.T) {
		resp := w.setTrust(t, cookie, csrf, w.owner, "trusted",
			"the plugin's pipeline has published two releases and both hashed clean")

		require.Equal(t, http.StatusSeeOther, resp.status, "body was %s", resp.body)
		require.Equal(t, "/review?msg=trust_set", resp.header.Get("Location"))
	})

	t.Run("and the next bump reaches the index with no human involved", func(t *testing.T) {
		auto := w.publish(t, "1.2.0")

		require.Equal(t, release.StateApproved.String(), auto.State,
			"a trusted owner's clean version bump of an already-approved plugin publishes itself")
		require.Contains(t, auto.Review, "published automatically")
		require.Contains(t, w.index(t), `"version":"1.2.0"`)

		// The 1.1.0 that was waiting is retired by the newer submission, and the answer SAYS SO.
		// A release that stops waiting with nothing saying so is indistinguishable from a bug.
		require.Len(t, auto.SupersededPending, 1,
			"the earlier waiting release was retired and the workflow was told")
	})

	t.Run("a bystander cannot set a tier", func(t *testing.T) {
		other, otherCSRF := w.sessionFor(t, w.bystander)

		resp := w.setTrust(t, other, otherCSRF, w.owner, "blocked", "because I said so")
		require.Equal(t, http.StatusForbidden, resp.status,
			"a signed-in account that is not a reviewer must not be able to change a tier")
	})

	t.Run("and neither can a token, however scoped", func(t *testing.T) {
		form := url.Values{}
		form.Set("level", "trusted")
		form.Set("note", "escalating myself")

		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
			w.srv.URL+"/review/accounts/"+w.owner+"/trust", strings.NewReader(form.Encode()))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer "+w.publishToken)

		// The capability floor, which is the whole reason the tier is worth having: a token that
		// could raise its own account would be a token that could publish without review.
		require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden},
			w.send(t, req).status)
	})
}
