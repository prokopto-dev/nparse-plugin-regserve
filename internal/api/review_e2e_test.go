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
		Publisher: release.NewPublisher(db, clk, fetcher),
		// The two objects the operator's configuration actually produces. ParseHandleList is the
		// same call cmd/regserve makes on os.Getenv(review.EnvVar()), so "the variable is unset"
		// is reproduced here rather than described.
		Queue:     review.NewQueue(db, clk, fetcher),
		Reviewers: review.NewReviewers(db, review.ParseHandleList(handles)),
		// The moderation console, wired exactly as cmd/regserve wires it. The SAME Publisher backs
		// Trust that backs Publisher, which is the point of the trust half of this file: the tier a
		// reviewer sets through a form is read by the publish path through the same object, so
		// "marked trusted" and "publishes without a human" are one fact rather than two.
		Trust:      release.NewPublisher(db, clk, fetcher),
		Moderation: review.NewPlugins(db, clk),
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

// trust posts the browser form a reviewer uses, which is the only door a human has: setting a
// tier is capability-floor, so it is session-only, so it is browser-only.
func (w *reviewE2E) trust(t *testing.T, cookie, csrf, accountID, level, note string) response {
	t.Helper()

	form := url.Values{}
	form.Set(auth.CSRFFieldName, csrf)
	form.Set("level", level)
	form.Set("note", note)
	form.Set("from", "plugin")
	form.Set("from_id", w.pluginID)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		w.srv.URL+"/review/accounts/"+accountID+"/trust", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: cookie})
	return w.send(t, req)
}

// moderate posts the delist/relist form.
func (w *reviewE2E) moderate(t *testing.T, cookie, csrf, pluginID, action, reason string) response {
	t.Helper()

	form := url.Values{}
	form.Set(auth.CSRFFieldName, csrf)
	form.Set("action", action)
	form.Set("reason", reason)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		w.srv.URL+"/review/plugins/"+pluginID+"/listing", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: cookie})
	return w.send(t, req)
}

// claimAndPublish registers a SECOND plugin id to the same owner and publishes to it with a token
// pinned to that id.
//
// It exists for the half of the trust proof that matters most: a trusted account submitting a NEW
// id. The token is pinned to the new plugin because ADR-0005 says a PAT is scoped to one plugin,
// so reusing the first token would be refused by the pin rather than by the review rule -- and the
// test would pass while proving something else entirely.
func (w *reviewE2E) claimAndPublish(t *testing.T, pluginID, version string) publishedRelease {
	t.Helper()

	insertClaimedPlugin(t, w.db, time.Date(2026, 8, 21, 3, 46, 0, 0, time.UTC), pluginID, w.owner)

	minted, err := w.tokens.Mint(t.Context(), auth.MintRequest{
		AccountID: w.owner,
		Name:      "the second plugin's release workflow",
		Scopes:    []authz.Scope{"plugin:publish"},
		PluginID:  pluginID,
	})
	require.NoError(t, err)

	sum := sha256.Sum256(w.artifactBody)
	body, err := json.Marshal(map[string]any{
		"version":         version,
		"artifact_url":    w.artifactURL,
		"artifact_sha256": hex.EncodeToString(sum[:]),
		"sdk_specifier":   ">=1.0,<2",
	})
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		w.srv.URL+api.BasePath+"/plugins/"+pluginID+"/releases", strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+minted.Secret)
	req.Header.Set("Idempotency-Key", "workflow-run-"+pluginID+"-"+version)

	resp := w.send(t, req)
	require.Equal(t, http.StatusCreated, resp.status, "body was %s", resp.body)

	var got publishedRelease
	require.NoError(t, json.Unmarshal(resp.body, &got), "body was %s", resp.body)
	return got
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

// THE MODERATION CONSOLE, END TO END, WITH NOTHING FAKED BETWEEN THE FORM AND THE INDEX.
//
// The operator's ask was one sentence: after reviewing somebody once, stop gating their version
// bumps. That behaviour already existed in release.Publisher.decide and had no control, so what
// this proves is not the rule — it is that a reviewer can now REACH the rule from a browser, and
// that reaching it does exactly what ADR-0007 says and nothing more.
//
// BOTH HALVES ARE IN ONE TEST ON PURPOSE. "A trusted account's version bump lists without a human"
// is a feature; "a trusted account's NEW id still goes to review" is the invariant that makes the
// feature safe, and a change that broke the second while keeping the first would pass any test
// that only asserted the first. The first appearance of an id is where impersonation is caught,
// and no tier bypasses it — so the two are asserted against the same database, the same account
// and the same trust row, one after the other.

func TestModerationConsole_ATrustedPublishersBumpListsItself_AndTheirNewIDStillGetsAHuman(t *testing.T) {
	t.Parallel()

	w := newReviewE2E(t, "themaintainer")
	cookie, csrf := w.sessionFor(t, w.reviewer)

	// --- 1. the first release of a new id goes to a human, whatever anybody's tier -------------
	first := w.publish(t, "1.0.0")
	require.Equal(t, "pending", first.State, "the first appearance of an id always gets a human")
	require.NotContains(t, w.index(t), w.pluginID)

	resp := w.decide(t, cookie, csrf, first.ReleaseID, "approve", "read the diff, looks fine")
	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Contains(t, w.index(t), `"1.0.0"`, "an approved release reaches the index")

	// --- 2. approving did NOT trust the publisher ----------------------------------------------
	//
	// The separation, measured through the real publisher rather than asserted about a form. If
	// approving raised trust, the bump below would list for the wrong reason and the whole test
	// would be a false positive.
	publisher := release.NewPublisher(w.db, clock.Fixed{T: time.Date(2026, 8, 21, 3, 46, 0, 0, time.UTC)}, nil)
	tier, err := publisher.TrustOf(t.Context(), w.owner)
	require.NoError(t, err)
	require.Equal(t, release.TrustNew, tier,
		"approving a release must never raise its publisher's tier as a side effect")

	// --- 3. a reviewer marks the publisher trusted, through the form ---------------------------
	resp = w.trust(t, cookie, csrf, w.owner, "trusted", "reviewed one release by hand; the build is reproducible")
	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Contains(t, resp.header.Get("Location"), "msg=trust_set", "body was %s", resp.body)

	tier, err = publisher.TrustOf(t.Context(), w.owner)
	require.NoError(t, err)
	require.Equal(t, release.TrustTrusted, tier, "the form must write the tier the publish path reads")

	// --- 4. THE FEATURE: a version bump of that plugin lists with no human ----------------------
	bump := w.publish(t, "1.1.0")
	require.Equal(t, "approved", bump.State,
		"a trusted owner's clean version bump of an already-approved plugin publishes itself")

	index := w.index(t)
	require.Contains(t, index, `"1.1.0"`, "and reaches the index with no reviewer involved")
	require.NotContains(t, index, `"1.0.0"`, "superseding the release it replaced")

	// Nobody decided it, and the row says so rather than being distinguishable only by a NULL.
	require.Contains(t, bump.Review, "published automatically")

	// --- 5. THE INVARIANT: a NEW id from the same trusted account still waits -------------------
	//
	// Same owner, same trust row, same clean artifact. The only difference is that the id has
	// never been seen before, and that is the whole of what decides this.
	fresh := w.claimAndPublish(t, "second-plugin", "1.0.0")
	require.Equal(t, "pending", fresh.State,
		"a new plugin id ALWAYS gets human review, whatever the submitter's tier (ADR-0007): "+
			"the first appearance of an id is where impersonation is caught")
	require.NotContains(t, w.index(t), "second-plugin", "and it is not listed while it waits")

	// And it really is waiting in the queue a human works, rather than merely not-listed.
	queue := w.browse(t, cookie, "/review")
	require.Equal(t, http.StatusOK, queue.status)
	require.Contains(t, string(queue.body), "second-plugin")
}

// TestModerationConsole_ADelistedPluginLeavesTheIndexAndKeepsItsClaim.
//
// The other capability the reviewer did not have. It is driven through the form, and what is
// asserted afterwards is mostly what did NOT happen: the id is still claimed, and re-claiming it
// is refused. An id that could be recycled is how you ship an update to somebody else's users.
func TestModerationConsole_ADelistedPluginLeavesTheIndexAndKeepsItsClaim(t *testing.T) {
	t.Parallel()

	w := newReviewE2E(t, "themaintainer")
	cookie, csrf := w.sessionFor(t, w.reviewer)

	out := w.publish(t, "1.0.0")
	require.Equal(t, http.StatusSeeOther,
		w.decide(t, cookie, csrf, out.ReleaseID, "approve", "fine").status)
	require.Contains(t, w.index(t), w.pluginID)

	// The console shows it before anything happens to it.
	page := w.browse(t, cookie, "/review/plugins")
	require.Equal(t, http.StatusOK, page.status)
	require.Contains(t, string(page.body), w.pluginID)

	resp := w.moderate(t, cookie, csrf, w.pluginID, "delist", "the author asked us to withdraw it")
	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Contains(t, resp.header.Get("Location"), "msg=listing_changed", "body was %s", resp.body)

	// GONE from what every client reads.
	require.NotContains(t, w.index(t), w.pluginID)

	// AND STILL CLAIMED. Not "the row is there" — the id is refused to a fresh claimant, which is
	// the property that actually matters and the one an accidental DELETE would break.
	owners := ownership.New(w.db, clock.Fixed{T: time.Date(2026, 8, 21, 3, 46, 0, 0, time.UTC)})
	claimed, err := core.ParsePluginID(w.pluginID)
	require.NoError(t, err)
	err = owners.ClaimID(t.Context(), ownership.Claim{
		PluginID: claimed, Name: "Someone Else's Merchant Mode",
	}, w.bystander)
	require.ErrorIs(t, err, ownership.ErrAlreadyClaimed,
		"a delisted id must never become available to somebody else")

	// And it comes back, through the same surface, without a maintainer writing SQL.
	resp = w.moderate(t, cookie, csrf, w.pluginID, "relist", "withdrawal was retracted")
	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Contains(t, w.index(t), w.pluginID, "the still-approved release returns to the index")
}

// TestModerationConsole_IsRefusedToEverybodyWhoIsNotAConfiguredReviewer.
//
// The negative half, in the same file as the positive one for the reason the queue's is: a server
// that let everybody moderate would pass every assertion above.
func TestModerationConsole_IsRefusedToEverybodyWhoIsNotAConfiguredReviewer(t *testing.T) {
	t.Parallel()

	w := newReviewE2E(t, "themaintainer")
	cookie, csrf := w.sessionFor(t, w.bystander)

	// A signed-in account that is not a reviewer.
	require.Equal(t, http.StatusForbidden, w.browse(t, cookie, "/review/plugins").status)
	require.Equal(t, http.StatusForbidden,
		w.moderate(t, cookie, csrf, w.pluginID, "delist", "I would like this gone").status)
	require.Equal(t, http.StatusForbidden,
		w.trust(t, cookie, csrf, w.bystander, "trusted", "trusting myself").status)

	// A real publish token, over the socket. Moderation is capability-floor: no token reaches it
	// however it is scoped, so a leaked publish token stays a leaked publish token.
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, w.srv.URL+"/review/plugins", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+w.publishToken)
	resp := w.send(t, req)
	require.Equal(t, http.StatusForbidden, resp.status)
	require.Contains(t, string(resp.body), "session-only")

	// Nothing was delisted and nobody was trusted by any of that.
	require.Contains(t, w.index(t), "")
	tier, err := release.NewPublisher(w.db, clock.Fixed{T: time.Now().UTC()}, nil).
		TrustOf(t.Context(), w.bystander)
	require.NoError(t, err)
	require.Equal(t, release.TrustNew, tier)
}
