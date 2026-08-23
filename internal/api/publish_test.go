package api_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// TOKEN PUBLISHING, END TO END: a REAL personal access token, over REAL HTTP, through the REAL
// middleware, against the REAL catalogue.
//
// THIS TEST EXISTS BECAUSE ITS ABSENCE SHIPPED. The publish route declared the permission
// `release.publish` — spelled correctly, paired with the correct scope, and naming nothing
// internal/authz has ever defined. authz.Satisfies looked it up, missed, and returned false, so
// every scoped token was answered 403: publishing on tag, which is the entire point of this
// service, was closed for every plugin that adopted the release workflow. Every existing test
// passed. The unit tests around the middleware use a fake principal and a fabricated Access, the
// domain tests call Publisher.Publish directly with an account id, and no test anywhere carried a
// minted token across the socket into the handler — which is the one path a plugin's CI takes.
//
// So the assertion here is deliberately the whole chain and not a layer of it: mint through
// auth.Tokens, send over the wire, resolve in the middleware, satisfy against the catalogue,
// compare the plugin pin, run the handler, fetch the artifact, hash it, write the row. A fake
// anywhere in that list is a fake covering the place the defect was.
//
// The negative half is here for the reason the capability-floor test gives: a middleware that
// admitted everything would pass the positive half on its own, so a token that is real, valid and
// wrongly scoped has to be refused in the same run.
func TestPublishRelease_ARealTokenScopedToPublish_IsAdmittedAndTheReleaseIsRecorded(t *testing.T) {
	t.Parallel()

	w := newPublishWorld(t)

	t.Run("the token is real and carries exactly the publish scope", func(t *testing.T) {
		// Proving the 201 below is about the DECLARATION and not about a token the server happens
		// to wave through. Without this, a token that resolved to nothing would still have to be
		// refused, and the positive case would be checking that a broken fixture fails politely.
		p, err := w.tokens.Resolve(t.Context(), w.publishToken)
		require.NoError(t, err)
		require.True(t, p.ViaToken())
		require.Equal(t, []authz.Scope{"plugin:publish"}, p.Scopes)
		require.True(t, p.Pinned())
	})

	t.Run("and publishing with it over HTTP succeeds", func(t *testing.T) {
		resp := w.publish(t, w.publishToken, "1.0.0", "workflow-run-1")

		require.Equal(t, http.StatusCreated, resp.status,
			"a scoped, pinned token must be able to publish; body was %s", resp.body)

		var got publishedRelease
		require.NoError(t, json.Unmarshal(resp.body, &got), "body was %s", resp.body)
		require.NotEmpty(t, got.ReleaseID)

		// The hash is the assertion that the bytes were really read: artifact.Digest cannot be
		// constructed outside internal/artifact, so this value exists only because the fetcher
		// reached the artifact server over a socket and hashed what it served (ADR-0008).
		require.True(t, got.Verified, "the artifact was not fetched and hashed: %s", got.Review)
		require.Equal(t, w.artifactSHA256(), got.SHA256)
		require.Equal(t, int64(len(w.artifactBody)), got.Bytes)

		// Pending, not approved, and that is the correct success: a new plugin id ALWAYS gets a
		// human, whatever the submitter's trust level. The release was accepted and recorded —
		// which is what a 403 prevented.
		require.Equal(t, release.StatePending.String(), got.State)
		require.NotEmpty(t, got.Reasons, "a release that waits says every rule that made it wait")
	})

	t.Run("while a real token without plugin:publish is refused", func(t *testing.T) {
		// The other side of the boundary, with the same shape of credential. This is what the
		// middleware is FOR, and a build that had stopped checking scopes would pass the case
		// above while failing this one.
		resp := w.publish(t, w.readToken, "1.1.0", "workflow-run-2")

		require.Equal(t, http.StatusForbidden, resp.status)
		p := problemOf(t, resp)
		require.Equal(t, api.CodeForbidden, p.Code)
		require.Contains(t, p.Detail, "plugin.publish",
			"the refusal names the permission the catalogue defines, which is what a workflow "+
				"author greps for")
	})
}

// TestPublishRelease_TheRefusal_CannotClassifyAnID.
//
// THE GATE ON THE ANTI-ENUMERATION GUARANTEE, over real HTTP with a real token.
//
// A publish refused for want of a grant must be the SAME RESPONSE whether the id is unclaimed or
// held by somebody else. If the two differed, an unpinned `plugin:publish` token would classify a
// wordlist for free: one answer would mean available, and the other would then PROVE the id is
// somebody's — which is the set that must stay hidden, because ids are permanent and never
// recycled and a squatter only needs the list.
//
// This is not hypothetical caution. The first version of this change made the unclaimed case say
// so, on the reasoning that POST /api/v1/plugins already answers "taken or not" to any signed-in
// caller. It does not usefully: that endpoint's "not taken" answer is a 201 that CLAIMS the id,
// permanently, with an audit row per attempt — a probe nobody can run twice. Review caught it. The
// comparison below is byte for byte so that the same argument cannot win twice.
//
// The on-ramp is still served, by the other half of the assertion: the one shared sentence names
// the claim step and where to do it, which is what the author who could not publish actually
// needed. It is safe precisely because it is unconditional — it is a fact about the registry, not
// about the id in the path.
func TestPublishRelease_TheRefusal_CannotClassifyAnID(t *testing.T) {
	t.Parallel()

	w := newPublishWorld(t)

	// UNPINNED, which is the credential the attack needs and also the author's real one: "any
	// plugin you own", by an account that owns neither id below. A pinned token is refused by the
	// middleware before the handler runs, which is a different refusal about a different thing.
	unclaimed := w.publishTo(t, "floating-combat-text", w.unpinnedToken, "1.9.2", "run-unclaimed")
	claimed := w.publishTo(t, w.somebodyElses, w.unpinnedToken, "1.0.0", "run-not-mine")

	t.Logf("unclaimed id       -> HTTP %d %s", unclaimed.status, unclaimed.body)
	t.Logf("claimed by another -> HTTP %d %s", claimed.status, claimed.body)

	t.Run("the two are indistinguishable", func(t *testing.T) {
		require.Equal(t, http.StatusNotFound, unclaimed.status)
		require.Equal(t, http.StatusNotFound, claimed.status)

		// The WHOLE document, not a field of it. A difference anywhere in the body is a difference
		// a script can read, and picking fields to compare is how the next one gets missed.
		require.Equal(t, string(claimed.body), string(unclaimed.body),
			"the publish refusal must not say which of the two situations it is")
	})

	t.Run("and it still names the step an author has never heard of", func(t *testing.T) {
		p := problemOf(t, unclaimed)
		require.Equal(t, api.CodeNotFound, p.Code,
			"the code is a closed enum a client switches on; only the prose moves")

		require.Contains(t, p.Detail, "no such plugin, or you do not hold it",
			"the original sentence still opens it")
		require.Contains(t, p.Detail, "claiming is session-only")
		require.Contains(t, p.Detail, "no token")
		require.Contains(t, p.Detail, "https://nparseplugins.prokopto.dev/account",
			"and where to do it, absolute, from the configured public URL")

		// Nothing in it is about THIS id. A message that named the id back would be a message
		// that varied with the id, which is the whole thing being guarded against.
		require.NotContains(t, p.Detail, "floating-combat-text")
	})
}

// TestPublishRelease_TheRefusal_FallsBackToAPathWithNoPublicURL.
//
// An instance that was never told its own public URL must not invent one from the request's Host
// header — that value is chosen by the caller, and this sentence is printed verbatim into somebody
// else's release pipeline by the reusable workflow. A path is less useful and it is not a lie.
func TestPublishRelease_TheRefusal_FallsBackToAPathWithNoPublicURL(t *testing.T) {
	t.Parallel()

	w := newPublishWorld(t, func(cfg *api.Config) { cfg.PublicURL = "" })

	resp := w.publishTo(t, "floating-combat-text", w.unpinnedToken, "1.9.2", "run-no-public-url")
	require.Equal(t, http.StatusNotFound, resp.status)

	p := problemOf(t, resp)
	require.Contains(t, p.Detail, "sign in at /account")
	require.NotContains(t, p.Detail, "http",
		"a host from the request would be a phishing link written by the caller")
}

// publishedRelease is the response body, decoded. It is written out here rather than reusing the
// handler's unexported type on purpose: this test is a client of the published contract, and a
// client only has the JSON.
type publishedRelease struct {
	ReleaseID string   `json:"release_id"`
	State     string   `json:"state"`
	Verified  bool     `json:"verified"`
	SHA256    string   `json:"artifact_sha256"`
	Bytes     int64    `json:"artifact_bytes"`
	Review    string   `json:"review"`
	Reasons   []string `json:"quarantine"`
}

// publishWorld is a real database, a real artifact server, a real publisher and a real server.
type publishWorld struct {
	srv    *httptest.Server
	tokens *auth.Tokens

	plugin       string
	account      string
	artifactBody []byte
	artifactURL  string

	// publishToken carries `plugin:publish` and is pinned to plugin, which is what a plugin's CI
	// holds. readToken carries `plugin:read` and is otherwise identical.
	publishToken string
	readToken    string

	// unpinnedToken carries `plugin:publish` and NO pin — the "any plugin you own" option on the
	// mint form, and the token the author this fixture is modelled on actually held. It is what
	// lets one token reach two different plugin ids, which the middleware's pin check would
	// otherwise refuse before the handler ran.
	unpinnedToken string

	// somebodyElses is an id claimed by ANOTHER account. It is what the ambiguous refusal is for.
	somebodyElses string
}

// newPublishWorld builds everything a publish touches, with nothing faked between the token and
// the row.
func newPublishWorld(t *testing.T, mutate ...func(cfg *api.Config)) *publishWorld {
	t.Helper()

	now := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	clk := clock.Fixed{T: now}
	db := storetest.New(t)

	w := &publishWorld{plugin: "merchant-mode", artifactBody: []byte("not a real wheel, but real bytes")}

	// A TLS server, because the fetcher re-asserts https on every hop and an http URL is refused
	// before anything is downloaded. Serving the bytes for real is what makes the hash assertion
	// mean something.
	artifacts := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		_, _ = rw.Write(w.artifactBody)
	}))
	t.Cleanup(artifacts.Close)
	w.artifactURL = artifacts.URL + "/merchant-mode-1.0.0.whl"

	pool := x509.NewCertPool()
	pool.AddCert(artifacts.Certificate())
	fetcher, err := artifact.NewFetcher(clk, artifact.Config{
		Timeout: 5 * time.Second,
		// The two narrow relaxations internal/release's fixture takes, and only these: loopback so
		// the fetch reaches httptest, and this server's own certificate so verification succeeds
		// rather than being switched off. Every other address category is still refused.
		PermitLoopback: true,
		RootCAs:        pool,
	})
	require.NoError(t, err)

	w.account = insertPublishingAccount(t, db, now)
	insertClaimedPlugin(t, db, now, w.plugin, w.account)

	pepper := core.NewSecret("a pepper that is not the production one")
	sessions, err := auth.NewSessions(db, clk, pepper)
	require.NoError(t, err)
	tokens, err := auth.NewTokens(db, clk, pepper)
	require.NoError(t, err)
	w.tokens = tokens

	cfg := api.Config{
		Clock:     clk,
		Authn:     auth.NewAuthenticator(sessions, tokens),
		Tokens:    tokens,
		Providers: identity.NewRegistry(stubProvider{}),
		Publisher: release.NewPublisher(db, clk, fetcher),
		// Configured, because the refusal an unclaimed id gets names where to claim it and this
		// is where that value comes from. An instance with none falls back to the path; naming
		// the live registry's own URL here keeps the fixture honest about what an author reads.
		PublicURL: "https://nparseplugins.prokopto.dev",
	}
	for _, m := range mutate {
		m(&cfg)
	}
	w.srv = httptest.NewServer(api.New(cfg))
	t.Cleanup(w.srv.Close)

	w.publishToken = w.mint(t, "the plugin's release workflow", "plugin:publish")
	w.readToken = w.mint(t, "a token that may only look", "plugin:read")

	// A second account holding a second id, so "claimed, and not by you" is a real row rather than
	// a hypothesis. Its owner never publishes here; it exists to be refused.
	w.somebodyElses = "merchant-mode-fork"
	insertClaimedPlugin(t, db, now, w.somebodyElses, insertPublishingAccountAs(t, db, now, "octocat"))

	unpinned, err := tokens.Mint(t.Context(), auth.MintRequest{
		AccountID: w.account,
		Name:      "any plugin you own",
		Scopes:    []authz.Scope{"plugin:publish"},
	})
	require.NoError(t, err)
	w.unpinnedToken = unpinned.Secret
	return w
}

// mint issues a token pinned to this world's plugin, exactly as the account page does.
func (w *publishWorld) mint(t *testing.T, name string, scope authz.Scope) string {
	t.Helper()

	minted, err := w.tokens.Mint(t.Context(), auth.MintRequest{
		AccountID: w.account,
		Name:      name,
		Scopes:    []authz.Scope{scope},
		// Pinned, because ADR-0005 wants the narrow choice to be the ordinary one and because a
		// pin nothing compares is decorative — the middleware compares it against `{id}`.
		PluginID: w.plugin,
	})
	require.NoError(t, err)
	return minted.Secret
}

// publish sends one release submission for this world's own plugin.
func (w *publishWorld) publish(t *testing.T, token, version, key string) response {
	t.Helper()

	return w.publishTo(t, w.plugin, token, version, key)
}

// publishTo sends one release submission with the token in an Authorization header, which is the
// only place a token is ever accepted.
func (w *publishWorld) publishTo(t *testing.T, pluginID, token, version, key string) response {
	t.Helper()

	body, err := json.Marshal(map[string]any{
		"version":         version,
		"artifact_url":    w.artifactURL,
		"artifact_sha256": w.artifactSHA256(),
		"sdk_specifier":   ">=1.0,<2",
	})
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		w.srv.URL+api.BasePath+"/plugins/"+pluginID+"/releases", strings.NewReader(string(body)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Idempotency-Key", key)

	// This server's own client, never a bare &http.Client{}: see harness.client.
	resp, err := w.srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	read, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return response{status: resp.StatusCode, header: resp.Header.Clone(), body: read}
}

// artifactSHA256 is the sha256 of the bytes the fixture actually serves. The submitted value is
// compared against the server's own and then discarded, so sending the truth is what keeps this
// test about authorisation rather than about a hash mismatch.
func (w *publishWorld) artifactSHA256() string {
	sum := sha256.Sum256(w.artifactBody)
	return hex.EncodeToString(sum[:])
}

// insertPublishingAccount creates an account WITH a GitHub identity, because only GitHub
// identities may publish (ADR-0011) and that is a CHECK on identity_provider.kind rather than a
// toggle. An account without one is refused by the domain, which would be a different test.
func insertPublishingAccount(t *testing.T, db *store.DB, now time.Time) string {
	t.Helper()
	return insertPublishingAccountAs(t, db, now, "prokopto-dev")
}

// insertPublishingAccountAs is the same thing under a named handle, for a fixture that needs a
// SECOND account. (provider, subject) is unique, so two accounts cannot share one.
func insertPublishingAccountAs(t *testing.T, db *store.DB, now time.Time, handle string) string {
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

// insertClaimedPlugin claims the id and grants it to the account, which is what makes the caller
// able to publish it — ownership is checked at the moment of the change (ADR-0005), not carried
// on the credential.
func insertClaimedPlugin(t *testing.T, db *store.DB, now time.Time, pluginID, accountID string) {
	t.Helper()

	require.NoError(t, db.Tx(t.Context(), func(q *store.Queries) error {
		if err := q.InsertPlugin(t.Context(), sqlitegen.InsertPluginParams{
			ID:        pluginID,
			Name:      "Merchant Mode",
			ClaimedAt: core.MicrosFromTime(now).Int64(),
			UpdatedAt: core.MicrosFromTime(now).Int64(),
		}); err != nil {
			return err
		}
		return q.InsertPluginOwner(t.Context(), sqlitegen.InsertPluginOwnerParams{
			PluginID:  pluginID,
			AccountID: accountID,
			Role:      ownership.RoleOwner.String(),
			GrantedAt: core.MicrosFromTime(now).Int64(),
		})
	}))
}
