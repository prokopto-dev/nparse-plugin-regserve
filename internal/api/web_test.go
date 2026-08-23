package api_test

import (
	"context"
	"errors"
	"io"
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
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
)

// The account surface.
//
// These are page tests: what is left to get wrong once internal/auth and internal/ownership are
// covered in their own packages is HTML — that the one-time secret appears exactly once, that a
// form without a valid token is refused before anything is read from it, and that a value coming
// from a provider cannot become markup.

const testSessionID = "sess-1"

func signedIn() auth.Principal {
	return auth.Principal{AccountID: "acct", DisplayName: "prokopto-dev", SessionID: testSessionID}
}

// fakeTokens is api.TokenService with the answers set per test.
type fakeTokens struct {
	minted    auth.NewToken
	mintErr   error
	listed    []auth.Listing
	revokeErr error

	sawMint   []auth.MintRequest
	sawRevoke []string
}

func (f *fakeTokens) Mint(_ context.Context, req auth.MintRequest) (auth.NewToken, error) {
	f.sawMint = append(f.sawMint, req)
	return f.minted, f.mintErr
}

func (f *fakeTokens) List(context.Context, string) ([]auth.Listing, error) { return f.listed, nil }

func (f *fakeTokens) Revoke(_ context.Context, _, tokenID string) error {
	f.sawRevoke = append(f.sawRevoke, tokenID)
	return f.revokeErr
}

// fakeOwnership is api.OwnershipService.
type fakeOwnership struct {
	mine   []ownership.Plugin
	owners []ownership.Owner
	role   ownership.Role
	addErr error
	rmErr  error

	sawAdd    []string
	sawRemove []string

	// claimErr is what ClaimID answers with, and sawClaim is every claim it was asked to make.
	// The real service is internal/ownership's and is tested there; what this fixture is for is
	// what the PAGE does with each answer.
	claimErr  error
	sawClaim  []ownership.Claim
	claimedBy []string
}

func (f *fakeOwnership) Mine(context.Context, string) ([]ownership.Plugin, error) {
	return f.mine, nil
}

func (f *fakeOwnership) Owners(_ context.Context, pluginID, _ string) ([]ownership.Owner, error) {
	for _, p := range f.mine {
		if p.ID == pluginID {
			return f.owners, nil
		}
	}
	return nil, ownership.ErrNotAnOwner
}

func (f *fakeOwnership) RoleOf(_ context.Context, pluginID, _ string) (ownership.Role, bool, error) {
	for _, p := range f.mine {
		if p.ID == pluginID {
			return f.role, true, nil
		}
	}
	return "", false, nil
}

func (f *fakeOwnership) Add(_ context.Context, _, _, handle string, _ ownership.Role) error {
	f.sawAdd = append(f.sawAdd, handle)
	return f.addErr
}

func (f *fakeOwnership) Remove(_ context.Context, _, _, targetID string) error {
	f.sawRemove = append(f.sawRemove, targetID)
	return f.rmErr
}

func (f *fakeOwnership) ClaimID(_ context.Context, c ownership.Claim, accountID string) error {
	f.sawClaim = append(f.sawClaim, c)
	f.claimedBy = append(f.claimedBy, accountID)
	return f.claimErr
}

// webHarness is a running account surface plus the fakes behind it.
type webHarness struct {
	srv       *httptest.Server
	authn     *fakeAuthn
	sessions  *fakeSessions
	tokens    *fakeTokens
	ownership *fakeOwnership

	// noClaimer builds the surface with no Claimer at all. See webHarness.claimer.
	noClaimer bool
}

func newWebHarness(t *testing.T, mutate ...func(h *webHarness)) *webHarness {
	t.Helper()

	h := &webHarness{
		authn:    &fakeAuthn{principal: signedIn()},
		sessions: &fakeSessions{},
		tokens: &fakeTokens{
			minted: auth.NewToken{
				Secret: auth.TokenPrefix + "abcd1234_" + strings.Repeat("s", 43),
				ID:     "tok-1",
				Prefix: "abcd1234",
			},
		},
		ownership: &fakeOwnership{
			role: ownership.RoleOwner,
			mine: []ownership.Plugin{{
				ID: "merchant-mode", Name: "Merchant Mode", Role: ownership.RoleOwner,
				Listed: true, HasApprovedRelease: true, GrantedAt: time.Unix(1, 0).UTC(),
			}},
			owners: []ownership.Owner{{
				AccountID: "acct", DisplayName: "prokopto-dev", Handle: "prokopto-dev",
				Role: ownership.RoleOwner, GrantedAt: time.Unix(1, 0).UTC(),
			}},
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
		Tokens:    h.tokens,
		Ownership: h.ownership,
		// The same object as Ownership, exactly as the serve command wires it: one service, two
		// consumer-declared interfaces.
		Claimer: h.claimer(),
	}))
	t.Cleanup(h.srv.Close)
	return h
}

// claimer is what the harness passes as api.Claimer. It is the fakeOwnership unless a test has
// asked for a build with none — noClaimer models a deployment that cannot register ids, where the
// form must not be offered at all rather than offered and answered 404.
func (h *webHarness) claimer() api.Claimer {
	if h.noClaimer {
		return nil
	}
	return h.ownership
}

// csrf is the value the fake session issuer expects back.
func (h *webHarness) csrf() string { return h.sessions.CSRFToken(signedIn()) }

func (h *webHarness) get(t *testing.T, path string) response {
	t.Helper()
	return h.request(t, http.MethodGet, path, nil)
}

func (h *webHarness) post(t *testing.T, path string, form url.Values) response {
	t.Helper()
	return h.request(t, http.MethodPost, path, form)
}

func (h *webHarness) request(t *testing.T, method, path string, form url.Values) response {
	t.Helper()

	var body *strings.Reader
	if form == nil {
		body = strings.NewReader("")
	} else {
		body = strings.NewReader(form.Encode())
	}

	req, err := http.NewRequestWithContext(t.Context(), method, h.srv.URL+path, body)
	require.NoError(t, err)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	// This server's own client, never a bare &http.Client{}: a shared http.DefaultTransport plus
	// httptest.Server.Close is how one parallel test severs another's connection.
	client := h.srv.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return response{status: resp.StatusCode, header: resp.Header.Clone(), body: raw}
}

// The home page moved. `/` is the PUBLIC plugin directory now, registered from the catalogue
// rather than from the sign-in machinery, and sign-in is a link in the header — so what used to be
// tested here is in directory_test.go: TestDirectory_IsPublic_AndListsEveryPlugin and
// TestDirectory_SignIn_IsAHeaderLinkAndOnlyWhenConfigured.

// TestHeader_EverySignedInPage_OffersTheWayBack — you can always get to your account.
//
// This is a REGRESSION test for a dead end that shipped. The header used to render the display
// name as plain text; the review queue has no back link of its own; and `/` could not tell a
// signed-in visitor from an anonymous one, so it offered them a sign-in link. A reviewer who
// clicked "review queue" was then stuck there unless they knew to type /account into the URL bar.
//
// Each page is asked separately rather than the layout being inspected once, because the layout is
// only half of it: a page that builds its pageData without an Account renders no nav at all, and
// that is exactly how one page ends up different from the others.
func TestHeader_EverySignedInPage_OffersTheWayBack(t *testing.T) {
	t.Parallel()

	// A HARNESS PER SUBTEST, built inside the closure. The harnesses share one http.Client and one
	// fakeAuthn, both of which record what they saw, so two parallel subtests driving the same one
	// is a data race — which is what `go test -race -shuffle=on` said the first time this ran.
	pages := []struct {
		name string
		body func(t *testing.T) string
	}{
		{name: "the account page", body: func(t *testing.T) string {
			return string(newReviewHarness(t).do(t, http.MethodGet, "/account", nil).body)
		}},
		{name: "the review queue", body: func(t *testing.T) string {
			return string(newReviewHarness(t).do(t, http.MethodGet, "/review", nil).body)
		}},
		{name: "a release under review", body: func(t *testing.T) string {
			path := "/review/releases/" + testReleaseID
			return string(newReviewHarness(t).do(t, http.MethodGet, path, nil).body)
		}},
		{name: "a plugin's settings", body: func(t *testing.T) string {
			return string(newWebHarness(t).get(t, "/plugins/merchant-mode/settings").body)
		}},
	}
	for _, page := range pages {
		t.Run(page.name, func(t *testing.T) {
			t.Parallel()

			body := page.body(t)
			require.Contains(t, body, `<a href="/account">your account</a>`,
				"%s must offer a way back to the account page", page.name)
			require.Contains(t, body, "sign out",
				"%s must offer a way out", page.name)
			require.NotContains(t, body, "sign in with GitHub",
				"%s is a signed-in page and must not tell the reader to sign in", page.name)
		})
	}
}

// TestAccountPage_IsCapabilityFloorAndPrivate — a browser surface is not a token surface.
func TestAccountPage_IsCapabilityFloorAndPrivate(t *testing.T) {
	t.Parallel()

	t.Run("a session reaches it", func(t *testing.T) {
		t.Parallel()

		h := newWebHarness(t)
		resp := h.get(t, "/account")

		require.Equal(t, http.StatusOK, resp.status)
		require.Contains(t, string(resp.body), "merchant-mode")
		// A page that depends on who is signed in must never be held by a shared cache, and
		// no-store is what keeps it out of the back-forward cache after a sign-out.
		require.Equal(t, "private, no-store", resp.header.Get("Cache-Control"))
	})

	t.Run("a token does not", func(t *testing.T) {
		t.Parallel()

		h := newWebHarness(t, func(h *webHarness) {
			h.authn.principal = auth.Principal{
				AccountID: "acct", TokenID: "tok", Scopes: authz.Scopes(),
			}
		})
		resp := h.get(t, "/account")

		require.Equal(t, http.StatusForbidden, resp.status,
			"every authenticated page here is capability-floor: a PAT must not authenticate a "+
				"browser surface")
	})

	t.Run("nobody does not", func(t *testing.T) {
		t.Parallel()

		h := newWebHarness(t, func(h *webHarness) { h.authn.err = auth.ErrNoCredential })
		require.Equal(t, http.StatusUnauthorized, h.get(t, "/account").status)
	})
}

// TestMintToken_ShowsTheSecretExactlyOnce — the one property the whole storage design rests on.
func TestMintToken_ShowsTheSecretExactlyOnce(t *testing.T) {
	t.Parallel()

	h := newWebHarness(t)

	resp := h.post(t, "/account/tokens", url.Values{
		auth.CSRFFieldName: {h.csrf()},
		"name":             {"merchant-mode release"},
		"scope":            {"plugin:publish"},
		"plugin_id":        {"merchant-mode"},
	})

	require.Equal(t, http.StatusOK, resp.status)
	require.Contains(t, string(resp.body), h.tokens.minted.Secret,
		"the secret is rendered into this response and nowhere else")

	require.Len(t, h.tokens.sawMint, 1)
	require.Equal(t, "merchant-mode release", h.tokens.sawMint[0].Name)
	require.Equal(t, []authz.Scope{"plugin:publish"}, h.tokens.sawMint[0].Scopes)
	require.Equal(t, "merchant-mode", h.tokens.sawMint[0].PluginID)

	// And never again. The server cannot show it a second time even if it wanted to — what it
	// stored is a keyed hash — so the account page must not carry it.
	again := h.get(t, "/account")
	require.Equal(t, http.StatusOK, again.status)
	require.NotContains(t, string(again.body), h.tokens.minted.Secret)
}

// TestMintToken_TheSecretIsNeverPutInAURL — canonical §6 has no exception, including for us.
//
// An earlier draft of this page redirected to `/account?minted=nprs_pat_…`, which this service's
// own middleware refuses with 401 — correctly. A URL is a thing that reaches access logs, proxy
// logs and browser history, and it makes no difference that we were the ones who wrote it.
func TestMintToken_TheSecretIsNeverPutInAURL(t *testing.T) {
	t.Parallel()

	h := newWebHarness(t)
	resp := h.post(t, "/account/tokens", url.Values{
		auth.CSRFFieldName: {h.csrf()},
		"name":             {"x"},
		"scope":            {"plugin:publish"},
	})

	require.Equal(t, http.StatusOK, resp.status, "a redirect would have to carry it somewhere")
	require.Empty(t, resp.header.Get("Location"))
	require.NotContains(t, resp.header.Get("Location"), auth.TokenPrefix)
}

// TestMutatingForms_WithoutAValidCSRFToken_AreRefused — a session cookie plus a form post.
//
// SameSite=Lax already withholds the cookie from a cross-site POST in every browser that matters.
// That is a browser behaviour this repository neither controls nor can test; the form token is the
// half that is ours, and it is checked on EVERY mutating form.
func TestMutatingForms_WithoutAValidCSRFToken_AreRefused(t *testing.T) {
	t.Parallel()

	forms := []struct {
		name string
		path string
		body url.Values
	}{
		{name: "mint a token", path: "/account/tokens", body: url.Values{"name": {"x"}, "scope": {"plugin:publish"}}},
		// A field the form does not use, so the body is not empty. A forged cross-site form
		// carries whatever its author put in it; an entirely empty POST is a different, degenerate
		// case, covered separately below.
		{name: "revoke a token", path: "/account/tokens/tok-1/revoke", body: url.Values{"submit": {"revoke"}}},
		{name: "claim a plugin id", path: "/account/plugins", body: url.Values{"id": {"floating-combat-text"}, "name": {"Floating Combat Text"}}},
		{name: "add an owner", path: "/plugins/merchant-mode/owners", body: url.Values{"action": {"add"}, "handle": {"octocat"}}},
		{name: "remove an owner", path: "/plugins/merchant-mode/owners", body: url.Values{"action": {"remove"}, "account_id": {"acct"}}},
	}

	tokens := []struct {
		name  string
		value string
	}{
		{name: "no token at all", value: ""},
		{name: "a wrong token", value: "not-the-token"},
		{name: "a token from another session", value: "csrf-for-somebody-else"},
	}

	for _, form := range forms {
		for _, token := range tokens {
			t.Run(form.name+" with "+token.name, func(t *testing.T) {
				t.Parallel()

				h := newWebHarness(t)
				body := url.Values{}
				for k, v := range form.body {
					body[k] = v
				}
				if token.value != "" {
					body.Set(auth.CSRFFieldName, token.value)
				}

				resp := h.post(t, form.path, body)
				require.Equal(t, http.StatusForbidden, resp.status)

				// Refused BEFORE anything is read from the form. A handler that validates input
				// first has already done work on behalf of a request it is about to refuse.
				require.Empty(t, h.tokens.sawMint)
				require.Empty(t, h.tokens.sawRevoke)
				require.Empty(t, h.ownership.sawAdd)
				require.Empty(t, h.ownership.sawRemove)
			})
		}
	}
}

// TestMutatingForms_WithNoBodyAtAll_AreRefused — the degenerate case, refused for its own reason.
//
// A form post with no body is malformed rather than unauthorised, and Huma answers 400 before a
// handler runs. What matters is that it is refused and that nothing happened; which of the two
// reasons it gives is not something a caller can act on differently.
func TestMutatingForms_WithNoBodyAtAll_AreRefused(t *testing.T) {
	t.Parallel()

	for _, path := range []string{
		"/account/tokens",
		"/account/tokens/tok-1/revoke",
		"/plugins/merchant-mode/owners",
	} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			h := newWebHarness(t)
			resp := h.post(t, path, url.Values{})

			require.GreaterOrEqual(t, resp.status, http.StatusBadRequest, "%s must refuse", path)
			require.Empty(t, h.tokens.sawMint)
			require.Empty(t, h.tokens.sawRevoke)
			require.Empty(t, h.ownership.sawAdd)
			require.Empty(t, h.ownership.sawRemove)
		})
	}
}

func TestRevokeToken_RedirectsBackWithAMessage(t *testing.T) {
	t.Parallel()

	h := newWebHarness(t)
	resp := h.post(t, "/account/tokens/tok-1/revoke", url.Values{
		auth.CSRFFieldName: {h.csrf()},
	})

	// Post/redirect/get, so a refresh re-issues the GET rather than the POST.
	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Equal(t, "/account?msg=token_revoked", resp.header.Get("Location"))
	require.Equal(t, []string{"tok-1"}, h.tokens.sawRevoke)
}

// TestPages_RenderOnlyMessagesThisPackageWrote — prose in a query string is prose an attacker chose.
//
// A crafted link would otherwise render their sentence inside our page, under our domain. It would
// be escaped — html/template sees to that — and it would still say what they wrote.
func TestPages_RenderOnlyMessagesThisPackageWrote(t *testing.T) {
	t.Parallel()

	h := newWebHarness(t)

	t.Run("a known code renders its own sentence", func(t *testing.T) {
		body := string(h.get(t, "/account?msg=token_revoked").body)
		require.Contains(t, body, "Token revoked.")
	})

	t.Run("an attacker's sentence renders nothing", func(t *testing.T) {
		crafted := "Your%20account%20was%20compromised.%20Call%20555-1234."
		body := string(h.get(t, "/account?msg="+crafted).body)
		require.NotContains(t, body, "555-1234")
		require.NotContains(t, body, "compromised")
	})
}

// TestPages_EscapeValuesThatCameFromAProvider — html/template, doing its job, asserted.
//
// A display name and a handle are whatever GitHub returned. The templates never reach for
// template.HTML, and this is what would notice if one started to.
func TestPages_EscapeValuesThatCameFromAProvider(t *testing.T) {
	t.Parallel()

	h := newWebHarness(t, func(h *webHarness) {
		h.authn.principal = auth.Principal{
			AccountID:   "acct",
			DisplayName: `<script>alert(1)</script>`,
			SessionID:   testSessionID,
		}
		h.ownership.owners = []ownership.Owner{{
			AccountID: "acct",
			Handle:    `"><img src=x onerror=alert(1)>`,
			Role:      ownership.RoleOwner,
		}}
	})

	for _, path := range []string{"/account", "/plugins/merchant-mode/settings"} {
		body := string(h.get(t, path).body)

		// The assertion is about MARKUP, not about the characters. `onerror=alert(1)` appearing as
		// text inside an escaped element is inert; an unescaped `<img` or `<script` is not. A test
		// that matched the payload's text would fail on correct output and pass on a page that
		// stripped the value entirely.
		require.NotContains(t, body, "<script", "%s rendered a raw element", path)
		require.NotContains(t, body, "<img", "%s rendered a raw element", path)

		// And the value IS rendered, escaped. Dropping it would also pass the assertions above.
		require.Contains(t, body, "&lt;script&gt;alert(1)&lt;/script&gt;",
			"%s must render the display name, escaped", path)
	}
}

// TestPluginSettings_NotYours_IsANotFound — not a 403.
//
// Telling a signed-in account "that plugin exists and is not yours" hands them an oracle for which
// ids exist, which is the same information the id-squatting rules exist to protect.
func TestPluginSettings_NotYours_IsANotFound(t *testing.T) {
	t.Parallel()

	h := newWebHarness(t)

	for _, path := range []string{
		"/plugins/raid-tools/settings",
		"/plugins/NOT-A-VALID-ID/settings",
	} {
		resp := h.get(t, path)
		require.Equal(t, http.StatusNotFound, resp.status, "%s", path)
	}
}

func TestManageOwners_AddAndRemove(t *testing.T) {
	t.Parallel()

	t.Run("add", func(t *testing.T) {
		t.Parallel()

		h := newWebHarness(t)
		resp := h.post(t, "/plugins/merchant-mode/owners", url.Values{
			auth.CSRFFieldName: {h.csrf()},
			"action":           {"add"},
			"handle":           {"octocat"},
			"role":             {"maintainer"},
		})

		require.Equal(t, http.StatusSeeOther, resp.status)
		require.Equal(t, "/plugins/merchant-mode/settings?msg=owners_updated",
			resp.header.Get("Location"))
		require.Equal(t, []string{"octocat"}, h.ownership.sawAdd)
	})

	t.Run("a handle nobody has signed in with", func(t *testing.T) {
		t.Parallel()

		h := newWebHarness(t, func(h *webHarness) { h.ownership.addErr = ownership.ErrNoSuchAccount })
		resp := h.post(t, "/plugins/merchant-mode/owners", url.Values{
			auth.CSRFFieldName: {h.csrf()},
			"action":           {"add"},
			"handle":           {"nobody"},
		})

		require.Equal(t, http.StatusSeeOther, resp.status)
		require.Equal(t, "/plugins/merchant-mode/settings?msg=owner_unknown",
			resp.header.Get("Location"))
	})

	t.Run("removing the last owner", func(t *testing.T) {
		t.Parallel()

		h := newWebHarness(t, func(h *webHarness) { h.ownership.rmErr = ownership.ErrLastOwner })
		resp := h.post(t, "/plugins/merchant-mode/owners", url.Values{
			auth.CSRFFieldName: {h.csrf()},
			"action":           {"remove"},
			"account_id":       {"acct"},
		})

		require.Equal(t, "/plugins/merchant-mode/settings?msg=owner_last",
			resp.header.Get("Location"))
	})

	t.Run("an action the form does not do", func(t *testing.T) {
		t.Parallel()

		h := newWebHarness(t)
		resp := h.post(t, "/plugins/merchant-mode/owners", url.Values{
			auth.CSRFFieldName: {h.csrf()},
			"action":           {"delete-everything"},
		})

		require.Equal(t, http.StatusBadRequest, resp.status)
		require.Empty(t, h.ownership.sawAdd)
		require.Empty(t, h.ownership.sawRemove)
	})
}

// TestAccountSurface_IsNotRegisteredWithoutItsDependencies — an honest 404.
func TestAccountSurface_IsNotRegisteredWithoutItsDependencies(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(api.New(api.Config{}))
	t.Cleanup(srv.Close)

	for _, path := range []string{"/", "/account", "/plugins/merchant-mode/settings"} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
		require.NoError(t, err)

		resp, err := srv.Client().Do(req)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusNotFound, resp.StatusCode, "%s must not be served", path)
	}
}

// TestPluginSettings_AMaintainer_IsNotOfferedControlsTheServiceWillRefuse.
//
// A maintainer holds the plugin and may publish to it; only an owner may change who holds it.
// Rendering the forms anyway would teach people the service is broken, and the page and the
// refusal read the same fact through Role.CanManageOwners.
func TestPluginSettings_AMaintainer_IsNotOfferedControlsTheServiceWillRefuse(t *testing.T) {
	t.Parallel()

	h := newWebHarness(t, func(h *webHarness) { h.ownership.role = ownership.RoleMaintainer })
	body := string(h.get(t, "/plugins/merchant-mode/settings").body)

	require.NotContains(t, body, `name="handle"`, "the add-an-owner form must not be rendered")
	require.NotContains(t, body, `value="remove"`, "the remove buttons must not be rendered")
	require.Contains(t, body, "as a <strong>maintainer</strong>",
		"and the page says why, rather than looking like it is missing something")

	// They still see who else holds it: a co-maintainer publishing to this plugin needs to know.
	require.Contains(t, body, "Owners")
}

func TestPluginSettings_AnOwner_IsOfferedTheForms(t *testing.T) {
	t.Parallel()

	// The other side of the boundary. A page that rendered the forms for nobody would pass the
	// assertions above.
	h := newWebHarness(t)
	body := string(h.get(t, "/plugins/merchant-mode/settings").body)

	require.Contains(t, body, `name="handle"`)
	require.Contains(t, body, "Add an owner")
}

// TestManageOwners_AMaintainersPost_IsRefusedByTheService — hiding the form is not the control.
//
// The form is not rendered for a maintainer, and a form that is not rendered is a form somebody can
// still post. The refusal lives in internal/ownership, inside the transaction; this is the page
// reporting it as something a person can read.
func TestManageOwners_AMaintainersPost_IsRefusedByTheService(t *testing.T) {
	t.Parallel()

	h := newWebHarness(t, func(h *webHarness) {
		h.ownership.role = ownership.RoleMaintainer
		h.ownership.addErr = ownership.ErrRoleCannotManageOwners
	})

	resp := h.post(t, "/plugins/merchant-mode/owners", url.Values{
		auth.CSRFFieldName: {h.csrf()},
		"action":           {"add"},
		"handle":           {"accomplice"},
		"role":             {"owner"},
	})

	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Equal(t, "/plugins/merchant-mode/settings?msg=owner_role_too_narrow",
		resp.header.Get("Location"))

	body := string(h.get(t, "/plugins/merchant-mode/settings?msg=owner_role_too_narrow").body)
	require.Contains(t, body, "Only an owner can change who holds it.")
}

// --- claiming a plugin id ----------------------------------------------------------------------

// TestAccountPage_OffersAWayToClaimAnID — the affordance that did not exist.
//
// THIS IS A REGRESSION TEST FOR A SHIPPED DEAD END. Claiming is capability-floor, so it is
// session-only, so a browser is the ONLY place it can happen — and the browser surface had no form
// for it. The account page offered a token mint and nothing else, and its empty state explained a
// migration from owners.json, which told a first-time author to go and report a problem when what
// they needed was to claim an id. An author with a repository, a build and a token could not find
// the one step that would make any of it work.
func TestAccountPage_OffersAWayToClaimAnID(t *testing.T) {
	t.Parallel()

	t.Run("the form is on the page", func(t *testing.T) {
		t.Parallel()

		body := string(newWebHarness(t).get(t, "/account").body)
		require.Contains(t, body, `action="/account/plugins"`)
		require.Contains(t, body, "Claim a plugin id")
		require.Contains(t, body, `name="id"`, "with somewhere to type the id")
		require.Contains(t, body, "permanent",
			"and the one warning that cannot be undone afterwards")
	})

	t.Run("and the token explainer says a token cannot do it", func(t *testing.T) {
		t.Parallel()

		// The omission was load-bearing: the list of what a token cannot do named minting,
		// ownership and trust, and not claiming — which is part of why the author believed the
		// token he had was the whole credential he needed.
		body := string(newWebHarness(t).get(t, "/account").body)
		require.Contains(t, body, "claim a plugin id")
		require.Contains(t, body, "browser session")
	})

	t.Run("and an account holding nothing is pointed at the claim, not at a migration", func(t *testing.T) {
		t.Parallel()

		h := newWebHarness(t, func(h *webHarness) { h.ownership.mine = nil })
		body := string(h.get(t, "/account").body)

		require.Contains(t, body, "Claim an id below",
			"the empty state is where a first-time author lands")
		require.Contains(t, body, "could publish nothing",
			"and minting a token while owning no plugin is a credential that cannot publish")
	})

	t.Run("while a build with no claimer sends nobody looking for a form", func(t *testing.T) {
		t.Parallel()

		// AND OWNING NOTHING, which is the state the guidance renders in. An earlier version of
		// this test used the default fixture, which holds a plugin — so the empty state never
		// rendered, and the copy telling a reader to "claim an id below" on a build with no form
		// below went unnoticed. A gate that cannot reach the strings it is guarding is not a gate.
		h := newWebHarness(t, func(h *webHarness) {
			h.noClaimer = true
			h.ownership.mine = nil
		})
		body := string(h.get(t, "/account").body)

		require.NotContains(t, body, `action="/account/plugins"`,
			"a form posting to a route this build does not serve is an on-ramp ending in a 404")
		for _, directive := range []string{
			"Claim an id below", "Claim your id first", "Claim an id above",
		} {
			require.NotContainsf(t, body, directive,
				"%q sends the reader to a form this build does not serve", directive)
		}

		// And says so, rather than going quiet: an empty page with no explanation is
		// indistinguishable from a broken one, which is the failure this whole page is about.
		require.Contains(t, body, "cannot register new plugin ids")

		// What stays true whatever is wired: a token could never have claimed an id anyway.
		require.Contains(t, body, "claim a plugin id",
			"the token explainer is a fact about tokens, not about this deployment")

		require.Equal(t, http.StatusNotFound, h.post(t, "/account/plugins", url.Values{
			auth.CSRFFieldName: {h.csrf()},
			"id":               {"floating-combat-text"},
			"name":             {"Floating Combat Text"},
		}).status)
	})
}

// TestClaimForm_ClaimsForTheSignedInAccount_AndSaysWhatHappened.
//
// The account id comes from the SESSION and from nowhere else — there is no on-behalf-of field and
// there must never be one, because an id is permanent and a claim made for the wrong account
// cannot be corrected, only handed over.
func TestClaimForm_ClaimsForTheSignedInAccount_AndSaysWhatHappened(t *testing.T) {
	t.Parallel()

	h := newWebHarness(t)

	resp := h.post(t, "/account/plugins", url.Values{
		auth.CSRFFieldName: {h.csrf()},
		"id":               {"floating-combat-text"},
		"name":             {"Floating Combat Text"},
		"description":      {"Damage numbers that float."},
		"author":           {"BennyTwoThumbs"},
		"homepage":         {"https://github.com/example/floating-combat-text"},
	})

	require.Equal(t, http.StatusSeeOther, resp.status, "post/redirect/get, like every other form")
	require.Equal(t, "/account?msg=plugin_claimed", resp.header.Get("Location"))

	require.Len(t, h.ownership.sawClaim, 1)
	require.Equal(t, core.PluginID("floating-combat-text"), h.ownership.sawClaim[0].PluginID)
	require.Equal(t, "Floating Combat Text", h.ownership.sawClaim[0].Name)
	require.Equal(t, "https://github.com/example/floating-combat-text", h.ownership.sawClaim[0].Homepage)
	require.Equal(t, []string{signedIn().AccountID}, h.ownership.claimedBy,
		"the claimant is the session's account, never a field somebody submitted")

	// And the page that lands says what was and was not done: an id is claimed, nothing is listed.
	landed := h.get(t, "/account?msg=plugin_claimed")
	require.Contains(t, string(landed.body), "not listed yet")
}

// TestClaimForm_EachRefusal_SaysWhatToDoAndNothingAboutWhoHoldsWhat.
func TestClaimForm_EachRefusal_SaysWhatToDoAndNothingAboutWhoHoldsWhat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   string
		err  error

		wantMessage string
		wantPage    string
		wantCalled  bool
	}{
		{
			name: "an id somebody already holds",
			id:   "merchant-mode",
			err:  ownership.ErrAlreadyClaimed,
			// It says the id is taken and NOT who has it. The set of listed ids is public; which
			// account holds an unlisted one is not, and answering that would make this form a way
			// to map ids to people.
			wantMessage: "plugin_id_taken",
			wantPage:    "already claimed",
			wantCalled:  true,
		},
		{
			name: "a malformed id",
			id:   "Not An Id",
			// Refused HERE, before the service is called at all: the rule is core.ParsePluginID's,
			// so the form cannot accept something the JSON endpoint would refuse.
			wantMessage: "plugin_id_invalid",
			wantPage:    "lowercase letter",
			wantCalled:  false,
		},
		{
			name:        "a listing the columns will not take",
			id:          "floating-combat-text",
			err:         ownership.ErrBadListing,
			wantMessage: "plugin_details_invalid",
			wantPage:    "https URL",
			wantCalled:  true,
		},
		{
			name:        "anything else",
			id:          "floating-combat-text",
			err:         errors.New("the database fell over"),
			wantMessage: "plugin_claim_failed",
			wantPage:    "could not be claimed",
			wantCalled:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newWebHarness(t, func(h *webHarness) { h.ownership.claimErr = tc.err })
			resp := h.post(t, "/account/plugins", url.Values{
				auth.CSRFFieldName: {h.csrf()},
				"id":               {tc.id},
				"name":             {"Something"},
			})

			require.Equal(t, http.StatusSeeOther, resp.status)
			require.Equal(t, "/account?msg="+tc.wantMessage, resp.header.Get("Location"))
			require.Equal(t, tc.wantCalled, len(h.ownership.sawClaim) == 1)

			// The message a redirect carries is a CODE looked up in a fixed table, so what renders
			// is prose this package wrote. Following it is what proves the code resolves to
			// something rather than to silence.
			landed := h.get(t, "/account?msg="+tc.wantMessage)
			require.Contains(t, string(landed.body), tc.wantPage)
			require.NotContains(t, string(landed.body), "prokopto-dev holds",
				"a refusal never says who holds an id")
		})
	}
}

// TestClaimForm_IsCapabilityFloor — no token, however scoped, reaches the form.
//
// The JSON endpoint's floor has been enforced since it was registered. Adding a second door onto
// the same act is exactly how a floor gets a hole in it, so the door is asserted here rather than
// assumed from the declaration it shares.
func TestClaimForm_IsCapabilityFloor(t *testing.T) {
	t.Parallel()

	h := newWebHarness(t, func(h *webHarness) {
		h.authn.principal = auth.Principal{
			AccountID: "acct", DisplayName: "prokopto-dev",
			TokenID: "tok-1", Scopes: authz.Scopes(),
		}
	})

	resp := h.post(t, "/account/plugins", url.Values{
		auth.CSRFFieldName: {h.csrf()},
		"id":               {"floating-combat-text"},
		"name":             {"Floating Combat Text"},
	})

	require.Equal(t, http.StatusForbidden, resp.status)
	// The refusal has to be THE FLOOR's and not the CSRF check's, which is also a 403 with nothing
	// claimed. Reading the sentence is what tells the two apart.
	require.Contains(t, string(resp.body), "session-only")
	require.Empty(t, h.ownership.sawClaim, "refused before the handler ran")
}
