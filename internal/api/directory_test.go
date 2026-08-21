package api_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

// The public plugin directory.
//
// What is left to get wrong once internal/plugin's search is covered against a real database is
// the PAGE: that it is reachable with no credential at all, that a search is a link, that a
// visitor's own text comes back as text, and that the rows this service declines to show are
// counted where somebody can see them.

// fakeDirectory is api.Directory. The search is a substring match here rather than the real query
// — what these tests are about is what the page does with an answer, and internal/plugin is where
// the answer itself is checked against SQLite.
type fakeDirectory struct {
	fakeCatalogue
	awaiting int
	delisted int
	err      error

	// sawQuery records every query the page passed down, which is how the truncation test checks
	// that the cap is applied BEFORE the store is asked rather than after it answers.
	sawQuery []string
}

func (f *fakeDirectory) Browse(_ context.Context, query string) (api.Browsed, error) {
	f.sawQuery = append(f.sawQuery, query)
	if f.err != nil {
		return api.Browsed{}, f.err
	}

	matched := make([]registry.Plugin, 0, len(f.plugins))
	for _, p := range f.plugins {
		haystack := strings.ToLower(p.ID + " " + p.Name + " " + p.Description + " " + p.Author)
		if strings.Contains(haystack, strings.ToLower(query)) {
			matched = append(matched, p)
		}
	}
	return api.Browsed{
		Plugins:  matched,
		Listed:   len(f.plugins),
		Awaiting: f.awaiting,
		Delisted: f.delisted,
	}, nil
}

func directoryOf(plugins ...registry.Plugin) *fakeDirectory {
	return &fakeDirectory{fakeCatalogue: fakeCatalogue{plugins: plugins}}
}

func described(id, name, description, author string) registry.Plugin {
	p := testPlugin(id)
	p.Name, p.Description, p.Author = name, description, author
	return p
}

// browse serves cfg and performs one GET, with no credential of any kind.
func browse(t *testing.T, cfg api.Config, path string) response {
	t.Helper()

	srv := httptest.NewServer(api.New(cfg))
	t.Cleanup(srv.Close)
	return fetch(t, srv, path, "")
}

// TestDirectory_IsPublic_AndListsEveryPlugin — the point of the page.
//
// `GET /index.json` is unauthenticated, so a human-readable view of the same catalogue that asked
// who you were first would be a worse-informed version of a document anybody can already fetch.
func TestDirectory_IsPublic_AndListsEveryPlugin(t *testing.T) {
	t.Parallel()

	dir := directoryOf(
		described("merchant-mode", "Merchant Mode", "linkable auction macros", "prokopto-dev"),
		described("spell-timers", "Spell Timers", "casting bars", "someone-else"),
	)
	resp := browse(t, api.Config{
		Directory: dir,
		PublicURL: "https://nparseplugins.prokopto.dev",
	}, "/")

	require.Equal(t, http.StatusOK, resp.status, "the directory needs no credential")
	require.Equal(t, "text/html; charset=utf-8", resp.header.Get("Content-Type"))

	body := string(resp.body)
	for _, want := range []string{
		"Merchant Mode", "merchant-mode", "linkable auction macros", "prokopto-dev",
		"Spell Timers", "spell-timers",
		`href="/plugins/merchant-mode"`,
		"2 plugins listed.",
		// The most likely reason somebody is on this page is to add the registry to their client.
		"https://nparseplugins.prokopto.dev/index.json",
	} {
		require.Containsf(t, body, want, "the directory must show %q", want)
	}
}

// TestDirectory_WithNoPublicURL_ShowsThePathRatherThanAGuess.
//
// A Host header is caller-controlled, and the one line of the page telling somebody what to paste
// into their client is the last place to start trusting one.
func TestDirectory_WithNoPublicURL_ShowsThePathRatherThanAGuess(t *testing.T) {
	t.Parallel()

	body := string(browse(t, api.Config{Directory: directoryOf(testPlugin("alpha"))}, "/").body)
	require.Contains(t, body, "/index.json")
	require.NotContains(t, body, "127.0.0.1", "the page must not echo the request's host")
}

// TestDirectory_Search_IsALinkableGetForm — the query is in the URL, so the result is a link.
func TestDirectory_Search_IsALinkableGetForm(t *testing.T) {
	t.Parallel()

	dir := directoryOf(
		described("merchant-mode", "Merchant Mode", "auction macros", "prokopto-dev"),
		described("spell-timers", "Spell Timers", "casting bars", "someone-else"),
	)
	resp := browse(t, api.Config{Directory: dir}, "/?q=merchant")

	require.Equal(t, http.StatusOK, resp.status)
	body := string(resp.body)
	require.Equal(t, []string{"merchant"}, dir.sawQuery)
	require.Contains(t, body, "Merchant Mode")
	require.NotContains(t, body, "Spell Timers")
	require.Contains(t, body, "1 of 2 listed plugins")
	// The box comes back filled in, so a search can be refined rather than retyped.
	require.Contains(t, body, `value="merchant"`)
	require.Contains(t, body, `method="get"`,
		"a POST would answer the same question and produce a page nobody can link to")
}

// TestDirectory_NothingMatched_SaysSoPlainly — and says how to see everything again.
func TestDirectory_NothingMatched_SaysSoPlainly(t *testing.T) {
	t.Parallel()

	dir := directoryOf(testPlugin("alpha"), testPlugin("beta"))
	body := string(browse(t, api.Config{Directory: dir}, "/?q=nothing-like-this").body)

	require.Contains(t, body, "Nothing matched")
	require.Contains(t, body, "All 2 listed")
	require.Contains(t, body, "shown by an empty search")
}

// TestDirectory_AnOverlongQuery_IsTruncatedRatherThanRefused.
//
// A cap is not optional on a field that reaches a database: without one, the length of the string
// scanned against every row is chosen by the caller. Refusing outright would be a search box that
// answers a pasted paragraph with an error document, so it is cut and the page says it was.
func TestDirectory_AnOverlongQuery_IsTruncatedRatherThanRefused(t *testing.T) {
	t.Parallel()

	dir := directoryOf(testPlugin("alpha"))
	resp := browse(t, api.Config{Directory: dir}, "/?q="+strings.Repeat("a", 500))

	require.Equal(t, http.StatusOK, resp.status, "a long search is not a client error")
	require.Len(t, dir.sawQuery, 1)
	require.Len(t, dir.sawQuery[0], 128, "the cap is applied before the store is asked")
	require.Contains(t, string(resp.body), "longer than this registry matches on")
}

// TestDirectory_ASearchTerm_ComesBackAsTextAndNeverAsMarkup.
//
// The search box is the one value on any of these pages that comes from a caller and is rendered
// back to them. html/template escapes by position, and this is the test that says so out loud.
func TestDirectory_ASearchTerm_ComesBackAsTextAndNeverAsMarkup(t *testing.T) {
	t.Parallel()

	dir := directoryOf(testPlugin("alpha"))
	body := string(browse(t, api.Config{Directory: dir}, `/?q=%22%3E%3Cscript%3Ealert(1)%3C%2Fscript%3E`).body)

	require.NotContains(t, body, "<script>alert(1)</script>")
	require.Contains(t, body, "&lt;script&gt;", "the term is shown, as text")
}

// TestDirectory_HiddenRows_AreCounted — never hide a row silently.
func TestDirectory_HiddenRows_AreCounted(t *testing.T) {
	t.Parallel()

	dir := directoryOf(testPlugin("alpha"))
	dir.awaiting, dir.delisted = 2, 1

	body := string(browse(t, api.Config{Directory: dir}, "/").body)
	require.Contains(t, body, "2 claimed ids are not shown")
	require.Contains(t, body, "1 delisted id is not shown")
	require.Contains(t, body, "never recycled")
}

// TestDirectory_UnreadableCatalogue_IsAnErrorAndNotAnEmptyPage.
//
// An empty directory and a directory that could not be read look identical to a visitor, and only
// one of them is true. This service does not serve the pleasant-looking one.
func TestDirectory_UnreadableCatalogue_IsAnErrorAndNotAnEmptyPage(t *testing.T) {
	t.Parallel()

	dir := directoryOf(testPlugin("alpha"))
	dir.err = errors.New("the database is on fire")
	resp := browse(t, api.Config{Directory: dir}, "/")

	require.Equal(t, http.StatusInternalServerError, resp.status)
	require.NotContains(t, string(resp.body), "Nothing is listed yet")
}

// TestPluginListingPage_IsPublic_AndShowsTheRelease.
func TestPluginListingPage_IsPublic_AndShowsTheRelease(t *testing.T) {
	t.Parallel()

	p := described("merchant-mode", "Merchant Mode", "linkable auction macros", "prokopto-dev")
	p.Latest.ReleaseNotes = "Fixed the recast timer.\nAdded a keybind."
	resp := browse(t, api.Config{Directory: directoryOf(p)}, "/plugins/merchant-mode")

	require.Equal(t, http.StatusOK, resp.status)
	body := string(resp.body)
	for _, want := range []string{
		"Merchant Mode", "merchant-mode", "linkable auction macros", "prokopto-dev",
		"1.0.0", p.Latest.SHA256, p.Latest.URL,
		"2.1.0", // the minimum app version, shown as a floor
		"Fixed the recast timer.\nAdded a keybind.", // plain text, newlines preserved
		`href="/plugins/merchant-mode/index.json"`,
	} {
		require.Containsf(t, body, want, "the listing page must show %q", want)
	}
}

// TestPluginListingPage_UnknownDelistedAndMalformed_AreTheSameAnswer.
//
// A visitor cannot tell a delisted plugin from one that never existed, and neither can anybody
// enumerating ids. The malformed case is here too: reporting WHY an id was rejected would be an
// oracle for which ids are merely absent.
func TestPluginListingPage_UnknownDelistedAndMalformed_AreTheSameAnswer(t *testing.T) {
	t.Parallel()

	cfg := api.Config{Directory: directoryOf(testPlugin("alpha"))}
	for _, path := range []string{"/plugins/never-existed", "/plugins/NOT-VALID", "/plugins/9lives"} {
		resp := browse(t, cfg, path)
		require.Equalf(t, http.StatusNotFound, resp.status, "%s", path)
		require.NotContains(t, string(resp.body), "pattern",
			"the refusal must not explain itself into an oracle")
	}
}

// TestDirectory_IsNotRegisteredWithoutACatalogue — an honest 404, not an empty page.
func TestDirectory_IsNotRegisteredWithoutACatalogue(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"/", "/plugins/alpha"} {
		resp := browse(t, api.Config{}, path)
		require.Equalf(t, http.StatusNotFound, resp.status, "%s must not be served", path)
	}
}

// TestDirectory_ATokenShapedSearch_IsRefusedBeforeTheHandler.
//
// Canonical §6 refuses a token in a query string with NO exception, and this service enforces it
// on every request before a handler runs — including a search box that happens to contain one.
// Pinned here because it is surprising: it is the rule working, not the search failing.
func TestDirectory_ATokenShapedSearch_IsRefusedBeforeTheHandler(t *testing.T) {
	t.Parallel()

	dir := directoryOf(testPlugin("alpha"))
	resp := browse(t, api.Config{Directory: dir}, "/?q="+auth.TokenPrefix+"abcd1234")

	require.Equal(t, http.StatusUnauthorized, resp.status)
	require.Empty(t, dir.sawQuery, "the refusal happens before the page is rendered")
}

// TestDirectory_SignIn_IsAHeaderLinkAndOnlyWhenConfigured.
//
// The front page stopped being a sign-in page. Where sign-in is not configured at all, the header
// offers nothing rather than a link that leads to a 404.
func TestDirectory_SignIn_IsAHeaderLinkAndOnlyWhenConfigured(t *testing.T) {
	t.Parallel()

	withSignIn := string(browse(t, api.Config{
		Directory: directoryOf(testPlugin("alpha")),
		Providers: identity.NewRegistry(stubProvider{}),
	}, "/").body)
	require.Contains(t, withSignIn, "/auth/github/login?next=/account")
	require.Contains(t, withSignIn, "sign in with GitHub")

	without := string(browse(t, api.Config{Directory: directoryOf(testPlugin("alpha"))}, "/").body)
	require.NotContains(t, without, "/auth/github/login")
}

// browseAs performs one GET carrying the given credential headers.
func browseAs(t *testing.T, cfg api.Config, path string, set func(*http.Request)) response {
	t.Helper()

	srv := httptest.NewServer(api.New(cfg))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+path, nil)
	require.NoError(t, err)
	set(req)

	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	defer func() { require.NoError(t, resp.Body.Close()) }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return response{status: resp.StatusCode, header: resp.Header.Clone(), body: body}
}

// TestDirectory_ASignedInVisitor_IsNotToldToSignIn.
//
// A public page is still read by people who are signed in, and a header offering them a sign-in
// link would be the page stating something false about the reader's own state. The session is
// resolved for DECORATION only: it cannot refuse the request, and every route that needs a
// credential asks again.
func TestDirectory_ASignedInVisitor_IsNotToldToSignIn(t *testing.T) {
	t.Parallel()

	authn := &fakeAuthn{principal: signedIn()}
	cfg := api.Config{
		Directory: directoryOf(testPlugin("alpha")),
		Providers: identity.NewRegistry(stubProvider{}),
		Authn:     authn,
		Sessions:  &fakeSessions{},
	}

	body := string(browseAs(t, cfg, "/", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: "a-session"})
	}).body)

	require.Contains(t, body, `<a href="/account">prokopto-dev</a>`,
		"the header names the account that is reading")
	require.NotContains(t, body, "sign in with GitHub")
	require.Equal(t, "a-session", authn.sawCreds.SessionCookie)
	require.Empty(t, authn.sawCreds.BearerToken)
}

// TestDirectory_ATokenIsNotABrowser.
//
// A personal access token must not authenticate a browser surface. On a public page there is
// nothing for it to authorise, so the rule is about what the page SAYS: a token holder does not
// get an account's name rendered onto a page by presenting it.
func TestDirectory_ATokenIsNotABrowser(t *testing.T) {
	t.Parallel()

	authn := &fakeAuthn{principal: signedIn()}
	cfg := api.Config{
		Directory: directoryOf(testPlugin("alpha")),
		Providers: identity.NewRegistry(stubProvider{}),
		Authn:     authn,
	}

	body := string(browseAs(t, cfg, "/", func(r *http.Request) {
		r.Header.Set("Authorization", "Bearer "+auth.TokenPrefix+"abcd1234_"+strings.Repeat("s", 43))
	}).body)

	require.NotContains(t, body, `<a href="/account">`,
		"a token must not put an account onto a page")
	require.Contains(t, body, "sign in with GitHub")
	require.Empty(t, authn.sawCreds.SessionCookie)
	require.Empty(t, authn.sawCreds.BearerToken,
		"a public page must not offer the Authorization header to the resolver at all")
}

// TestDirectory_ARejectedSession_StillGetsThePage.
//
// Decoration must never be able to take a route away: an expired or revoked cookie produces an
// anonymous page, not a 401 on a page that needs no credential.
func TestDirectory_ARejectedSession_StillGetsThePage(t *testing.T) {
	t.Parallel()

	cfg := api.Config{
		Directory: directoryOf(testPlugin("alpha")),
		Providers: identity.NewRegistry(stubProvider{}),
		Authn:     &fakeAuthn{err: auth.ErrCredentialRejected},
	}

	resp := browseAs(t, cfg, "/", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: "stale"})
	})

	require.Equal(t, http.StatusOK, resp.status)
	require.Contains(t, string(resp.body), "sign in with GitHub")
}

// TestIndex_WithNoCookie_NeverAsksWhoIsCalling — the cost of the decoration above is zero for the
// clients that matter. Every nParse+ install polls this endpoint and none of them carry a cookie.
func TestIndex_WithNoCookie_NeverAsksWhoIsCalling(t *testing.T) {
	t.Parallel()

	authn := &fakeAuthn{principal: signedIn()}
	resp := browseAs(t, api.Config{
		Catalogue: fakeCatalogue{plugins: []registry.Plugin{testPlugin("alpha")}},
		Authn:     authn,
	}, api.PathIndex, func(*http.Request) {})

	require.Equal(t, http.StatusOK, resp.status)
	require.Empty(t, authn.sawCreds.SessionCookie)
	require.Empty(t, authn.sawCreds.BearerToken)
}
