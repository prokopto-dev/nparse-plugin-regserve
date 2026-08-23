package api_test

import (
	"html"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
)

// The author on-ramp at /publish.
//
// The registry could say what plugins exist and could not say how to make one: the front page
// listed a catalogue, and the walkthrough lived in a docs file nothing on the site pointed at. What
// is left to get wrong once the prose is written is the part a reader depends on being true — that
// the page needs no credential, that it says the first release waits for a human, that the
// `uses:` line it hands somebody is a PIN, and that the GitHub expression syntax survives being
// rendered by a template engine that uses the same braces.

// TestPublishGuide_IsPublic_AndNamesEveryStepOfTheRealPath.
//
// Public because the reader it is written for does not have an account yet. Asking them who they
// are before telling them what an account would be for answers the question after they have
// stopped asking it.
func TestPublishGuide_IsPublic_AndNamesEveryStepOfTheRealPath(t *testing.T) {
	t.Parallel()

	// The claim-capable build: this test is about the WHOLE path, and the whole path is only true
	// on an instance that serves every step of it. The builds that serve fewer are covered by
	// TestPublishGuide_TellsAReaderOnlyWhatThisBuildCanDo.
	resp := browse(t, claimCapable(), api.PathPublish)

	require.Equal(t, http.StatusOK, resp.status, "the on-ramp needs no credential")
	require.Equal(t, "text/html; charset=utf-8", resp.header.Get("Content-Type"))

	body := string(resp.body)
	for _, want := range []string{
		"https://github.com/prokopto-dev/nparse-plugin-template",
		"Claim your plugin id",
		"plugin:publish",
		"REGSERVE_TOKEN",
		"Tag a release",
		"publish-plugin.yml@",
		"docs/operations/publishing-from-ci.md",
	} {
		require.Containsf(t, body, want, "the walkthrough must name %q", want)
	}
}

// TestPublishGuide_SaysTheFirstReleaseWaitsForAHuman.
//
// A new plugin id ALWAYS gets human review (ADR-0007), and an author who does not expect it reads
// a pending release as a failed publish. This project designs against a confident mistake in both
// directions; "your plugin is live" when it is waiting is that mistake in one sentence, and so is
// letting somebody discover the rule from a warning annotation on their release day.
func TestPublishGuide_SaysTheFirstReleaseWaitsForAHuman(t *testing.T) {
	t.Parallel()

	body := string(browse(t, api.Config{Directory: directoryOf(testPlugin("alpha"))},
		api.PathPublish).body)

	require.Contains(t, body, "always goes to human review")
	require.Contains(t, body, "pending")
	require.Contains(t, body, "not a failure",
		"the page has to say what a pending release IS, not only that it happens")
}

// TestPublishGuide_SaysClaimingIsSessionOnly_BeforeTheTokenStep.
//
// This used to assert the opposite — that the page said there was NO FORM for claiming (issue 42)
// — and the honesty was right while it was true. The form exists now, so the assertion moved to
// what still has to be true: that claiming is a separate act no token can perform, said BEFORE the
// step that mints one. An author who reads the token step first concludes the token is the
// credential, wires CI, and is answered 404 on every tag. One did.
func TestPublishGuide_SaysClaimingIsSessionOnly_BeforeTheTokenStep(t *testing.T) {
	t.Parallel()

	body := string(browse(t, claimCapable(), api.PathPublish).body)

	require.Contains(t, body, "A token cannot do this step")
	require.Contains(t, body, "session-only")
	require.Contains(t, body, "Claim a plugin id",
		"the page names the form by the legend it carries on the account page")

	// ORDER, not just presence. The rule the page exists to teach is a sequence — claim, then mint
	// a token pinned to what you claimed — and prose that says the right things in the wrong order
	// teaches the wrong one.
	claim := strings.Index(body, "Claim your plugin id")
	token := strings.Index(body, "Mint a scoped token")
	require.GreaterOrEqual(t, claim, 0)
	require.Greater(t, token, claim, "claiming has to come before minting, on the page as in life")

	// The claim takes the AUTHENTICATED CALLER's account id and the body has no on-behalf-of
	// field, so "ask somebody to claim it for you" hands them the plugin — permanently, since ids
	// are never reassigned. The page has to say that, or its workaround costs an author their id.
	require.Contains(t, body, "Do not ask somebody else to claim it for you")
	require.Contains(t, body, "becomes the owner")
}

// usesRef finds the ref of every reusable-workflow reference on a page.
var usesRef = regexp.MustCompile(
	`prokopto-dev/nparse-plugin-regserve/\.github/workflows/publish-plugin\.yml@([A-Za-z0-9._/-]+)`)

// TestPublishGuide_PinsTheReusableWorkflow_ToAnImmutableCommit.
//
// The workflow is consumed through `workflow_call`: it runs the author's job with the author's
// publish token, so the ref this page hands them decides what gets to run next to that secret.
// A TAG DOES NOT QUALIFY — `git tag -f` and a force-push here would repoint it, and every pipeline
// that copied it runs different code on its next release with no diff and nothing to notice. Only
// the 40-character commit SHA cannot move.
//
// DOC003 gates the same rule over the files. This gates what a reader is actually SERVED, which is
// the only version of the rule that reaches anybody.
func TestPublishGuide_PinsTheReusableWorkflow_ToAnImmutableCommit(t *testing.T) {
	t.Parallel()

	body := string(browse(t, api.Config{Directory: directoryOf(testPlugin("alpha"))},
		api.PathPublish).body)

	refs := usesRef.FindAllStringSubmatch(body, -1)
	require.NotEmpty(t, refs, "the page must show the uses: line; this gate is not vacant")

	commit := regexp.MustCompile(`^[0-9a-f]{40}$`)
	for _, m := range refs {
		require.Regexpf(t, commit, m[1],
			"@%s is a movable ref: a reusable workflow runs the caller's job with the caller's "+
				"secret, so what this page hands them has to be a commit nobody can repoint", m[1])
	}

	require.Contains(t, body, "# v0.3.0",
		"the pin must name its release: forty hex characters do not say which version a "+
			"reader's pipeline is on, and a pin nobody can place is never updated")
}

// TestPublishGuide_RendersTheGitHubExpressionSyntax_Intact.
//
// `${{ … }}` and `{{ … }}` are the same two braces to html/template, so the snippet writes the
// GitHub delimiters as HTML entities. That is invisible in the source and easy to "tidy up", and
// the failure is silent in exactly the wrong way: the page still renders, and the YAML somebody
// copies out of it publishes a literal string instead of the version they built.
func TestPublishGuide_RendersTheGitHubExpressionSyntax_Intact(t *testing.T) {
	t.Parallel()

	body := string(browse(t, api.Config{Directory: directoryOf(testPlugin("alpha"))},
		api.PathPublish).body)

	start := strings.Index(body, `<pre class="snippet">`)
	require.GreaterOrEqual(t, start, 0, "the page must carry a copyable snippet")
	end := strings.Index(body[start:], "</pre>")
	require.Greater(t, end, 0)

	// What a reader copies is the text after the browser resolves entities, not the markup.
	snippet := html.UnescapeString(body[start+len(`<pre class="snippet">`) : start+end])
	require.Contains(t, snippet, "${{ secrets.REGSERVE_TOKEN }}",
		"the token reaches the workflow through secrets:, and the line has to be copyable")
	require.Contains(t, snippet, "${{ needs.build.outputs.version }}")
	require.NotContains(t, snippet, "&#123;",
		"an entity that survives into the copied text is a workflow file that does not parse")
}

// claimCapable is a build that serves the directory, the account surface AND the claim form: the
// live deployment's shape, and the one the walkthrough's instructions are true on.
//
// Written out rather than defaulted, because the whole point of the tests below is that the page
// says different things on different builds, and a fixture that quietly wired everything would
// make the interesting cases unreachable.
func claimCapable() api.Config {
	return api.Config{
		Directory: directoryOf(testPlugin("alpha")),
		Providers: identity.NewRegistry(stubProvider{}),
		Login:     &fakeLogin{},
		Sessions:  &fakeSessions{},
		Tokens:    &fakeTokens{},
		Ownership: &fakeOwnership{},
		Claimer:   &fakeOwnership{},
	}
}

// TestPublishGuide_TellsAReaderOnlyWhatThisBuildCanDo.
//
// FOUR WIRING STATES, FOUR WALKTHROUGHS, and the assertions are as much about what is ABSENT as
// about what is there. Both halves of that are corrections:
//
//   - an earlier version kept "on your account, mint a token" unconditional and merely APPENDED a
//     note saying there was no account page, so a publisher-only reader was sent to a dead
//     destination and then told it was dead. The test checked only for the appended sentence, so
//     it blessed the contradiction. A test for a conditional page has to assert the branch not
//     taken is GONE;
//   - the next version collapsed the claim endpoint into the claim form, so an API-first build —
//     registerPlugins is gated on Claimer ALONE — was told ids could not be claimed there while
//     POST /api/v1/plugins sat answering. Naming a door that is not there and denying one that is
//     are the same mistake with the sign flipped.
//
// The four rows are wirings runServe can actually produce. A fifth would be a fifth row.
func TestPublishGuide_TellsAReaderOnlyWhatThisBuildCanDo(t *testing.T) {
	t.Parallel()

	// Sign-in, a Claimer, and no account surface: the JSON endpoint is served and nothing else is.
	apiFirst := claimCapable()
	apiFirst.Tokens, apiFirst.Ownership = nil, nil

	// The account surface with nothing to claim through: /account and the token forms are served,
	// the claim form is not, and neither is the endpoint.
	signInOnly := claimCapable()
	signInOnly.Claimer = nil

	tests := []struct {
		name string
		cfg  api.Config

		wants    []string
		wantsNot []string
	}{
		{
			name: "a build that serves the form tells the whole path",
			cfg:  claimCapable(),
			wants: []string{
				"/auth/github/login?next=/account",
				"Claim a plugin id",
				`On <a href="/account">your account</a>`,
			},
			wantsNot: []string{
				"cannot be claimed on this instance",
				"no account page on this instance",
				"serves no claim form",
			},
		},
		{
			// THE ACCOUNT PAGE AND THE CLAIM FORM COME APART. /account is served here and the
			// token step is real; only the step above it is not.
			name: "a build with an account page and nothing to claim through still mints",
			cfg:  signInOnly,
			wants: []string{
				"Ids cannot be claimed on this instance",
				"enable claiming",
				`On <a href="/account">your account</a>`,
			},
			wantsNot: []string{
				"Claim a plugin id",
				"no account page on this instance",
				"POST /api/v1/plugins",
			},
		},
		{
			// AND THE CLAIM ENDPOINT AND THE ACCOUNT PAGE COME APART TOO, the other way round.
			name: "an api-first build names the endpoint it actually serves",
			cfg:  apiFirst,
			wants: []string{
				"serves no claim form",
				"POST /api/v1/plugins",
				"no account page on this instance",
			},
			wantsNot: []string{
				"Ids cannot be claimed on this instance",
				`On <a href="/account">your account</a>`,
			},
		},
		{
			name: "a publisher-only build sends nobody anywhere it does not serve",
			cfg:  api.Config{Directory: directoryOf(testPlugin("alpha"))},
			wants: []string{
				"Ids cannot be claimed on this instance",
				"no account page on this instance",
				"whoever operates the registry",
				// The recovery has to be one the operator can perform. An id nobody has claimed
				// has no plugin row, and the ownership import skips ids it does not already carry
				// rather than inventing them, so "ask them to grant it to you" is advice that
				// cannot be followed for exactly the reader this page is written for.
				"enable claiming",
			},
			wantsNot: []string{
				`href="/account"`,
				"/auth/github/login",
				"Claim a plugin id",
				"POST /api/v1/plugins",
				"claim the id and grant it to you",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := string(browse(t, tc.cfg, api.PathPublish).body)
			for _, want := range tc.wants {
				require.Containsf(t, body, want, "this build has to say %q", want)
			}
			for _, unwanted := range tc.wantsNot {
				// THE ABSENCE IS THE ASSERTION. A dead instruction followed by a correction is
				// worse than either alone: the reader follows the first one.
				require.NotContainsf(t, body, unwanted,
					"this build must not say %q — it is not true here", unwanted)
			}
		})
	}
}

// TestDirectory_LeadsToTheAuthorOnRamp — the gap this page was built to close.
//
// The front page is where somebody arrives. Before this, everything on it answered "what plugins
// exist" and nothing answered "how do I make one", so a visitor who came to write a plugin left
// knowing exactly what they arrived knowing.
func TestDirectory_LeadsToTheAuthorOnRamp(t *testing.T) {
	t.Parallel()

	body := string(browse(t, api.Config{Directory: directoryOf(testPlugin("alpha"))}, "/").body)

	require.Contains(t, body, `href="`+api.PathPublish+`"`)
	require.Contains(t, body, "https://github.com/prokopto-dev/nparse-plugin-template",
		"the template is the first step and is worth naming where somebody lands")
}

// TestEveryPublicPage_CarriesTheOnRampInItsHeader.
//
// A listing's page is what gets pasted into a chat window, so it is where a lot of people first
// meet this registry. A destination reachable only from the front page is a destination half the
// visitors never see.
func TestEveryPublicPage_CarriesTheOnRampInItsHeader(t *testing.T) {
	t.Parallel()

	cfg := api.Config{Directory: directoryOf(testPlugin("alpha"))}
	for _, path := range []string{"/", "/plugins/alpha", api.PathPublish} {
		body := string(browse(t, cfg, path).body)
		require.Containsf(t, body, `<a href="`+api.PathPublish+`">publish a plugin</a>`,
			"%s must offer the on-ramp in the header", path)
	}
}
