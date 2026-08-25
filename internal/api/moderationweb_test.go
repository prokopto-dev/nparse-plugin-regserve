package api_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
)

// The moderation console's surface.
//
// internal/review covers what delisting DOES to a database. What is left to get wrong here is who
// may reach these pages and what they are told: a console that let a token delist a plugin would
// be moderation delegated to a CI credential, and one that offered a trust control without saying
// what a tier means would be a reviewer picking a word.
//
// The access half is covered by reviewRoutes() in reviewweb_test.go, which every one of these
// routes is a member of — and by TestReviewRoutes_CoverEveryReviewerOperationInTheDocument, which
// derives that membership from the route registry rather than trusting the list.

// testAccountID is a well-formed ULID, because the trust form parses one before assembling a
// redirect. See api.returnPath: a Location built from unvalidated input is a header somebody else
// gets to write.
const testAccountID = "01JCX0MPZZZZZZZZZZZZZZZZZY"

// fakeModeration is api.PluginModeration, recording what it was asked.
type fakeModeration struct {
	listing review.Listing
	all     []review.Listing

	getErr error
	opErr  error

	sawDelist []string
	sawRelist []string
}

func (f *fakeModeration) List(context.Context) ([]review.Listing, error) {
	return f.all, f.getErr
}

func (f *fakeModeration) Get(_ context.Context, id string) (review.Listing, error) {
	if f.getErr != nil {
		return review.Listing{}, f.getErr
	}
	l := f.listing
	l.ID = id
	return l, nil
}

func (f *fakeModeration) Delist(_ context.Context, id, _, reason string) error {
	f.sawDelist = append(f.sawDelist, id+"|"+reason)
	return f.opErr
}

func (f *fakeModeration) Relist(_ context.Context, id, _, reason string) error {
	f.sawRelist = append(f.sawRelist, id+"|"+reason)
	return f.opErr
}

// fakeTrust is api.TrustService, recording the tier and the note it was handed.
type fakeTrust struct {
	err error

	sawSet []string
}

func (f *fakeTrust) SetTrust(_ context.Context, accountID string, level release.Trust, _, note string) error {
	f.sawSet = append(f.sawSet, accountID+"|"+level.String()+"|"+note)
	return f.err
}

// TestModerationConsole_ShowsEveryStateAndSaysWhatDelistingKeeps.
//
// The catalogue page is the answer to "what does this registry carry", so the test is that it
// carries the rows the PUBLIC directory correctly declines to show — and says, where a reviewer
// will read it, that delisting does not free the id.
func TestModerationConsole_ShowsEveryStateAndSaysWhatDelistingKeeps(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t, func(h *reviewHarness) {
		h.moderation.all = []review.Listing{
			{ID: "listed-plugin", Name: "Listed", LiveVersion: "1.0.0"},
			{ID: "awaiting-plugin", Name: "Awaiting"},
			{
				ID: "gone-plugin", Name: "Gone", Delisted: true,
				DelistedAt: time.Unix(1, 0).UTC(), DelistedReason: "withdrawn by its author",
				LiveVersion: "2.0.0",
			},
		}
	})

	resp := h.do(t, http.MethodGet, api.PathReviewCatalogue, nil)
	require.Equal(t, http.StatusOK, resp.status)
	body := string(resp.body)

	// EVERY STATE, INCLUDING THE TWO THE DIRECTORY HIDES. That is the reason this page exists.
	require.Contains(t, body, "listed-plugin")
	require.Contains(t, body, "awaiting-plugin", "a claimed id with nothing published must be visible")
	require.Contains(t, body, "gone-plugin", "a delisted id must be visible to a moderator")

	require.Contains(t, body, "delisted")
	require.Contains(t, body, "nothing approved yet")

	// The invariant, stated where somebody about to act on it will read it.
	require.Contains(t, body, "never recycled")
}

// TestModerationPluginPage_ShowsTheTierBesideEveryOwnerAndOffersToChangeIt.
//
// "Show the publisher's CURRENT tier wherever you offer to change it, or the reviewer is
// guessing." Both halves are asserted: the tier is on the page, and the control is there too.
func TestModerationPluginPage_ShowsTheTierBesideEveryOwnerAndOffersToChangeIt(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t, func(h *reviewHarness) {
		h.moderation.listing = review.Listing{
			Name: "Merchant Mode", LiveVersion: "1.0.0",
			Owners: []review.Holder{
				{AccountID: testAccountID, Handle: "prokopto-dev", Role: "owner", Trust: "trusted"},
			},
		}
	})

	resp := h.do(t, http.MethodGet, "/review/plugins/merchant-mode", nil)
	require.Equal(t, http.StatusOK, resp.status)
	body := string(resp.body)

	require.Contains(t, body, "prokopto-dev")
	require.Contains(t, body, "trusted", "the current tier is shown where the change is offered")
	require.Contains(t, body, `action="/review/accounts/`+testAccountID+`/trust"`,
		"the control posts against the ACCOUNT, which is what a tier belongs to")

	// ADR-0007, said out loud rather than left for the layout to imply.
	require.Contains(t, body, "belongs to the account")
	require.Contains(t, body, "no per-plugin trust")

	// And the delist control, with the invariant beside it.
	require.Contains(t, body, `value="delist"`)
	require.Contains(t, body, "stays claimed")
}

// TestModerationPluginPage_ADelistedPluginOffersRelistAndNotDelist.
func TestModerationPluginPage_ADelistedPluginOffersRelistAndNotDelist(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t, func(h *reviewHarness) {
		h.moderation.listing = review.Listing{
			Name: "Merchant Mode", Delisted: true, DelistedAt: time.Unix(1, 0).UTC(),
			DelistedReason: "malware in the wheel", LiveVersion: "1.0.0",
		}
	})

	body := string(h.do(t, http.MethodGet, "/review/plugins/merchant-mode", nil).body)

	require.Contains(t, body, `value="relist"`)
	require.NotContains(t, body, `value="delist"`,
		"offering to delist an already-delisted plugin is offering a refusal")
	require.Contains(t, body, "malware in the wheel", "the reason on the row is what a moderator needs")
	require.Contains(t, body, "only record")
}

// TestModerationListingForm_DelistsAndRelistsThroughTheService.
func TestModerationListingForm_DelistsAndRelistsThroughTheService(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		action string
		want   func(h *reviewHarness) []string
	}{
		{name: "delist", action: "delist", want: func(h *reviewHarness) []string { return h.moderation.sawDelist }},
		{name: "relist", action: "relist", want: func(h *reviewHarness) []string { return h.moderation.sawRelist }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newReviewHarness(t)
			resp := h.do(t, http.MethodPost, "/review/plugins/merchant-mode/listing",
				withCSRF(url.Values{"action": {tc.action}, "reason": {"a stated reason"}}, h.csrf()))

			require.Equal(t, http.StatusSeeOther, resp.status)
			require.Equal(t, "/review/plugins/merchant-mode?msg=listing_changed",
				resp.header.Get("Location"), "post/redirect/get, back to the page acted on")
			require.Equal(t, []string{"merchant-mode|a stated reason"}, tc.want(h))
		})
	}
}

// TestModerationListingForm_RefusesAnActionItDoesNotHave — including anything resembling a delete.
func TestModerationListingForm_RefusesAnActionItDoesNotHave(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t)
	for _, action := range []string{"", "delete", "remove", "purge", "DELIST"} {
		resp := h.do(t, http.MethodPost, "/review/plugins/merchant-mode/listing",
			withCSRF(url.Values{"action": {action}, "reason": {"why"}}, h.csrf()))
		require.Equal(t, http.StatusBadRequest, resp.status, "action %q", action)
	}
	require.Empty(t, h.moderation.sawDelist, "an unrecognised action must reach no service")
	require.Empty(t, h.moderation.sawRelist)
}

// TestTrustForm_SetsTheTierAndReturnsWhereItCameFrom.
//
// The return path is the interesting half. The control is offered on two pages, so the form has to
// say which — and it says so as a KIND and an ID that the handler parses, never as a URL it would
// otherwise be concatenating into a Location header.
func TestTrustForm_SetsTheTierAndReturnsWhereItCameFrom(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		from   string
		fromID string
		want   string
	}{
		{
			name: "from a release page", from: "release", fromID: testReleaseID,
			want: "/review/releases/" + testReleaseID + "?msg=trust_set",
		},
		{
			name: "from a plugin page", from: "plugin", fromID: "merchant-mode",
			want: "/review/plugins/merchant-mode?msg=trust_set",
		},
		{
			// A kind this service does not render falls back to the console rather than failing:
			// the tier has already been written by the time the redirect is chosen, and refusing
			// to redirect would show an error over a change that succeeded.
			name: "from something this service did not render", from: "elsewhere", fromID: "x",
			want: api.PathReviewCatalogue + "?msg=trust_set",
		},
		{
			// The one that matters. An id that does not parse can never reach the header.
			name: "from an id that is not one", from: "plugin", fromID: "../../somewhere-else",
			want: api.PathReviewCatalogue + "?msg=trust_set",
		},
		{
			name: "from an absolute URL somebody hoped would be followed",
			from: "release", fromID: "https://example.invalid/phish",
			want: api.PathReviewCatalogue + "?msg=trust_set",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newReviewHarness(t)
			resp := h.do(t, http.MethodPost, "/review/accounts/"+testAccountID+"/trust",
				withCSRF(url.Values{
					"level":   {"trusted"},
					"note":    {"published five clean releases"},
					"from":    {tc.from},
					"from_id": {tc.fromID},
				}, h.csrf()))

			require.Equal(t, http.StatusSeeOther, resp.status)
			require.Equal(t, tc.want, resp.header.Get("Location"))
			require.Equal(t, []string{testAccountID + "|trusted|published five clean releases"},
				h.trust.sawSet)
		})
	}
}

// TestTrustForm_RefusesATierThatIsNotOne_WithoutCallingTheService.
func TestTrustForm_RefusesATierThatIsNotOne_WithoutCallingTheService(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t)
	// NOT "TRUSTED " -- release.ParseTrust trims and lower-cases before comparing, so surrounding
	// whitespace and case are deliberately tolerated. A test asserting otherwise would be asserting
	// against the parser rather than against this form.
	for _, level := range []string{"", "admin", "superuser", "trusted-plus"} {
		resp := h.do(t, http.MethodPost, "/review/accounts/"+testAccountID+"/trust",
			withCSRF(url.Values{"level": {level}, "note": {"why"}}, h.csrf()))
		require.Equal(t, http.StatusSeeOther, resp.status, "level %q", level)
		require.Contains(t, resp.header.Get("Location"), "msg=trust_bad_level", "level %q", level)
	}
	require.Empty(t, h.trust.sawSet,
		"a tier this service does not have must never reach the service that writes one")
}

// TestTrustForm_ReportsAMissingReason — the note is the only place the reasoning survives.
func TestTrustForm_ReportsAMissingReason(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t, func(h *reviewHarness) { h.trust.err = release.ErrNoTrustReason })
	resp := h.do(t, http.MethodPost, "/review/accounts/"+testAccountID+"/trust",
		withCSRF(url.Values{"level": {"trusted"}, "from": {"plugin"}, "from_id": {"mm"}}, h.csrf()))

	require.Equal(t, http.StatusSeeOther, resp.status)
	require.Contains(t, resp.header.Get("Location"), "msg=trust_no_reason")
}

// TestReleasePage_OffersTrustSeparatelyFromApproveAndReject.
//
// THE SEPARATION, ASSERTED ON THE PAGE. internal/review asserts that approving does not touch a
// tier; this asserts that the page cannot make it look as though it might — the two controls are
// in different forms posting to different routes, so there is no submit button that does both.
func TestReleasePage_OffersTrustSeparatelyFromApproveAndReject(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t, func(h *reviewHarness) {
		h.queue.detail.Submitter = review.Submitter{
			AccountID: testAccountID, Handle: "prokopto-dev", Trust: "new",
		}
	})

	body := string(h.do(t, http.MethodGet, "/review/releases/"+testReleaseID, nil).body)

	// The current tier, beside the person, on the page that offers to change it.
	require.Contains(t, body, "prokopto-dev")
	require.Contains(t, body, "holds them at")

	// TWO FORMS, TWO ACTIONS. The decide form posts to the release; the trust form posts to the
	// account. A single form carrying both would be an approval that silently raised trust.
	decide := `action="/review/releases/` + testReleaseID + `/decide"`
	trust := `action="/review/accounts/` + testAccountID + `/trust"`
	require.Contains(t, body, decide)
	require.Contains(t, body, trust)

	require.Less(t, strings.Index(body, decide), strings.Index(body, trust),
		"the trust control sits after the decision, where the judgement is formed")

	// And the approve button belongs to the decide form only: everything between the trust form's
	// action and its close must not contain one.
	trustBlock := body[strings.Index(body, trust):]
	trustBlock = trustBlock[:strings.Index(trustBlock, "</form>")]
	require.NotContains(t, trustBlock, `value="approve"`,
		"approving must never be a button on the form that changes trust")
	require.NotContains(t, trustBlock, `value="reject"`)

	require.Contains(t, body, "separate decision from approving")
}

// TestReleasePage_StillOffersTrustAfterTheReleaseIsDecided.
//
// A reviewer is redirected back here after approving, and "approve, then decide whether to stop
// gating them" is the ordinary order of the two thoughts. A control that vanished the moment the
// release was decided would disappear at exactly the point it is wanted.
func TestReleasePage_StillOffersTrustAfterTheReleaseIsDecided(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t, func(h *reviewHarness) {
		h.queue.detail.State = "approved"
		h.queue.detail.Submitter = review.Submitter{AccountID: testAccountID, Trust: "new"}
	})

	body := string(h.do(t, http.MethodGet, "/review/releases/"+testReleaseID, nil).body)

	require.NotContains(t, body, `value="approve"`, "a decided release has nothing left to decide")
	require.Contains(t, body, `action="/review/accounts/`+testAccountID+`/trust"`,
		"but its publisher's tier is still a decision worth making from here")
}

// TestReviewPages_OfferNoTrustControlWhereTheRouteIsNotRegistered.
//
// A form posting to a route this build does not serve is the dead end this whole surface exists to
// remove, so the page and the registration read the SAME dependency. This is the assertion that
// they do.
func TestReviewPages_OfferNoTrustControlWhereTheRouteIsNotRegistered(t *testing.T) {
	t.Parallel()

	h := newReviewHarness(t, func(h *reviewHarness) {
		h.trust = nil
		h.moderation = nil
	})

	body := string(h.do(t, http.MethodGet, "/review/releases/"+testReleaseID, nil).body)
	require.NotContains(t, body, "/trust\"", "no control where there is no route to answer it")
	require.NotContains(t, body, "/review/plugins", "and no link to a console this build does not serve")

	// And the routes really are absent, rather than present and refusing.
	require.Equal(t, http.StatusNotFound,
		h.do(t, http.MethodGet, api.PathReviewCatalogue, nil).status)
	require.Equal(t, http.StatusNotFound,
		h.do(t, http.MethodPost, "/review/accounts/"+testAccountID+"/trust",
			withCSRF(url.Values{"level": {"trusted"}}, h.csrf())).status)
}
