package core_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
)

// The rule that governs every URL this registry publishes.
//
// It lives here because it was written twice — once for `release.artifact_url` and once for
// `plugin.homepage` — and the two drifted: one refused userinfo, query and fragment, the other
// refused only userinfo. Neither author was careless. The rule simply lived in two places, which
// is all it takes.

// TestCheckPublishedURL_AcceptsWhatARealURLLooksLike — the floor is not a wall.
//
// If this refused a GitHub release asset or a project page, nothing could be published at all.
func TestCheckPublishedURL_AcceptsWhatARealURLLooksLike(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"https://github.com/prokopto-dev/nparseplus-plugin-merchant-mode",
		"https://github.com/owner/repo/releases/download/v1.0.0/plugin-1.0.0-py3-none-any.whl",
		"https://cdn.example.com/plugins/merchant-mode/1.0.0/merchant_mode.whl",
		"https://example.com",
		"https://example.com/",
		"https://example.com:8443/a.whl",
		"https://sub.domain.example.co.uk/deep/path/file.zip",
		"HTTPS://example.com/a.whl", // url.Parse lower-cases the scheme, as the client's parser does
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, core.CheckPublishedURL(raw))
		})
	}
}

// TestCheckPublishedURL_RefusesEveryPlaceACredentialTravels.
//
// Three of them, and the query is refused WHOLE rather than by parameter name: a denylist of
// X-Amz-Signature, sig, token, AWSAccessKeyId, sv... is a list somebody has to remember to extend,
// and the entry that gets forgotten is the one that leaks.
func TestCheckPublishedURL_RefusesEveryPlaceACredentialTravels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		url     string
		secrets []string
	}{
		{
			name:    "an s3 signed url",
			url:     "https://cdn.example.com/plugin.whl?X-Amz-Signature=deadbeefcafe&X-Amz-Expires=900",
			secrets: []string{"deadbeefcafe", "X-Amz-Signature"},
		},
		{
			name:    "an azure shared access signature",
			url:     "https://acct.blob.core.windows.net/c/plugin.whl?sv=2021-08-06&sig=abc123def",
			secrets: []string{"abc123def"},
		},
		{
			name:    "a token in a parameter nobody would think to denylist",
			url:     "https://example.com/docs?t=s3cr3tvalue",
			secrets: []string{"s3cr3tvalue"},
		},
		{
			name:    "a bare question mark, which is still a query string on the wire",
			url:     "https://example.com/plugin.whl?",
			secrets: nil,
		},
		{
			name:    "a fragment",
			url:     "https://example.com/readme#token=deadbeefcafe",
			secrets: []string{"deadbeefcafe"},
		},
		{
			name:    "userinfo with a password",
			url:     "https://alice:hunter2@example.com/plugin.whl",
			secrets: []string{"hunter2"},
		},
		{
			// A bare username is a credential on its own for plenty of services, and it is the
			// half url.URL.Redacted() does not remove.
			name:    "username-only userinfo",
			url:     "https://ghp_averysecretlookingtoken@example.com/",
			secrets: []string{"ghp_averysecretlookingtoken"},
		},
		{
			name:    "all three at once",
			url:     "https://alice:hunter2@example.com/x?sig=abc123#frag",
			secrets: []string{"hunter2", "abc123", "frag"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := core.CheckPublishedURL(tc.url)
			require.ErrorIs(t, err, core.ErrUnpublishableURL)

			// The refusal must not echo what it is refusing. These errors reach logs and review
			// notes, and the reason for the refusal IS that the value may hold a secret.
			for _, secret := range tc.secrets {
				require.NotContains(t, err.Error(), secret,
					"the refusal echoed %q, which is the credential it exists to keep out", secret)
			}
		})
	}
}

// TestCheckPublishedURL_RefusesSchemesThatAreNotHomepagesOrDownloads.
//
// `javascript:`, `data:` and `file:` are not addresses — they are instructions to whatever
// component renders the link, and this registry has no way to know what a given client version
// does with one.
func TestCheckPublishedURL_RefusesSchemesThatAreNotHomepagesOrDownloads(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"",
		"http://example.com/a.whl",
		"ftp://example.com/a.whl",
		"javascript:alert(1)",
		"data:text/html,<script>x</script>",
		"file:///etc/passwd",
		"https://",
		"//example.com/a.whl",
		"example.com",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			require.ErrorIs(t, core.CheckPublishedURL(raw), core.ErrUnpublishableURL)
		})
	}
}

// TestCheckPublishedURL_AnUnparseableURL_SaysNothingAboutItsValue.
//
// A parse error's own message quotes its input, and an input this service could not even parse is
// the last one to start echoing.
func TestCheckPublishedURL_AnUnparseableURL_SaysNothingAboutItsValue(t *testing.T) {
	t.Parallel()

	err := core.CheckPublishedURL("https://alice:hunter2@exa mple.com/x")
	require.ErrorIs(t, err, core.ErrUnpublishableURL)
	require.NotContains(t, err.Error(), "hunter2")
}

// TestCheckPublishedURL_TheLengthCapBelongsToTheCaller — stated so the split is deliberate.
//
// This says nothing about length. The caps live next to the other field caps in the packages that
// store the value, because a bound on what a stranger may store is a different judgement from
// what a URL is.
func TestCheckPublishedURL_TheLengthCapBelongsToTheCaller(t *testing.T) {
	t.Parallel()

	require.NoError(t, core.CheckPublishedURL("https://example.com/"+strings.Repeat("a", 8000)))
}
