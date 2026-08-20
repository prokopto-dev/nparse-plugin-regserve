package artifact_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity/guard"
)

// ValidateURL guards a value that is PUBLISHED, which makes it a different judgement from the one
// Fetch makes. Fetch asks "can these bytes be obtained safely". This asks "may this string be
// rendered into the index document and served to every client on the internet, for ever, cached by
// anything in between".
//
// The second question is stricter, and the difference is the whole reason the function exists.

// TestValidateURL_AcceptsWhatARealArtifactURLLooksLike — the rule is a floor, not a wall.
//
// If this refused a GitHub release asset, nothing could be published at all. ADR-0002 keeps
// artifacts on GitHub, and these are the shapes that come out of a release workflow.
func TestValidateURL_AcceptsWhatARealArtifactURLLooksLike(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"https://github.com/prokopto-dev/nparseplus-plugin-merchant-mode/releases/download/v1.0.0/merchant_mode-1.0.0-py3-none-any.whl",
		"https://github.com/owner/repo/releases/download/v2.1.0-rc.1/plugin.zip",
		"https://cdn.example.com/plugins/merchant-mode/1.0.0/merchant_mode.whl",
		"https://example.com/a.whl",
		"https://example.com:8443/a.whl",
		"HTTPS://example.com/a.whl", // url.Parse lower-cases the scheme, as the client's parser does
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()
			require.NoError(t, artifact.ValidateURL(raw))
		})
	}
}

// TestValidateURL_RefusesAURLThatWouldPublishACredential.
//
// release.artifact_url is rendered verbatim into the index and served to every nParse+ client. A
// signed URL's signature IS a bearer credential for those bytes — that is what a signed URL is —
// so publishing one hands it to everybody who polls, cached, for as long as it is valid.
//
// The query is refused WHOLE rather than by inspecting parameter names. A denylist of
// X-Amz-Signature, token, sig, AWSAccessKeyId... is a list somebody has to remember to extend, and
// the entry that gets forgotten is the one that leaks. The guarded dialer refuses addresses by
// category for exactly the same reason.
func TestValidateURL_RefusesAURLThatWouldPublishACredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		url     string
		secrets []string
	}{
		{
			name:    "an s3 signed url, the realistic one",
			url:     "https://cdn.example.com/plugin.whl?X-Amz-Signature=deadbeefcafe&X-Amz-Expires=900",
			secrets: []string{"deadbeefcafe", "X-Amz-Signature"},
		},
		{
			name:    "a token in a parameter nobody would think to denylist",
			url:     "https://cdn.example.com/plugin.whl?t=s3cr3tvalue",
			secrets: []string{"s3cr3tvalue"},
		},
		{
			name:    "an azure shared access signature",
			url:     "https://acct.blob.core.windows.net/c/plugin.whl?sv=2021-08-06&sig=abc123def",
			secrets: []string{"abc123def"},
		},
		{
			name:    "a bare question mark, which is still a query string on the wire",
			url:     "https://example.com/plugin.whl?",
			secrets: nil,
		},
		{
			name:    "a fragment, which the server never sees and the index would still carry",
			url:     "https://example.com/plugin.whl#sha256=deadbeefcafe",
			secrets: []string{"deadbeefcafe"},
		},
		{
			name:    "userinfo with a password",
			url:     "https://alice:hunter2@example.com/plugin.whl",
			secrets: []string{"hunter2"},
		},
		{
			// A bare username is a credential on its own for plenty of services -- a token pasted
			// where a username goes is the common shape.
			name:    "username-only userinfo",
			url:     "https://ghp_averysecretlookingtoken@example.com/plugin.whl",
			secrets: []string{"ghp_averysecretlookingtoken"},
		},
		{
			name:    "all of them at once",
			url:     "https://alice:hunter2@example.com/plugin.whl?sig=abc123#frag",
			secrets: []string{"hunter2", "abc123", "frag"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := artifact.ValidateURL(tc.url)
			require.ErrorIs(t, err, artifact.ErrBadArtifactURL)

			// The refusal must not echo the value it is refusing. This error reaches a log and a
			// review note, and the reason for the refusal IS that the value may hold a secret.
			for _, secret := range tc.secrets {
				require.NotContains(t, err.Error(), secret,
					"the refusal echoed %q, which is the credential it exists to keep out", secret)
			}
		})
	}
}

// TestValidateURL_RefusesWhatIsNotAFetchableHTTPSURL — the guard's own rule, still applied.
func TestValidateURL_RefusesWhatIsNotAFetchableHTTPSURL(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"",
		"http://example.com/a.whl",
		"ftp://example.com/a.whl",
		"https://",
		"//example.com/a.whl",
		"file:///etc/passwd",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			err := artifact.ValidateURL(raw)
			require.ErrorIs(t, err, artifact.ErrBadArtifactURL)
			require.ErrorIs(t, err, guard.ErrNotHTTPS)
		})
	}
}

// TestValidateURL_IsStricterThanFetch — the two judgements are deliberately different.
//
// A signed CDN URL is perfectly FETCHABLE, and the fetcher follows redirects to exactly that kind
// of URL on every GitHub release. What it must not be is STORED. Asserting the asymmetry directly
// stops somebody later "unifying" the two checks on the grounds that they look similar.
func TestValidateURL_IsStricterThanFetch(t *testing.T) {
	t.Parallel()

	const signed = "https://cdn.example.com/plugin.whl?X-Amz-Signature=deadbeefcafe"

	// Refused for STORING.
	require.ErrorIs(t, artifact.ValidateURL(signed), artifact.ErrBadArtifactURL)

	// And nothing about it is refused for FETCHING: guard.RequireHTTPS, which is what the fetcher
	// applies on hop one, is happy with it. The fetcher must stay happy with it, because the
	// redirect at the end of every GitHub release asset lands on one.
	require.NoError(t, guard.RequireHTTPS(signed))
}

// TestValidateURL_TheLengthCapIsTheSubmissionLayers — stated here so the split is deliberate.
//
// ValidateURL says nothing about length. The cap lives in release.NewSubmission, next to the other
// field caps, because it is a bound on what a stranger may store rather than a statement about
// what a URL is.
func TestValidateURL_TheLengthCapIsTheSubmissionLayers(t *testing.T) {
	t.Parallel()

	long := "https://example.com/" + strings.Repeat("a", 8000) + ".whl"
	require.NoError(t, artifact.ValidateURL(long))
}
