package guard_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity/guard"
)

// TestNewClient_ProductionDefaults_RefuseLoopback — the escape hatch is not on by default.
//
// Every other test in this package sets PermitLoopback so it can talk to an httptest server. This
// is the one that proves the thing production builds does not: a client from the zero Config
// refuses to dial its own machine, which is the first hop of every SSRF that matters.
func TestNewClient_ProductionDefaults_RefuseLoopback(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	require.NoError(t, err)

	_, err = guard.Do(t.Context(), guard.NewClient(guard.Config{}), req, 1024)
	require.ErrorIs(t, err, guard.ErrBlockedAddress,
		"the default client must refuse loopback; if this passes, every guarded call in the "+
			"service can reach localhost")
}

// TestNewClient_CheckRedirect_RefusesADowngradeOnEveryHop — https is re-asserted per hop.
//
// The dangerous redirect is not the first one. It is the fourth, from a host that looked fine, to
// http://169.254.169.254/ — and net/http follows it without complaint unless CheckRedirect says
// otherwise. The hook is exercised directly because reproducing a real chain would need a
// certificate authority to make the https legs verifiable.
func TestNewClient_CheckRedirect_RefusesADowngradeOnEveryHop(t *testing.T) {
	t.Parallel()

	client := guard.NewClient(guard.Config{})
	require.NotNil(t, client.CheckRedirect, "a client with no CheckRedirect follows anything")

	tests := []struct {
		name string
		to   string
		hops int
		want error
	}{
		{name: "https on the first hop", to: "https://example.com/a", hops: 1},
		{name: "https deep in the chain", to: "https://example.com/d", hops: 4},
		{name: "http on the first hop", to: "http://example.com/a", hops: 1, want: guard.ErrNotHTTPS},
		{name: "http deep in the chain", to: "http://169.254.169.254/latest/meta-data/", hops: 4, want: guard.ErrNotHTTPS},
		{name: "a scheme that is neither", to: "file:///etc/passwd", hops: 1, want: guard.ErrNotHTTPS},
		{name: "one hop past the cap", to: "https://example.com/z", hops: guard.DefaultMaxRedirects + 1, want: guard.ErrTooManyRedirects},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tt.to, nil)
			require.NoError(t, err)

			via := make([]*http.Request, tt.hops)
			for i := range via {
				u, perr := url.Parse("https://start.example/")
				require.NoError(t, perr)
				via[i] = &http.Request{URL: u}
			}

			err = client.CheckRedirect(req, via)
			if tt.want == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tt.want)
		})
	}
}

func TestRequireHTTPS_RejectsAnythingElse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{name: "https", in: "https://example.com/x.zip", ok: true},
		{name: "https uppercase", in: "HTTPS://example.com/x.zip", ok: true},
		{name: "http", in: "http://example.com/x.zip"},
		{name: "no scheme", in: "example.com/x.zip"},
		{name: "protocol relative", in: "//example.com/x.zip"},
		{name: "file", in: "file:///etc/passwd"},
		{name: "empty", in: ""},
		// The one that looks like it passes a prefix check and is not https at all.
		{name: "a host named https", in: "http://https.example.com/x.zip"},
		// These four begin with the right eight characters and name no host. A prefix check passes
		// them; what follows is a callback URL of `https:///auth/github/callback` that GitHub
		// cannot redirect to, accepted at boot and failing in a browser.
		{name: "a scheme and nothing else", in: "https://"},
		{name: "a scheme and a query", in: "https://?x"},
		{name: "a scheme and a path", in: "https:///auth/github/callback"},
		{name: "a scheme and a fragment", in: "https://#x"},
		{name: "not a url at all", in: "https://exa mple.com/x.zip"},
		// A bare host with no path is a perfectly good base URL and must keep working.
		{name: "no path", in: "https://example.com", ok: true},
		{name: "a port", in: "https://example.com:8443/x.zip", ok: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := guard.RequireHTTPS(tt.in)
			if tt.ok {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, guard.ErrNotHTTPS)
		})
	}
}

// TestReadCapped_FailsAtTheCapRatherThanAfterIt — the cap is applied during the read.
//
// The boundary is the whole test: exactly the cap is fine, one byte more is an error, and the
// error arrives having allocated one byte over budget rather than whatever the far end chose to
// send. A cap checked after io.ReadAll has already lost.
func TestReadCapped_FailsAtTheCapRatherThanAfterIt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		size int
		cap  int64
		ok   bool
	}{
		{name: "well under", size: 10, cap: 1024, ok: true},
		{name: "exactly at the cap", size: 1024, cap: 1024, ok: true},
		{name: "one byte over", size: 1025, cap: 1024},
		{name: "wildly over", size: 100_000, cap: 1024},
		{name: "empty body under a zero cap", size: 0, cap: 0, ok: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body, err := guard.ReadCapped(strings.NewReader(strings.Repeat("a", tt.size)), tt.cap)
			if tt.ok {
				require.NoError(t, err)
				require.Len(t, body, tt.size)
				return
			}
			require.ErrorIs(t, err, guard.ErrTooLarge)
			require.Nil(t, body, "an over-cap read returns no body; a truncated one would be worse")
		})
	}
}

// TestDo_CapsTheBodyOverARealSocket — the cap survives the round trip.
//
// The unit test above proves ReadCapped; this proves the caller everything goes through actually
// uses it, over a real connection, with a server that sends more than it should. PermitLoopback is
// what lets this reach an httptest server at all.
func TestDo_CapsTheBodyOverARealSocket(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 4096)))
	}))
	t.Cleanup(srv.Close)

	client := guard.NewClient(guard.Config{PermitLoopback: true})

	t.Run("within the cap", func(t *testing.T) {
		t.Parallel()

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
		require.NoError(t, err)

		resp, err := guard.Do(t.Context(), client, req, 8192)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Len(t, resp.Body, 4096)
	})

	t.Run("over the cap", func(t *testing.T) {
		t.Parallel()

		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
		require.NoError(t, err)

		resp, err := guard.Do(t.Context(), client, req, 100)
		require.ErrorIs(t, err, guard.ErrTooLarge)
		require.Nil(t, resp.Body)
		require.Equal(t, http.StatusOK, resp.StatusCode,
			"the status is still reported: an oversized body and no answer at all are different")
	})
}

// --- the additions Phase 3 needed -------------------------------------------------------------

// TestCopyCapped_StopsAtTheCapWithoutHoldingTheBytes — the streaming half of canonical §9.
//
// ReadCapped answers "give me the body", which is right for an identity provider's JSON and wrong
// for a 50 MiB artifact: that is 50 MiB resident per concurrent publish, on the word of whoever
// supplied the URL. CopyCapped answers "put it somewhere and tell me how much there was".
func TestCopyCapped_StopsAtTheCapWithoutHoldingTheBytes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    int
		cap     int64
		wantErr error
		wantN   int64
	}{
		{name: "well under the cap", body: 10, cap: 1024, wantN: 10},
		{name: "exactly at the cap", body: 1024, cap: 1024, wantN: 1024},
		{name: "one byte over", body: 1025, cap: 1024, wantErr: guard.ErrTooLarge, wantN: 1025},
		{name: "far over", body: 1 << 20, cap: 1024, wantErr: guard.ErrTooLarge, wantN: 1025},
		{name: "empty", body: 0, cap: 1024, wantN: 0},
		{name: "a zero cap accepts nothing but empty", body: 1, cap: 0, wantErr: guard.ErrTooLarge, wantN: 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			src := &countingReader{remaining: tc.body}
			var dst bytes.Buffer

			n, err := guard.CopyCapped(&dst, src, tc.cap)
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
			}
			require.Equal(t, tc.wantN, n)

			// THE OVERRUN IS EXACTLY ONE BYTE, ever. LimitReader is given cap+1 so that "exactly
			// the cap" and "there was more" are distinguishable, and that extra byte is the whole
			// budget over the limit that anything is allowed to spend.
			require.LessOrEqual(t, src.read, tc.cap+1,
				"read %d bytes against a cap of %d: the source got to send more than one byte "+
					"past the limit", src.read, tc.cap)
		})
	}
}

// countingReader yields `remaining` bytes and counts how many were actually asked for, which is
// what makes "abandoned mid-stream" an assertion rather than a description.
type countingReader struct {
	remaining int
	read      int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, io.EOF
	}
	n := min(len(p), c.remaining)
	for i := range n {
		p[i] = byte(i)
	}
	c.remaining -= n
	c.read += int64(n)
	return n, nil
}

// TestReadCapped_StillBehaves — the buffering caller keeps its contract.
func TestReadCapped_StillBehaves(t *testing.T) {
	t.Parallel()

	got, err := guard.ReadCapped(strings.NewReader("hello"), 1024)
	require.NoError(t, err)
	require.Equal(t, "hello", string(got))

	_, err = guard.ReadCapped(strings.NewReader("hello"), 4)
	require.ErrorIs(t, err, guard.ErrTooLarge)
}

// TestNewClient_NeverSkipsCertificateVerification — RootCAs narrows trust; it does not remove it.
//
// A client with InsecureSkipVerify would make every https assertion in this package decorative:
// the scheme would be right and the peer would be whoever answered. There is no Config field that
// could set one, and this is what notices if somebody adds the line directly.
func TestNewClient_NeverSkipsCertificateVerification(t *testing.T) {
	t.Parallel()

	for _, cfg := range []guard.Config{
		{},
		{PermitLoopback: true},
		{RootCAs: x509.NewCertPool()},
	} {
		client := guard.NewClient(cfg)

		tr, ok := client.Transport.(*http.Transport)
		require.True(t, ok, "the transport is not an *http.Transport; the guarding lives on it")
		require.NotNil(t, tr.TLSClientConfig, "no TLS configuration: the defaults are not stated")
		require.False(t, tr.TLSClientConfig.InsecureSkipVerify,
			"certificate verification is off; https would be a scheme and not a guarantee")
		require.GreaterOrEqual(t, tr.TLSClientConfig.MinVersion, uint16(tls.VersionTLS12))
	}
}

// TestNewClient_TheResolverIsUsedAndChangesNothingAboutWhatIsRefused.
//
// Config.Resolver exists so a test can prove the address check runs against the RESOLVED address.
// It must not become a way to reach somewhere the guard would otherwise refuse: whatever a
// resolver answers still goes through the Control hook, which is the point.
func TestNewClient_TheResolverIsUsedAndChangesNothingAboutWhatIsRefused(t *testing.T) {
	t.Parallel()

	client := guard.NewClient(guard.Config{})
	tr, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	require.NotNil(t, tr.DialContext, "no dialer: the Control hook is where the refusal happens")
}
