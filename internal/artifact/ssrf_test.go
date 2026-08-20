package artifact_test

import (
	"crypto/x509"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity/guard"
)

// This service fetches URLs a stranger supplied, by design (ADR-0008). That is an SSRF surface by
// construction, and every test in this file is a specific way that surface is usually exploited.
//
// A note on what these prove and what they do not: a passing test here says the defence is present
// and fires. It does not say the defence is complete, and the categories the dialer refuses are
// deny-by-category rather than a CIDR list precisely because a list is a thing somebody has to
// remember to extend.

// testClock is fixed so that Result.FetchedAt — which becomes release.verified_at, the database's
// own record that a hash was computed rather than accepted — is an exact assertion.
var testClock = clock.Fixed{T: time.Unix(1_760_000_000, 0).UTC()}

// tlsServer starts an https server and returns it with a fetcher that trusts it.
//
// Real TLS rather than plain http, because the fetcher refuses anything else and a test that had
// to relax that would be testing a service nobody runs. The trust is narrowed to this one
// certificate: RootCAs REPLACES the anchors, it does not disable verification, and there is no
// way to ask this package for a client that skips it.
func tlsServer(t *testing.T, h http.Handler, cfg artifact.Config) (*httptest.Server, *artifact.Fetcher) {
	t.Helper()

	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())

	// PermitLoopback relaxes the loopback check AND NOTHING ELSE: every assertion in this file
	// about a private, link-local, multicast or metadata address is made by a fetcher that is
	// still refusing all of them.
	cfg.PermitLoopback = true
	cfg.RootCAs = pool
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}

	f, err := artifact.NewFetcher(testClock, cfg)
	require.NoError(t, err)
	return srv, f
}

// TestFetch_BlockedAddresses_AreRefused — the dialer refuses everything that is not routable on
// the public internet, in both address families and in both spellings of a v4 address.
//
// These are literals rather than names on purpose: a literal reaches the Control hook with nothing
// in between, so a failure here is unambiguously the address check and not a resolver.
func TestFetch_BlockedAddresses_AreRefused(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
	}{
		{"ipv4 loopback", "https://127.0.0.1/plugin.zip"},
		{"ipv4 loopback, other than .1", "https://127.99.12.3/plugin.zip"},
		{"ipv6 loopback", "https://[::1]/plugin.zip"},
		{"ipv4-mapped ipv6 loopback", "https://[::ffff:127.0.0.1]/plugin.zip"},
		{"rfc1918 ten", "https://10.0.0.1/plugin.zip"},
		{"rfc1918 172.16", "https://172.16.0.1/plugin.zip"},
		{"rfc1918 192.168", "https://192.168.1.1/plugin.zip"},
		{"ipv4-mapped ipv6 private", "https://[::ffff:10.0.0.1]/plugin.zip"},
		{"unique local ipv6", "https://[fd00::1]/plugin.zip"},
		{"link-local ipv4", "https://169.254.1.1/plugin.zip"},
		{"link-local ipv6", "https://[fe80::1]/plugin.zip"},
		{"cloud metadata, the famous one", "https://169.254.169.254/latest/meta-data/"},
		{"cloud metadata, alibaba", "https://100.100.100.200/latest/meta-data/"},
		{"cloud metadata, aws over ipv6", "https://[fd00:ec2::254]/latest/meta-data/"},
		{"unspecified ipv4", "https://0.0.0.0/plugin.zip"},
		{"unspecified ipv6", "https://[::]/plugin.zip"},
		{"multicast ipv4", "https://224.0.0.1/plugin.zip"},
		{"multicast ipv6", "https://[ff02::1]/plugin.zip"},
		{"carrier-grade nat", "https://100.64.0.1/plugin.zip"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// A PRODUCTION-SHAPED FETCHER: no PermitLoopback. This table is the whole deny list,
			// and testing it through the relaxation that exists for httptest would be testing a
			// configuration nothing ships with — and would silently drop the loopback rows, which
			// are the ones an SSRF actually aims at first.
			f, err := artifact.NewFetcher(
				testClock,
				artifact.Config{Timeout: 5 * time.Second},
			)
			require.NoError(t, err)

			_, err = f.Fetch(t.Context(), tc.url)

			require.ErrorIs(t, err, artifact.ErrNotFetched)
			require.ErrorIs(t, err, guard.ErrBlockedAddress,
				"%s reached the network; the dialer must refuse it", tc.url)
			require.Equal(t,
				"not verified: the artifact url resolves to an address this service will not connect to",
				artifact.Reason(err))
		})
	}
}

// TestFetch_HostnameResolvingToAPrivateAddress_IsRefusedAtConnectTime — the DNS-rebinding case.
//
// THIS IS THE TEST THE BRIEF FOR THIS PHASE ASKED FOR, and it is the bug this class of code
// usually has. The submitted URL names an ordinary-looking host. Nothing about the STRING is
// refusable — it is not a literal, not loopback, not obviously internal. The refusal has to happen
// after the name is resolved and before the socket is connected, against the address that came
// back.
//
// A guard that validated the hostname and then handed the name back to the resolver would pass
// every other test in this file. It would also be exploitable by anyone who can serve two answers
// for one name: the check sees a public address, the connect gets a private one.
func TestFetch_HostnameResolvingToAPrivateAddress_IsRefusedAtConnectTime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		host     string
		resolves net.IP
	}{
		{"rebinds to rfc1918", "artifacts.example.test.", net.IPv4(10, 0, 0, 7)},
		{"rebinds to loopback", "cdn.example.test.", net.IPv4(127, 0, 0, 1)},
		{"rebinds to cloud metadata", "releases.example.test.", net.IPv4(169, 254, 169, 254)},
		{"rebinds to ipv6 unique-local", "assets.example.test.", net.ParseIP("fd00::99")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resolver := startFakeDNS(t, dnsRecords{tc.host: tc.resolves})

			// PermitLoopback is NOT set here, deliberately. This fetcher is production-shaped:
			// every category is refused, including the loopback one, which is what makes the
			// "rebinds to loopback" row meaningful rather than a special case.
			f, err := artifact.NewFetcher(
				testClock,
				artifact.Config{Timeout: 5 * time.Second, Resolver: resolver},
			)
			require.NoError(t, err)

			name := tc.host[:len(tc.host)-1] // the wire form has a trailing dot; a URL does not
			_, err = f.Fetch(t.Context(), "https://"+name+"/plugin.zip")

			require.ErrorIs(t, err, artifact.ErrNotFetched)
			require.ErrorIs(t, err, guard.ErrBlockedAddress,
				"a name resolving to %s was dialled; the check must run against the RESOLVED "+
					"address, not the hostname", tc.resolves)
			// The error names the ADDRESS and not the name. The hostname is the part that lied,
			// and an operator reading this at 2am needs to know what it lied about.
			require.Contains(t, err.Error(), tc.resolves.String())
		})
	}
}

// TestFetch_ARedirectIsRefused_OnEveryHopAndInBothWays — hop two onward is where the interesting
// attack lives.
//
// The first URL is one a reviewer might eyeball. The redirect is not: it is chosen at request time
// by whoever controls the host the first URL points at, so a check that only ran on hop one is a
// check an attacker steps around by answering 302.
func TestFetch_ARedirectIsRefused_OnEveryHopAndInBothWays(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		wantIs error
	}{
		{
			// The downgrade. https on the way in, plaintext on the way out, to the address that
			// hands out cloud credentials to anything that can reach it.
			name:   "downgrade to http at the metadata service",
			target: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
			wantIs: guard.ErrNotHTTPS,
		},
		{
			// Still https, so the scheme check is satisfied and the ADDRESS check is what has to
			// catch it. Both defences are needed; neither is a superset of the other.
			name:   "https to the metadata service",
			target: "https://169.254.169.254/latest/meta-data/",
			wantIs: guard.ErrBlockedAddress,
		},
		{
			name:   "https to a private address",
			target: "https://10.1.2.3/internal",
			wantIs: guard.ErrBlockedAddress,
		},
		{
			name:   "downgrade to http on an otherwise ordinary host",
			target: "http://example.test/plugin.zip",
			wantIs: guard.ErrNotHTTPS,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv, f := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tc.target, http.StatusFound)
			}), artifact.Config{})

			_, err := f.Fetch(t.Context(), srv.URL+"/plugin.zip")

			require.ErrorIs(t, err, artifact.ErrNotFetched)
			require.ErrorIs(t, err, tc.wantIs)
		})
	}
}

// TestFetch_ARedirectLoop_IsBoundedRatherThanHung — the hop cap.
func TestFetch_ARedirectLoop_IsBoundedRatherThanHung(t *testing.T) {
	t.Parallel()

	var target string
	srv, f := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target+"/again", http.StatusFound)
	}), artifact.Config{})
	target = srv.URL

	_, err := f.Fetch(t.Context(), srv.URL+"/plugin.zip")

	require.ErrorIs(t, err, artifact.ErrNotFetched)
	require.ErrorIs(t, err, guard.ErrTooManyRedirects)
	require.Equal(t, "not verified: the artifact url redirected too many times", artifact.Reason(err))
}

// TestFetch_APlainHTTPURL_IsRefusedBeforeAnyRequestIsBuilt — hop one.
//
// A plain http:// URL never reaches the redirect check, because there is nothing to redirect from.
// The two halves are both needed and neither covers the other.
func TestFetch_APlainHTTPURL_IsRefusedBeforeAnyRequestIsBuilt(t *testing.T) {
	t.Parallel()

	reached := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached <- struct{}{}
	}))
	t.Cleanup(srv.Close)

	f, err := artifact.NewFetcher(testClock,
		artifact.Config{Timeout: 5 * time.Second, PermitLoopback: true})
	require.NoError(t, err)

	_, err = f.Fetch(t.Context(), srv.URL+"/plugin.zip") // httptest.NewServer is http://

	require.ErrorIs(t, err, artifact.ErrNotFetched)
	require.ErrorIs(t, err, guard.ErrNotHTTPS)
	require.Empty(t, reached, "the request was made; an http:// url must be refused before that")
}

// TestFetch_AURLThatIsNotAFetchableHTTPSURL_IsRefused — the shapes that begin with the right eight
// characters and name nothing.
func TestFetch_AURLThatIsNotAFetchableHTTPSURL_IsRefused(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{
		"",
		"https://",
		"https://?x=1",
		"http://example.test/plugin.zip",
		"ftp://example.test/plugin.zip",
		"file:///etc/passwd",
		"gopher://example.test:70/_test",
		"//example.test/plugin.zip",
		"javascript:alert(1)",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Parallel()

			f, err := artifact.NewFetcher(testClock,
				artifact.Config{Timeout: 5 * time.Second, PermitLoopback: true})
			require.NoError(t, err)

			_, err = f.Fetch(t.Context(), raw)

			require.ErrorIs(t, err, artifact.ErrNotFetched)
			require.ErrorIs(t, err, guard.ErrNotHTTPS)
		})
	}
}

// TestNewFetcher_ProductionDefaults_RefuseLoopback — the test-only relaxation is test-only.
//
// PermitLoopback exists so the rest of this file can run against a real socket. A production
// constructor that set it would make every other assertion here a description of the test suite
// rather than of the service.
func TestNewFetcher_ProductionDefaults_RefuseLoopback(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("plugin"))
	}))
	t.Cleanup(srv.Close)

	f, err := artifact.NewFetcher(testClock,
		artifact.Config{Timeout: 5 * time.Second}) // no PermitLoopback
	require.NoError(t, err)

	_, err = f.Fetch(t.Context(), srv.URL+"/plugin.zip")
	require.ErrorIs(t, err, guard.ErrBlockedAddress)
}

// TestFetch_DefaultConfiguration_IsGuarded — a fetcher built with a zero Config still has a
// timeout and still has a cap.
//
// A zero value that means "no limit" is how a defence becomes optional: nothing fails, nothing
// says anything, and the first caller who forgets a field has built an unguarded fetcher.
func TestFetch_DefaultConfiguration_IsGuarded(t *testing.T) {
	t.Parallel()

	f, err := artifact.NewFetcher(testClock, artifact.Config{})
	require.NoError(t, err)

	// Loopback is refused, which is only true if the zero Config did not turn the checks off.
	_, err = f.Fetch(t.Context(), "https://127.0.0.1/plugin.zip")
	require.ErrorIs(t, err, guard.ErrBlockedAddress)
}

// TestNewFetcher_ARefusableConfiguration_IsRefusedAtConstruction — a negative cap is not "no cap".
func TestNewFetcher_ARefusableConfiguration_IsRefusedAtConstruction(t *testing.T) {
	t.Parallel()

	_, err := artifact.NewFetcher(clock.Fixed{}, artifact.Config{MaxBytes: -1})
	require.ErrorIs(t, err, artifact.ErrBadConfig)

	_, err = artifact.NewFetcher(nil, artifact.Config{})
	require.ErrorIs(t, err, artifact.ErrBadConfig)
}

// TestFetch_UserinfoInTheURL_IsNotEchoedIntoTheError — credentials in a URL stay out of the log.
//
// A publish request is free to submit https://user:password@host/..., and the error from a failed
// fetch is logged and can reach a review note. url.Redacted is what keeps the password out of both.
func TestFetch_UserinfoInTheURL_IsNotEchoedIntoTheError(t *testing.T) {
	t.Parallel()

	f, err := artifact.NewFetcher(testClock, artifact.Config{Timeout: 5 * time.Second})
	require.NoError(t, err)

	_, err = f.Fetch(t.Context(), "https://someone:hunter2@10.0.0.1/plugin.zip")

	require.ErrorIs(t, err, guard.ErrBlockedAddress)
	require.NotContains(t, err.Error(), "hunter2")
}

// TestFetch_AURLIsNeverParsedTwiceIntoDifferentThings — the URL the guard checked is the URL
// fetched.
//
// A check that parses the string, approves it, and then hands the ORIGINAL STRING to a second
// parser is a check on a different value than the one used. It is the same class of bug as
// validating a hostname and re-resolving it, one layer up.
func TestFetch_AURLIsNeverParsedTwiceIntoDifferentThings(t *testing.T) {
	t.Parallel()

	// Parsed by RequireHTTPS as https with host example.test; a second, sloppier parse might read
	// the userinfo as the host and reach a different conclusion.
	const raw = "https://example.test@10.0.0.1/plugin.zip"

	u, err := url.Parse(raw)
	require.NoError(t, err)
	require.Equal(t, "10.0.0.1", u.Hostname(), "the fixture is only interesting if net/url agrees")

	f, err := artifact.NewFetcher(testClock, artifact.Config{Timeout: 5 * time.Second})
	require.NoError(t, err)

	_, err = f.Fetch(t.Context(), raw)
	require.ErrorIs(t, err, guard.ErrBlockedAddress)
}
