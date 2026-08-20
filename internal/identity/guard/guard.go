// Package guard builds the HTTP client every outbound request in this service goes through.
//
// Gate NET001 permits outbound requests from `internal/identity/*` and `internal/artifact` only,
// and this package is where the actual guarding lives so that the two do not each grow their own
// idea of what "guarded" means. It sits under internal/identity rather than at the top of the tree
// because NET001 is written against the tree: a package that constructs an http.Client anywhere
// else fails the gate, and widening the gate to make room for the thing that implements it would
// be a strange way to keep it.
//
// The threat is SSRF, and it is not hypothetical here: an artifact URL is supplied by whoever is
// publishing, and an identity provider's endpoints are configuration. Four defences, and canonical
// §9 requires all four rather than the best one:
//
//   - THE DIALER REFUSES private, loopback, link-local, multicast, unspecified and cloud-metadata
//     addresses, and it does so in the Control hook — which runs against the RESOLVED address,
//     after DNS. A check on the hostname is defeated by a name that resolves to 127.0.0.1, and
//     a check on the resolved address before dialling is defeated by a second lookup returning
//     something else (DNS rebinding). The Control hook is the only place the two cannot be
//     different.
//   - https IS RE-ASSERTED ON EVERY REDIRECT HOP, not only on the first URL. A 302 from https to
//     http is a downgrade an attacker controls, and the interesting one is a 302 to
//     http://169.254.169.254/ from a host that looked fine.
//   - THE HOP COUNT IS CAPPED, so a redirect loop is a bounded error rather than a hung request.
//   - THE RESPONSE IS CAPPED DURING THE READ. See ReadCapped: a cap applied after the read has
//     already allocated whatever the far end chose to send.
package guard

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// Errors this package returns. They are sentinels because the caller's response differs: a refused
// address is worth an audit line naming the URL, and a size cap is worth one naming the limit.
var (
	// ErrBlockedAddress is a dial to an address the guard refuses. The message names the address
	// rather than the hostname, because the hostname is the part that lied.
	ErrBlockedAddress = errors.New("address is not routable on the public internet")

	// ErrNotHTTPS is a request or a redirect hop that is not https.
	ErrNotHTTPS = errors.New("url is not https")

	// ErrTooManyRedirects is the hop cap.
	ErrTooManyRedirects = errors.New("too many redirects")

	// ErrTooLarge is the size cap, raised DURING the read.
	ErrTooLarge = errors.New("response exceeds the size cap")
)

// Defaults. Each is a number somebody will want to change, so each says what it is protecting.
const (
	// DefaultTimeout bounds the whole request including the body read. GitHub's API answers in
	// well under a second; ten seconds is the point past which something is wrong rather than slow.
	DefaultTimeout = 10 * time.Second

	// DefaultMaxRedirects matches the client's own budget for the index (canonical §1). Release
	// asset URLs redirect twice — to the CDN and then to a signed URL — so the honest floor is
	// three, and five leaves room without letting a chain wander.
	DefaultMaxRedirects = 5
)

// Config is the only argument to NewClient.
type Config struct {
	// Timeout bounds the entire request. Zero means DefaultTimeout; there is no "no timeout".
	Timeout time.Duration

	// MaxRedirects caps the hop count. Zero means DefaultMaxRedirects. Negative means none are
	// followed at all, which is what a caller that wants to inspect a Location header asks for.
	MaxRedirects int

	// PermitLoopback disables the loopback half of the address check, and NOTHING ELSE.
	//
	// It exists so a test can point this client at an httptest server, which is the only way to
	// test the redirect and size behaviour against a real socket. It is deliberately narrow —
	// private and cloud-metadata ranges stay refused even when it is set — and no production
	// constructor sets it. TestNewClient_ProductionDefaults_RefuseLoopback is what asserts that.
	PermitLoopback bool

	// RootCAs replaces the certificate authorities used to verify a server, and NOTHING ELSE.
	//
	// It exists so a test can fetch from an httptest TLS server, whose certificate is signed by
	// nothing the system trusts. It can only ever NARROW or REPLACE the set of anchors — it cannot
	// widen what a given anchor vouches for, and there is deliberately no InsecureSkipVerify here
	// and no Config field that could set one. A client that skipped verification would make every
	// https assertion in this package decorative: the scheme would be right and the peer would be
	// whoever answered. TestNewClient_NeverSkipsCertificateVerification is what asserts that.
	RootCAs *x509.CertPool

	// Resolver overrides where hostnames are looked up. Nil means the system resolver.
	//
	// It changes WHERE A NAME IS LOOKED UP and never WHAT IS REFUSED: whatever a resolver hands
	// back still goes through the Control hook below, against the literal address the kernel is
	// about to connect to. That is the whole point of it being here — a test can hand this a
	// resolver that answers 10.0.0.1 for a name that looks perfectly ordinary, which is precisely
	// the DNS-rebinding shape, and watch the dial refused anyway. A guard that validated the
	// hostname and then let the resolver answer again would pass every other test in this file
	// and fail that one.
	Resolver *net.Resolver
}

// NewClient returns a client that only reaches the public internet over https.
func NewClient(cfg Config) *http.Client {
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}
	maxRedirects := cfg.MaxRedirects
	if maxRedirects == 0 {
		maxRedirects = DefaultMaxRedirects
	}

	dialer := &net.Dialer{
		Timeout:   cfg.Timeout,
		KeepAlive: 30 * time.Second,
		Resolver:  cfg.Resolver,
		Control:   control(cfg.PermitLoopback),
	}

	return &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
			// Verification is always on. MinVersion is stated rather than left to the default so
			// that "which TLS versions does this service accept from a server" is answerable by
			// reading this file, and so it cannot drift downwards with a toolchain change.
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				RootCAs:    cfg.RootCAs, // nil means the system pool
			},
			// A guarded dialer that never runs is not a guard. Proxy settings come from the
			// environment by default, and a proxy would make every connection go to the proxy's
			// address — which is inside the network we are refusing to reach.
			Proxy:                 nil,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			IdleConnTimeout:       30 * time.Second,
			TLSHandshakeTimeout:   cfg.Timeout,
			ExpectContinueTimeout: time.Second,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return fmt.Errorf("%w: %d hops from %s", ErrTooManyRedirects, len(via), via[0].URL)
			}
			// EVERY hop, not just the first. The dangerous redirect is the one that downgrades
			// after a request that looked fine, and http.Client does not check this for us.
			if !strings.EqualFold(req.URL.Scheme, "https") {
				return fmt.Errorf("%w: redirected to %s", ErrNotHTTPS, req.URL.Redacted())
			}
			return nil
		},
	}
}

// RequireHTTPS rejects a URL that is not a usable https URL, before a request is built.
//
// The redirect check above covers hops two onward; this covers hop one, where the URL came
// straight from a publish request or from configuration. Both are needed: a plain http:// URL
// never reaches CheckRedirect, because there is nothing to redirect from.
//
// It PARSES rather than matching a prefix, and the difference is not pedantry. `https://` and
// `https://?x` both begin with the right eight characters and name no host at all. A prefix check
// passes them, and what happens next is worse than a rejection would have been: this service
// enables sign-in and builds a callback URL of `https:///auth/github/callback`, which GitHub
// cannot redirect to — so the configuration is accepted at boot and fails in a browser, which is
// the failure mode this repository exists to design against. The function's NAME is a promise that
// what comes back is fetchable; a prefix is not evidence of that.
func RequireHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %q is not a url: %w", ErrNotHTTPS, rawURL, err)
	}
	// url.Parse lower-cases the scheme, so `HTTPS://example.com` is accepted here as it is by the
	// client's own parser — being the stricter end of a tolerant protocol is one thing, rejecting
	// a spelling everything else accepts is another.
	if u.Scheme != "https" {
		return fmt.Errorf("%w: %q", ErrNotHTTPS, rawURL)
	}
	if u.Hostname() == "" {
		return fmt.Errorf("%w: %q names no host", ErrNotHTTPS, rawURL)
	}
	return nil
}

// CopyCapped streams src into dst, refusing past maxBytes, and returns how many bytes it wrote.
//
// This is the cap "during the read" that canonical §9 requires, in the shape an artifact needs:
// the bytes go straight to a hash and are never held. A 50 MiB artifact read into a []byte first
// is 50 MiB of resident memory per concurrent publish, on the word of whoever supplied the URL —
// and the publish path has no use for the bytes afterwards.
//
// io.LimitReader is given maxBytes+1 so that "it was exactly the cap" and "there was more" are
// distinguishable. That one extra byte is the entire overrun: the copy stops there, the body is
// abandoned mid-stream, and the far end never gets to finish sending.
//
// THE CAP IS NEVER TAKEN FROM Content-Length. That header is written by the sender, so believing
// it would let an attacker declare one byte and send fifty megabytes — or declare fifty megabytes
// and be refused for bytes it never sent. The only number that counts is the one this function
// counted.
func CopyCapped(dst io.Writer, src io.Reader, maxBytes int64) (int64, error) {
	n, err := io.Copy(dst, io.LimitReader(src, maxBytes+1))
	if err != nil {
		return n, fmt.Errorf("read the response body: %w", err)
	}
	if n > maxBytes {
		return n, fmt.Errorf("%w of %d bytes", ErrTooLarge, maxBytes)
	}
	return n, nil
}

// ReadCapped reads at most max bytes and fails if there are more.
//
// It is CopyCapped into a buffer, for the callers that genuinely need the bytes — an identity
// provider's JSON answer, which is small and has to be parsed. A caller that only needs to
// measure or digest what arrived should use CopyCapped and never hold it.
func ReadCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := CopyCapped(&buf, r, maxBytes); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// control is the net.Dialer Control hook: the last point before the connection where the resolved
// address is known and the connection has not happened yet.
func control(permitLoopback bool) func(network, address string, c syscall.RawConn) error {
	return func(network, address string, _ syscall.RawConn) error {
		// Only TCP. A guard that silently permits udp or unix because it did not think of them is
		// a guard with a hole shaped like whatever it forgot.
		if !strings.HasPrefix(network, "tcp") {
			return fmt.Errorf("%w: %s is not tcp", ErrBlockedAddress, network)
		}

		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("split the dial address %q: %w", address, err)
		}
		addr, err := netip.ParseAddr(host)
		if err != nil {
			// Control is called with a literal address, so a name here means the resolver handed
			// us something we cannot check. Refusing is the only safe reading of "we do not know
			// what this is".
			return fmt.Errorf("%w: %q is not an ip address", ErrBlockedAddress, host)
		}
		if blocked(addr, permitLoopback) {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, addr)
		}
		return nil
	}
}

// cloudMetadata are the metadata endpoints that are NOT already covered by the link-local check.
//
// 169.254.169.254 (AWS, GCP, Azure, DigitalOcean) and fe80::/10 are link-local and refused below
// without help. These two are not, and each one hands out credentials to anything that can reach
// it, which is the entire prize in an SSRF.
var cloudMetadata = []netip.Addr{
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6 (unique-local, also refused below)
}

// blocked reports whether addr is one this service must never open a connection to.
//
// The list is deny-by-category rather than a set of CIDRs, because a CIDR list is a list somebody
// has to remember to extend. Everything that is not globally routable is refused, and the
// categories are named so that a reader can tell which one caught a given address.
func blocked(addr netip.Addr, permitLoopback bool) bool {
	// An IPv4-mapped IPv6 address (::ffff:127.0.0.1) answers false to Is4() and true to
	// IsLoopback() only after unmapping. Unmapping first means one check covers both spellings.
	addr = addr.Unmap()

	switch {
	case addr.IsLoopback():
		return !permitLoopback
	case addr.IsUnspecified(), // 0.0.0.0 and :: route to localhost on most stacks
		addr.IsLinkLocalUnicast(), // 169.254.0.0/16, fe80::/10 — includes cloud metadata
		addr.IsLinkLocalMulticast(),
		addr.IsInterfaceLocalMulticast(),
		addr.IsMulticast(),
		addr.IsPrivate(): // 10/8, 172.16/12, 192.168/16, fc00::/7
		return true
	}

	for _, meta := range cloudMetadata {
		if addr == meta {
			return true
		}
	}

	// 100.64.0.0/10, the carrier-grade NAT range, is neither private nor link-local by Go's
	// definitions and is where a provider's internal services sit often enough to matter.
	if addr.Is4() && addr.As4()[0] == 100 && addr.As4()[1]&0xc0 == 64 {
		return true
	}
	return false
}

// Response is what Do gives back.
//
// It is deliberately NOT an *http.Response. Do reads the body to the cap and closes it, so the
// Response it would otherwise hand back carries a drained, closed Body that every caller has to
// remember not to touch — and `bodyclose` cannot tell that it was closed, so every call site grows
// a waiver. A value with the three things a caller actually wants has neither problem.
type Response struct {
	StatusCode int
	Header     http.Header

	// Body is the whole response, never more than the cap Do was given.
	Body []byte
}

// Do runs req through client and returns the response, with its body read to maxBytes and closed.
//
// It exists so that every caller gets the body cap and the closed body without writing them out
// again — `bodyclose` lints the second half, nothing lints the first, and a 50 MiB artifact read
// into memory because one call site forgot is an out-of-memory kill rather than an error.
func Do(ctx context.Context, client *http.Client, req *http.Request, maxBytes int64) (Response, error) {
	// #nosec G704 -- this IS the guarded client: its dialer refuses private, loopback, link-local,
	// multicast and cloud-metadata addresses in the Control hook, after DNS, and its CheckRedirect
	// re-asserts https on every hop. The URL being attacker-influenced is the normal case here, and
	// the whole package is the mitigation.
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return Response{}, fmt.Errorf("request %s: %w", req.URL.Redacted(), err)
	}
	defer func() { _ = resp.Body.Close() }() // read to the cap or abandoned; either way it closes

	out := Response{StatusCode: resp.StatusCode, Header: resp.Header}

	body, err := ReadCapped(resp.Body, maxBytes)
	if err != nil {
		// The status is still returned: "it answered 500 and the body was oversized" and "it never
		// answered" are different things to the caller deciding whether to retry.
		return out, fmt.Errorf("read %s: %w", req.URL.Redacted(), err)
	}
	out.Body = body
	return out, nil
}
