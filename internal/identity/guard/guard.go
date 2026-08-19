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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
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
		Control:   control(cfg.PermitLoopback),
	}

	return &http.Client{
		Timeout: cfg.Timeout,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
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

// RequireHTTPS rejects a URL that is not https before a request is built.
//
// The redirect check above covers hops two onward; this covers hop one, where the URL came
// straight from a publish request or from configuration. Both are needed: a plain http:// URL
// never reaches CheckRedirect, because there is nothing to redirect from.
func RequireHTTPS(rawURL string) error {
	if !strings.HasPrefix(strings.ToLower(rawURL), "https://") {
		return fmt.Errorf("%w: %q", ErrNotHTTPS, rawURL)
	}
	return nil
}

// ReadCapped reads at most max bytes and fails if there are more.
//
// The cap is applied DURING the read (canonical §9): io.LimitReader is given max+1 so that "we
// read exactly the cap" and "there was more" are distinguishable, and the extra byte is the only
// thing over budget that is ever allocated. Checking Content-Length instead would trust a header
// the sender writes, and reading it all and then measuring is a 50 MiB allocation on the word of
// whoever supplied the URL.
func ReadCapped(r io.Reader, maxBytes int64) ([]byte, error) {
	buf, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read the response body: %w", err)
	}
	if int64(len(buf)) > maxBytes {
		return nil, fmt.Errorf("%w of %d bytes", ErrTooLarge, maxBytes)
	}
	return buf, nil
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

// Do runs req through client and returns the response body, capped at maxBytes.
//
// It exists so that every caller gets the body cap and the closed body without writing them out
// again — bodyclose lints the second half, nothing lints the first, and a 50 MiB artifact read
// into memory because one call site forgot is an out-of-memory kill rather than an error.
func Do(ctx context.Context, client *http.Client, req *http.Request, maxBytes int64) (
	*http.Response, []byte, error,
) {
	resp, err := client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, nil, fmt.Errorf("request %s: %w", req.URL.Redacted(), err)
	}
	defer func() { _ = resp.Body.Close() }() // the body is fully read or abandoned; either way it closes

	body, err := ReadCapped(resp.Body, maxBytes)
	if err != nil {
		return resp, nil, fmt.Errorf("read %s: %w", req.URL.Redacted(), err)
	}
	return resp, body, nil
}
