package artifact

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity/guard"
)

// MaxBytes is the hard cap on an artifact, enforced DURING the read and never from a header.
//
// Fifty mebibytes is what the CI job this server replaces allowed, and it is far above any real
// nParse+ plugin: the largest in the live catalogue is under two. It is a cap on what a stranger
// can make this process spend, not a size anybody is expected to approach.
const MaxBytes int64 = 50 << 20

// DefaultTimeout bounds the whole fetch: connect, TLS, redirects and every byte of the body.
//
// FORTY-FIVE SECONDS IS NOT AN ARBITRARY NUMBER. cmd/regserve serves with WriteTimeout of 60s, so
// a fetch allowed to run longer than that produces the worst outcome available: the release row is
// written, the response is cut off in flight, and the publishing workflow sees a failure for a
// publish that succeeded — then re-runs. Idempotency makes that recoverable rather than duplicated
// (canonical §6), but "recoverable" is not "correct", and a timeout that cannot fit inside the
// response it is part of is a bug waiting for a slow morning.
//
// TestDefaultTimeout_FitsInsideTheServersWriteTimeout ties the two together, so raising either one
// without redoing the arithmetic is a red test rather than a discovery.
//
// The cost, stated: 50 MiB in 45 seconds is a floor of about 1.2 MiB/s. An artifact that cannot be
// fetched that fast is not published — it goes to review with "not verified" recorded, which is
// the honest answer and is exactly what ADR-0008 asks for.
const DefaultTimeout = 45 * time.Second

// Errors this package returns. Each is a sentinel because the publish path answers them
// differently, and because Reason turns each into a review note a human reads during an incident.
var (
	// ErrNotFetched is any failure to obtain the bytes: refused address, bad scheme, timeout,
	// non-2xx status, connection reset. It wraps the specific cause.
	//
	// THE RELEASE IS NOT PUBLISHED. It goes to review with the reason recorded. "We could not
	// check" and "we checked and it was fine" must never produce the same outcome — that is the
	// one failure mode this whole design exists to prevent (ADR-0008).
	ErrNotFetched = errors.New("the artifact could not be fetched")

	// ErrBadStatus is a response that arrived and was not a 2xx. Separate from a transport failure
	// because a 404 on a release asset is somebody's typo and a 503 is GitHub having a morning.
	ErrBadStatus = errors.New("the artifact url did not answer with success")
)

// Config is the only argument to NewFetcher.
type Config struct {
	// Timeout bounds the whole fetch. Zero means DefaultTimeout; there is no "no timeout".
	Timeout time.Duration

	// MaxBytes caps the artifact. Zero means MaxBytes; negative is refused at construction rather
	// than silently becoming "everything".
	MaxBytes int64

	// PermitLoopback lets a test point the fetcher at an httptest server, and NOTHING ELSE:
	// private, link-local, multicast and cloud-metadata addresses stay refused even when it is
	// set. No production constructor sets it, and TestNewFetcher_ProductionDefaults_RefuseLoopback
	// is what asserts that.
	PermitLoopback bool

	// Resolver overrides where hostnames are looked up. Nil means the system resolver. It changes
	// nothing about what is refused — see guard.Config.Resolver, and the rebinding test that is
	// the reason it exists.
	Resolver *net.Resolver

	// RootCAs replaces the certificate authorities a server is verified against. Nil means the
	// system pool. Verification is never disabled — see guard.Config.RootCAs.
	RootCAs *x509.CertPool
}

// Fetcher downloads an artifact and hashes it.
//
// It holds the guarded client from internal/identity/guard, which is where the actual guarding
// lives so that the two packages permitted to make outbound requests cannot grow two different
// ideas of what "guarded" means (canonical §9).
type Fetcher struct {
	client   *http.Client
	clk      clock.Clock
	maxBytes int64
}

// ErrBadConfig is a Fetcher asked for something that is not a fetcher: a negative cap, no clock.
var ErrBadConfig = errors.New("artifact fetcher configuration")

// NewFetcher builds the fetcher. The clock is injected like everywhere else, because verified_at
// is a fact about when this server read the bytes and a test needs to be able to place it.
func NewFetcher(clk clock.Clock, cfg Config) (*Fetcher, error) {
	if clk == nil {
		return nil, fmt.Errorf("%w: no clock", ErrBadConfig)
	}
	if cfg.MaxBytes < 0 {
		return nil, fmt.Errorf("%w: negative byte cap %d", ErrBadConfig, cfg.MaxBytes)
	}
	if cfg.MaxBytes == 0 {
		cfg.MaxBytes = MaxBytes
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultTimeout
	}

	return &Fetcher{
		client: guard.NewClient(guard.Config{
			Timeout:        cfg.Timeout,
			PermitLoopback: cfg.PermitLoopback,
			Resolver:       cfg.Resolver,
			RootCAs:        cfg.RootCAs,
			// MaxRedirects is left at guard's default. A GitHub release asset redirects twice —
			// to the CDN and then to a signed URL — and every hop is re-checked for https and
			// dialled through the same refusing dialer.
		}),
		clk:      clk,
		maxBytes: cfg.MaxBytes,
	}, nil
}

// Result is what Fetch learned. It carries no bytes, on purpose: see the package comment.
type Result struct {
	// Digest is the sha256 of the bytes this server read. It is the value that gets stored, and
	// the only type that can reach the column.
	Digest Digest

	// Bytes is how many bytes were read, counted here rather than taken from a header.
	Bytes int64

	// FetchedAt is when this server read them. It becomes release.verified_at, which is the
	// database's own record that a stored hash was computed rather than accepted.
	FetchedAt time.Time

	// FinalHost is the host the last redirect hop landed on, which is often not the host in the
	// submitted URL — a GitHub release asset ends up on a CDN. It is what the artifact-host
	// quarantine rule compares against previous releases.
	//
	// THE HOST AND NOT THE URL, deliberately. A signed CDN URL carries its signature in the query
	// string, and this value is written into audit_log — a table that is append-only by trigger
	// and can therefore never be redacted. A hostname answers the question quarantine asks and
	// cannot carry a credential.
	FinalHost string
}

// Fetch downloads rawURL, hashes it, and discards it.
//
// Every defence canonical §9 requires is present here or in the client this holds, and each is
// load-bearing rather than belt-and-braces — removing one is a security change that needs an
// argument in the pull request:
//
//   - https IS RE-ASSERTED ON HOP ONE, here, before a request is built. A plain http:// URL never
//     reaches a redirect check, because there is nothing to redirect from.
//   - https IS RE-ASSERTED ON EVERY LATER HOP by the client's CheckRedirect. The interesting
//     redirect is not the first URL, it is the 302 to http://169.254.169.254/ from a host that
//     looked perfectly ordinary.
//   - THE HOP COUNT IS CAPPED, so a redirect loop is a bounded error rather than a hung request.
//   - EVERY HOP IS DIALLED THROUGH A DIALER THAT REFUSES private, loopback, link-local, multicast,
//     unspecified and cloud-metadata addresses, in the Control hook — which runs against the
//     RESOLVED address, after DNS, immediately before connect. Validating a hostname and handing
//     it back to the resolver is a DNS-rebinding TOCTOU, and it is the bug this class of code
//     usually has. The Control hook is the one place where the address that was checked and the
//     address that is connected to cannot be different ones.
//   - THE SIZE CAP IS ENFORCED DURING THE READ, never from Content-Length, which is written by
//     whoever we are being careful about. An oversized body is abandoned mid-stream.
//   - THE TIMEOUT IS EXPLICIT and the caller's ctx is carried throughout.
//
// A failure is ErrNotFetched, and the release it was for is not published.
func (f *Fetcher) Fetch(ctx context.Context, rawURL string) (Result, error) {
	// Hop one. RequireHTTPS parses rather than matching a prefix, so `https://` naming no host at
	// all is refused here rather than becoming a confusing dial error.
	//
	// ITS MESSAGE IS DROPPED AND ONLY ITS SENTINEL IS KEPT. RequireHTTPS formats the URL it was
	// given with %q, and the URL it was given here came out of a publish request: `http://
	// token@host/plugin.whl?sig=...` is a perfectly ordinary rejected input, and echoing it would
	// put the credential in the log line and the review note. guard is a package with several
	// callers and its own error is right for the ones whose URLs are configuration; this caller's
	// URLs are hostile by construction, so the sanitising happens here rather than there.
	if err := guard.RequireHTTPS(rawURL); err != nil {
		return Result{}, fmt.Errorf("%w: %w: %s", ErrNotFetched, guard.ErrNotHTTPS, safeRawURL(rawURL))
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		// transportCause for the same reason as below: NewRequest parses the URL, and a parse
		// failure is a *url.Error carrying the raw string. RequireHTTPS has already parsed it
		// successfully, so this is unreachable today — which is exactly when a leak gets in.
		return Result{}, fmt.Errorf("%w: build the request for %s: %w",
			ErrNotFetched, safeRawURL(rawURL), transportCause(err))
	}

	// #nosec G704 -- the URL is attacker-influenced BY DESIGN (ADR-0008), and this client is the
	// mitigation: its dialer refuses private, loopback, link-local, multicast and cloud-metadata
	// addresses in the Control hook after DNS, and its CheckRedirect re-asserts https on every
	// hop. Fetching a stranger's URL is this package's whole job.
	resp, err := f.client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %s: %w", ErrNotFetched, safeURL(req.URL), transportCause(err))
	}
	defer func() {
		// Closed on every path, including the one where the body is abandoned half-read because
		// it went over the cap. An unclosed 50 MiB body is a file descriptor and a connection held
		// until the finaliser runs, and `bodyclose` is the linter that would otherwise be right.
		_ = resp.Body.Close()
	}()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return Result{}, fmt.Errorf("%w: %w: %d", ErrNotFetched, ErrBadStatus, resp.StatusCode)
	}

	// The bytes go straight from the socket into the hash. They are never held, never written to a
	// path, never extracted and never executed — there is nowhere in this function they could be.
	sum := sha256.New()
	n, err := guard.CopyCapped(sum, resp.Body, f.maxBytes)
	if err != nil {
		return Result{}, fmt.Errorf("%w: %s: %w", ErrNotFetched, safeURL(req.URL), transportCause(err))
	}

	return Result{
		Digest:    Digest{hex: fmt.Sprintf("%x", sum.Sum(nil))},
		Bytes:     n,
		FetchedAt: f.clk.Now(),
		FinalHost: finalHost(resp),
	}, nil
}

// safeURL renders a URL for an error message, keeping only the parts that cannot be a credential.
//
// url.URL.Redacted() IS NOT ENOUGH, and the difference matters because the errors this package
// returns are deliberately propagated: the publish path logs them, and Reason turns them into a
// review note a human reads. Redacted replaces the PASSWORD and nothing else. It keeps the
// username, which is a credential on its own for plenty of services, and it keeps the entire query
// string -- which for a release asset is exactly where the signature lives:
//
//	https://alice@cdn.example/plugin.whl?X-Amz-Signature=...
//
// Redacted returns that unchanged. So this keeps the scheme, the host and the path, and drops
// userinfo, query and fragment outright.
//
// The path is kept because a 404 on /v1.2.0/plugin.whl is a different report from a 404 on the
// repository root, and a path is not where credentials are conventionally carried. If that stops
// being true for an upstream this service fetches from, this function is the one place to narrow.
func safeURL(u *url.URL) string {
	if u == nil {
		return ""
	}
	// Field by field rather than by clearing fields on a copy: a URL type that grows a member
	// would otherwise start carrying it here, which is how this kind of function rots. Opaque is
	// among the ones left out — for `javascript:alert(secret)` it holds the entire payload.
	safe := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	return safe.String()
}

// transportCause strips the *url.Error wrapper net/http puts around a transport failure.
//
// SAFEURL IS NOT ENOUGH ON ITS OWN, and this is the half that is easy to miss. http.Client.Do
// returns a *url.Error whose Error() renders as:
//
//	Get "https://alice@host/plugin.whl?X-Amz-Signature=...": dial tcp ...
//
// -- the RAW url, verbatim, embedded by the standard library. Wrapping that with %w puts the
// credential back into the message the line above just took it out of, which is exactly what
// happened here: the first fix redacted our own half of the string and the test still found the
// signature, because net/http had written it into the other half.
//
// Unwrapping to Err keeps everything a caller matches on -- guard.ErrBlockedAddress,
// guard.ErrNotHTTPS, context.Canceled all live below this wrapper -- and drops only the rendered
// URL. What is lost is the HTTP method, which is always GET here.
func transportCause(err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		return urlErr.Err
	}
	return err
}

// safeRawURL is safeURL for a string that has not been parsed yet, and may not parse at all.
//
// It exists for the first-hop rejection, where the URL is refused BECAUSE it is malformed or has
// the wrong scheme — so there is no *url.URL to hand to safeURL, and the string itself is the one
// thing that must not be echoed.
func safeRawURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		// Deliberately says nothing about the value. A parse error's message quotes the input,
		// and an input this service could not even parse is the last one to start trusting.
		return "(the url could not be parsed)"
	}
	return safeURL(u)
}

// finalHost reports the host the last hop landed on.
//
// resp.Request is the request that produced this response, which after a redirect chain is the
// LAST one rather than the one handed to Do. That is the host whose bytes we hashed, and it is the
// one the quarantine rule cares about.
func finalHost(resp *http.Response) string {
	if resp.Request == nil || resp.Request.URL == nil {
		return ""
	}
	return resp.Request.URL.Hostname()
}

// Reason turns a fetch failure into the sentence recorded on the release and shown to whoever
// reviews it.
//
// It is deliberately short, deliberately free of URLs and driver internals, and deliberately never
// optimistic. Canonical house style: the failure mode designed against is a CONFIDENT MISTAKE, not
// a miss — so every branch here says some version of "not verified", and there is no branch that
// says anything else.
func Reason(err error) string {
	const prefix = "not verified: "
	switch {
	case err == nil:
		// Reaching this means a caller asked why a success failed. Saying "verified" here would be
		// this function inventing the one answer it must never give.
		return prefix + "no reason was recorded"
	case errors.Is(err, guard.ErrBlockedAddress):
		return prefix + "the artifact url resolves to an address this service will not connect to"
	case errors.Is(err, guard.ErrNotHTTPS):
		return prefix + "the artifact url, or a redirect from it, was not https"
	case errors.Is(err, guard.ErrTooManyRedirects):
		return prefix + "the artifact url redirected too many times"
	case errors.Is(err, guard.ErrTooLarge):
		return prefix + fmt.Sprintf("the artifact is larger than the %d byte limit", MaxBytes)
	case errors.Is(err, ErrBadStatus):
		return prefix + "the artifact url did not answer with success"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return prefix + "the artifact could not be downloaded within the time limit"
	default:
		return prefix + "the artifact could not be downloaded"
	}
}

// ErrBadArtifactURL is a URL that must not be STORED, whatever fetching it would have done.
//
// It is separate from the fetch errors because it is a different judgement. Those say "we could
// not get the bytes"; this says "this value has no business in release.artifact_url", which is a
// column served verbatim in the public index to every installed client.
var ErrBadArtifactURL = errors.New("artifact url is not one this registry will publish")

// ValidateURL checks a submitted artifact URL before anything is fetched or stored.
//
// It is https-and-fetchable, per guard.RequireHTTPS, PLUS a rule that is about PUBLICATION rather
// than about safety, and that is the part worth reading twice.
//
// # This value is published, and cannot be recalled
//
// release.artifact_url is rendered verbatim into the index document and served to every nParse+
// client on the internet. It is cached by clients and by anything in front of them. Whatever goes
// in that column is public the moment a client polls, and this registry cannot take it back.
//
// So a URL that carries a credential is refused, in both of the two shapes that carry one:
//
//   - USERINFO. `https://token@host/plugin.whl` fetches perfectly well and would publish the token.
//   - QUERY AND FRAGMENT. `https://host/plugin.whl?X-Amz-Signature=...` is a BEARER CREDENTIAL for
//     those bytes for as long as the signature is valid — that is the entire purpose of a signed
//     URL. Publishing one hands it to everybody, and the same reasoning already keeps signed
//     queries out of this service's error messages and out of audit_log. The field that is
//     ACTUALLY PUBLISHED is the one where it matters most.
//
// # Why the whole query, and not the parameters that look dangerous
//
// A denylist of `X-Amz-Signature`, `token`, `sig`, `Signature`, `AWSAccessKeyId`... is a list
// somebody has to remember to extend, and the one that gets forgotten is the one that leaks. The
// guarded dialer refuses addresses by CATEGORY for the same reason. A submitted artifact URL has
// no legitimate need for a query string: ADR-0002 keeps artifacts on GitHub, whose release assets
// are `https://github.com/owner/repo/releases/download/vX/asset.whl` — path only. The redirect TO
// a signed CDN URL happens during the fetch and is not what gets stored.
//
// THE COST, STATED: an upstream that genuinely needs a query parameter to serve an artifact cannot
// be published here without a change to this function. That is a loud, fixable refusal at publish
// time, argued in a pull request — which is the right way round compared to discovering that a
// signature has been sitting in the public index for a week.
//
// # Refused, not stripped
//
// A URL that needed a credential to fetch will not fetch without it, so silently removing the
// credential would produce a listing whose artifact 401s for every user. A refused publish tells
// the submitter something they can act on; a broken listing tells their users nothing.
func ValidateURL(rawURL string) error {
	if err := guard.RequireHTTPS(rawURL); err != nil {
		// The message is dropped for the reason Fetch drops it: RequireHTTPS quotes the URL, and
		// this one came out of a publish request.
		return fmt.Errorf("%w: %w: %s", ErrBadArtifactURL, guard.ErrNotHTTPS, safeRawURL(rawURL))
	}

	// Parsed again rather than threaded out of RequireHTTPS: that function's contract is a
	// boolean-shaped one, and widening it to return a *url.URL would make every other caller hold
	// a parsed value it does not want. The parse has already succeeded once, so this cannot fail.
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrBadArtifactURL, safeRawURL(rawURL))
	}

	// NONE of these messages echo the URL. Each one is refusing a value BECAUSE it may contain a
	// credential, and putting it in an error would send it to the log and the review note — the
	// two places this service has already had to take it out of.
	switch {
	case u.User != nil:
		return fmt.Errorf("%w: it carries credentials in its userinfo, and this url is published "+
			"in the index to every client", ErrBadArtifactURL)
	case u.RawQuery != "" || u.ForceQuery:
		return fmt.Errorf("%w: it carries a query string, and this url is published in the index "+
			"to every client — a signed url's signature is a credential for those bytes. Submit "+
			"the stable download url; redirects to a signed one are followed when the artifact is "+
			"fetched", ErrBadArtifactURL)
	case u.Fragment != "" || u.RawFragment != "":
		return fmt.Errorf("%w: it carries a fragment, which is never sent to the server and so "+
			"cannot be part of fetching the artifact, but would be published in the index",
			ErrBadArtifactURL)
	}
	return nil
}
