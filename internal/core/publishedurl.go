package core

import (
	"errors"
	"fmt"
	"net/url"
)

// A URL this registry PUBLISHES, and the one rule that governs every one of them.
//
// Two columns hold a URL that is rendered verbatim into the index document and served to every
// nParse+ client on the internet: `release.artifact_url` and `plugin.homepage`. Both are cached by
// clients and by anything in front of them, and neither can be recalled once a client has seen it.
//
// THE RULE IS HERE, ONCE, BECAUSE IT WAS WRITTEN TWICE AND DRIFTED. `internal/artifact` refused
// userinfo, query and fragment; `internal/ownership` refused only userinfo, so a homepage of
// `https://example.com/?token=...` was publishable while an artifact URL with the same shape was
// not. Neither author was careless — the rule simply lived in two places, which is all it takes.
// A third column will one day need the same rule, and it will get this function.

// ErrUnpublishableURL is a URL this registry will not put in the index.
var ErrUnpublishableURL = errors.New("url is not one this registry will publish")

// CheckPublishedURL reports whether raw may be stored in a column the index renders.
//
// It requires https with a host, and refuses the three places a credential travels in a URL:
//
//   - USERINFO. `https://token@host/x` — a bare username is a credential on its own for plenty of
//     services, and url.URL.Redacted() famously does not remove it.
//   - THE QUERY, WHOLE. A signed URL's signature IS a bearer credential for whatever it points at;
//     that is what a signed URL is. It is refused entirely rather than by parameter name, because
//     a denylist of `X-Amz-Signature`, `sig`, `token`, `AWSAccessKeyId`, `sv`… is a list somebody
//     has to remember to extend, and the entry that gets forgotten is the one that leaks. The
//     guarded dialer refuses ADDRESSES by category for the same reason.
//   - THE FRAGMENT. Never sent to a server, so it cannot be part of reaching the resource — and
//     still published, still cached, still unrecallable.
//
// THE COST, STATED: a URL that genuinely needs a query parameter cannot be published without a
// change to this function. That is a loud refusal at submission time, argued in a pull request,
// which is the right way round compared to discovering a signature has been sitting in the public
// index for a week. Artifacts live on GitHub (ADR-0002), whose release assets are path-only, and
// every forge's project page is too.
//
// NONE OF THE MESSAGES ECHO THE URL. Each refusal is happening BECAUSE the value may hold a
// secret, and these errors reach logs and review notes.
func CheckPublishedURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		// A parse error's message quotes its input, and an input this service could not parse is
		// the last one to start trusting.
		return fmt.Errorf("%w: it is not a url", ErrUnpublishableURL)
	}

	switch {
	case u.Scheme != "https":
		// The scheme IS echoed: it is not a credential, and "javascript is not a scheme this
		// registry will publish as a link" is the sentence that tells somebody what to fix.
		return fmt.Errorf("%w: it must be https, and %q is not", ErrUnpublishableURL, u.Scheme)
	case u.Hostname() == "":
		return fmt.Errorf("%w: it names no host", ErrUnpublishableURL)
	case u.User != nil:
		return fmt.Errorf("%w: it carries credentials in its userinfo, and this url is published "+
			"in the index to every client", ErrUnpublishableURL)
	case u.RawQuery != "" || u.ForceQuery:
		return fmt.Errorf("%w: it carries a query string, and this url is published in the index "+
			"to every client — a signed url's signature is a credential for what it points at",
			ErrUnpublishableURL)
	case u.Fragment != "" || u.RawFragment != "":
		return fmt.Errorf("%w: it carries a fragment, which is never sent to a server and so "+
			"cannot be part of reaching the resource, but would be published in the index",
			ErrUnpublishableURL)
	}
	return nil
}
