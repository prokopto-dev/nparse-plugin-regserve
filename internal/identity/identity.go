// Package identity resolves a person at an OAuth provider into an identity this service can store.
//
// The data model is ADR-0003's and has not moved: an `account` is the thing that owns plugins and
// holds tokens, and an `identity(provider, subject)` is a way to prove you are that account. One
// account may hold several. ADR-0011 ships exactly one provider against that model — GitHub — and
// is explicit that this is one provider, not a collapse of the schema: adding a second is a row in
// `identity_provider` and a package under here, not a migration on a primary key.
//
// `subject` is the provider's IMMUTABLE NUMERIC ID and never the handle. Handles change, and the
// entire reason the account and the identity are separate rows is to survive that. A rename must
// be a decoration refresh, not a new account with somebody else's plugins.
//
// This package and its subpackages are two of the three trees permitted to make outbound HTTP
// requests (gate NET001). Everything they send goes through internal/identity/guard.
package identity

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// Kind is a provider's key. It is the value in `identity.provider_kind` and in the
// `identity_provider` table's primary key, so the spelling is the database's spelling.
type Kind string

// KindGitHub is the only provider that exists (ADR-0011). It is written out as a whole quoted
// literal because it is a database value, and a composed one would not be greppable.
const KindGitHub Kind = "github"

func (k Kind) String() string { return string(k) }

// Identity is one resolved provider identity.
//
// Subject is the only field that is an identifier. Handle and DisplayName are cached decoration
// refreshed at every login, shown to humans, and never matched on — the static registry compared
// handles case-insensitively and that is exactly the property being replaced.
type Identity struct {
	Provider Kind

	// Subject is the provider's immutable id, as text. For GitHub it is the numeric user id.
	Subject string

	// Handle is the login name as it was at this login: `prokopto-dev`, with no leading @.
	Handle string

	// DisplayName is the human name the provider holds, which is frequently empty.
	DisplayName string
}

// Errors a provider returns. They are sentinels so the callback handler can answer 401 for a
// credential problem and 502 for the provider being unreachable, rather than mapping strings.
var (
	// ErrExchangeRejected is the provider refusing the authorization code: reused, expired, or
	// issued to a different client. It is a normal thing to see in a log — a user who waits on the
	// consent screen and then presses the back button produces one — so it is not an alarm.
	ErrExchangeRejected = errors.New("the provider rejected the authorization code")

	// ErrProviderUnavailable is the provider being unreachable or answering with something this
	// code cannot parse. It is deliberately distinct from a rejection: one is the user's session,
	// the other is our dependency, and telling a user to try again is only right for the second.
	ErrProviderUnavailable = errors.New("the identity provider is unavailable")

	// ErrNoSubject is a provider that authenticated somebody and then did not say who. It should
	// be impossible; it is a distinct error because silently creating an account keyed on an empty
	// subject would collapse every such login onto ONE account.
	ErrNoSubject = errors.New("the provider returned no subject")
)

// Provider is one OAuth identity provider.
//
// Both methods take the PKCE material explicitly rather than holding it, because a provider value
// is shared by every concurrent login and a verifier belongs to one of them. A field would be a
// data race with a security consequence rather than a corrupted counter.
type Provider interface {
	// Kind is the provider's key, which is also its row in `identity_provider`.
	Kind() Kind

	// AuthorizeURL is where the browser is sent. state and challenge are minted by the caller from
	// crypto/rand; this method only assembles the URL.
	AuthorizeURL(state, challenge string) string

	// Exchange trades an authorization code for the identity behind it.
	//
	// The provider's access token is used once, inside this call, to read the identity — and is
	// then discarded. It is never returned, never stored and never logged: this service has no use
	// for acting as the user at the provider, so holding the token would be an asset with no
	// purpose and a breach with no upside.
	Exchange(ctx context.Context, code, verifier string) (Identity, error)
}

// Registry is the set of providers this build offers.
//
// It holds one today and is a map anyway, because ADR-0011's reversal cost is "a package and a
// row" and a hard-coded single provider would make it "a package, a row and every call site".
type Registry struct {
	providers map[Kind]Provider
}

// NewRegistry builds a registry from the providers this build has configured.
func NewRegistry(providers ...Provider) *Registry {
	m := make(map[Kind]Provider, len(providers))
	for _, p := range providers {
		m[p.Kind()] = p
	}
	return &Registry{providers: m}
}

// ErrUnknownProvider is a kind this build does not implement. A login URL naming one is a request
// for a provider that was never registered — a stale bookmark, or somebody probing.
var ErrUnknownProvider = errors.New("unknown identity provider")

// Get returns the provider for kind.
func (r *Registry) Get(kind Kind) (Provider, error) {
	p, ok := r.providers[kind]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProvider, kind)
	}
	return p, nil
}

// Kinds returns the configured provider kinds, sorted. Used by the login page, so that a build
// with no provider configured renders a page saying so rather than a button that 404s.
//
// Sorted because it comes from a map and the login page is rendered from it: a button order that
// changes between requests reads as a broken page, and a second provider would make that visible.
func (r *Registry) Kinds() []Kind {
	out := make([]Kind, 0, len(r.providers))
	for k := range r.providers {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
