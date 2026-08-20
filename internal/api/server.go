// Package api holds every HTTP route in this service. Gate ROUTE001 enforces that.
//
// Routes live in one tree so that "what does this service expose" is answerable by reading a
// directory, and so the coverage tests — which walk the route registry to assert every operation
// declares a permission — cannot be defeated by a route registered somewhere they do not look.
//
// Registration goes through Huma v2 (ADR-0012): operations are declared, not just handled, so the
// OpenAPI document is derived from the same code that serves the traffic rather than maintained
// beside it. What Huma is NOT allowed to do is decide anything about the bytes of the schema-v1
// index document — see index.go and newHumaAPI below.
package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/api/middleware"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
)

// BasePath is the product API. The index endpoints deliberately sit OUTSIDE it — their shape is
// pinned by a parser we do not own, so they must not move when the product API versions. See
// ADR-0009 and canonical §6.
//
// No route is mounted under it yet: the sign-in journey and the account surface sit outside it for
// the same reason the index endpoints do — they are browser paths, and an OAuth App's registered
// callback URL must not move when the product API versions. It is declared here so the first
// handler that needs the prefix reaches for this constant rather than typing the string, which is
// how a service ends up with two spellings of its own base path.
const BasePath = "/api/v1"

// contentTypeJSON is the only media type this service marshals into. One spelling, because the
// format map, the default format, the response declarations and the problem+json filter all have
// to agree, and four string literals are four chances for them not to.
const contentTypeJSON = "application/json"

// SpecVersion is the version of the API DESCRIPTION, not of the binary.
//
// It is deliberately not the ldflags build stamp: openapi/openapi.json is a checked-in generated
// file and gate GEN001 regenerates it to compare, so a version that changed with every build would
// report drift on every commit and teach everyone to ignore the gate. Bump it when the described
// contract changes.
const SpecVersion = "1.0.0"

// Catalogue is what the API needs in order to render the index.
//
// A consumer-declared interface rather than a concrete store type: it keeps internal/api free of
// database/sql (gate SQL001), and it lets the index endpoints be tested against a fixture without
// a database at all.
type Catalogue interface {
	// Listings returns every publicly visible plugin, in any order. NewIndex sorts.
	Listings(ctx context.Context) ([]registry.Plugin, error)

	// Listing returns one plugin. It must return ErrListingNotFound when the id is unknown or not
	// publicly visible — a delisted plugin is indistinguishable from a missing one to a client.
	Listing(ctx context.Context, id core.PluginID) (registry.Plugin, error)
}

// ReadyChecker reports whether the service can serve traffic that touches the database.
type ReadyChecker interface {
	Ready(ctx context.Context) error
}

// Config is the only argument to New.
//
// One struct rather than a long parameter list, because every caller — the serve command, the
// tests, and the spec generator — should be constructing the same thing, and a positional list of
// six optional dependencies is a list somebody eventually passes in the wrong order.
type Config struct {
	// Version, Commit and BuildDate are ldflags stamps. No endpoint serves them yet — the meta
	// operation under BasePath arrives with the product API in Phase 2. Until then `regserve
	// version` is where they are readable, and they are carried here so that endpoint needs no
	// change to the wiring. They are NOT the OpenAPI version; see SpecVersion.
	Version   string
	Commit    string
	BuildDate string

	// Clock is injected. A nil Clock falls back to the system clock so tests that do not care
	// about time do not have to say so.
	Clock clock.Clock

	// Catalogue backs the index endpoints. A nil Catalogue means those routes are not registered
	// at all, rather than registered and returning 500 — a route that exists but cannot work is
	// worse than an honest 404.
	Catalogue Catalogue

	// Readiness backs /readyz. Nil means the endpoint is not registered.
	//
	// The serve command always supplies one, including on an instance with no catalogue: a
	// readiness check that reports "not ready, and here is why" is working, and answering 404
	// instead reads to an operator like an older build is deployed.
	Readiness ReadyChecker

	// Authn resolves the credential on a request. Nil means this build cannot authenticate: the
	// middleware still runs and every non-public operation answers 503, which is the honest
	// statement. It must NOT mean "let everything through" — a nil dependency that opens a door is
	// the failure mode this whole layer exists to prevent.
	Authn Authenticator

	// Login and Sessions back the sign-in journey, and Providers is what a login URL is resolved
	// against. All three are needed together; any of them nil means the auth routes are not
	// registered at all, exactly as a nil Catalogue leaves the index endpoints unregistered.
	//
	// A deployment with no OAuth client configured therefore serves the catalogue and answers 404
	// on /auth/github/login, rather than serving a sign-in button that leads to a 500.
	Login     Login
	Sessions  SessionIssuer
	Providers *identity.Registry

	// Tokens backs the account surface's token management. It is separate from Authn because the
	// two are different jobs: Authn answers "who is this request", Tokens mints and revokes the
	// credentials a pipeline uses. Nothing registers a route against it yet — token management is
	// a capability-floor operation and therefore browser-only, and the pages arrive with the
	// account surface.
	Tokens TokenService

	// Ownership backs the plugin settings page. Nil, like a nil Tokens, means the account surface
	// is not registered — an honest 404 rather than a page that half works.
	Ownership OwnershipService
}

// TokenService is what the account surface needs in order to manage personal access tokens.
//
// Declared here, next to its consumer, for the same reason Catalogue is: internal/api says what it
// needs and the wiring supplies it.
type TokenService interface {
	Mint(ctx context.Context, req auth.MintRequest) (auth.NewToken, error)
	List(ctx context.Context, accountID string) ([]auth.Listing, error)
	Revoke(ctx context.Context, accountID, tokenID string) error
}

// New builds the HTTP handler.
func New(cfg Config) http.Handler {
	if cfg.Clock == nil {
		cfg.Clock = clock.System{}
	}

	mux := http.NewServeMux()
	api := newHumaAPI(mux)

	// Installed before any route is registered, and unconditionally. It enforces the Access every
	// operation declares — including "public", which it passes straight through — so that the
	// document's description of who may call an operation and the server's behaviour come from one
	// value rather than two. A middleware added only when authentication is configured would be a
	// middleware that is absent on exactly the instance where a route was left undeclared.
	api.UseMiddleware(authMiddleware(api, cfg.Authn))

	registerHealth(api, cfg.Readiness)
	if cfg.Catalogue != nil {
		registerIndex(api, cfg.Catalogue)
	}
	if cfg.Login != nil && cfg.Sessions != nil && cfg.Providers != nil {
		registerAuth(api, cfg.Login, cfg.Sessions, cfg.Providers)

		// The account surface needs everything the sign-in journey needs, plus somewhere to read
		// and write. Registered together with it and on the same condition: a sign-in that leads
		// to a 404 and an account page with no way to reach it are the same defect from two ends.
		if cfg.Tokens != nil && cfg.Ownership != nil {
			registerWeb(api, WebDeps{
				Sessions:  cfg.Sessions,
				Tokens:    cfg.Tokens,
				Ownership: cfg.Ownership,
				Providers: cfg.Providers,
			})
		}
	}

	// Plain http.Handler wrappers rather than Huma middleware, because they must also cover the
	// responses Huma never sees: the 404 and 405 the mux answers by itself. A request id that
	// covers only the routes that matched is a request id nobody can quote in a bug report — and a
	// token refused only on the routes that matched is a token accepted on the ones that did not.
	return middleware.RequestID(middleware.SecureHeaders(RefuseTokenInQuery(mux)))
}

// newHumaAPI builds the Huma API, and every line of the config is load-bearing.
//
// It is a hand-built huma.Config rather than huma.DefaultConfig, and that is the decision that
// makes it safe to put /index.json behind a framework at all. DefaultConfig would:
//
//   - install a schema-link transformer that adds a `$schema` member to every response body. The
//     nParse+ client's pydantic models ignore unknown keys, so this would not break them today —
//     but it is our document gaining a field we did not write, in the one format we do not own;
//   - negotiate the response format from the Accept header against huma.DefaultFormats, a package
//     -level map that ANY imported package can add to. `import _ ".../formats/cbor"` anywhere in
//     the build — ours or a dependency's — would silently make `Accept: application/cbor` serve
//     the index as CBOR to a client that asked for anything (`*/*` selects the first offered
//     format). Every released client would report the registry as unreachable;
//   - serve /openapi.json, /docs and /schemas/{schema} from paths we did not choose.
//
// So: the format map is a literal with JSON and nothing else, the transformer list stays empty,
// and the three doc paths stay unset. Gate SCHEMA001 asserts the result over real HTTP responses.
func newHumaAPI(mux *http.ServeMux) huma.API {
	cfg := huma.Config{
		OpenAPI: &huma.OpenAPI{
			OpenAPI: "3.1.0",
			Info: &huma.Info{
				Title:       "nParse+ plugin registry",
				Version:     SpecVersion,
				Description: specDescription,
				License: &huma.License{
					Name:       "Apache-2.0",
					Identifier: "Apache-2.0",
				},
			},
			Servers: []*huma.Server{
				{URL: "https://nparseplugins.prokopto.dev", Description: "the live registry"},
			},
			Components: &huma.Components{
				SecuritySchemes: securitySchemes(),
			},
		},

		// JSON, and only JSON. Both keys are needed: the bare "json" key is what Huma resolves
		// `application/problem+json` through when it writes an error document, so dropping it
		// turns every problem response into "unknown content type".
		Formats: map[string]huma.Format{
			contentTypeJSON: huma.DefaultJSONFormat,
			"json":          huma.DefaultJSONFormat,
		},
		DefaultFormat: contentTypeJSON,

		// NoFormatFallback stays false on purpose. With one format registered, the fallback is
		// what turns `Accept: application/cbor` into a JSON response instead of a 406 — a client
		// that asks for something we do not have gets the document rather than an error about its
		// header. Turning it on would make a stray Accept header a hard failure.
		NoFormatFallback: false,

		// Empty: no /openapi.json, no /docs, no /schemas. The document is a checked-in build
		// artifact (openapi/openapi.json), so serving it would be a second copy that can disagree,
		// on paths nothing in ADR-0009 reserved.
		OpenAPIPath: "",
		DocsPath:    "",
		SchemasPath: "",
	}

	return humago.New(mux, cfg)
}

const specDescription = "The plugin registry for nParse+.\n\n" +
	"`GET /index.json` and `GET /plugins/{id}/index.json` serve the schema-v1 index document " +
	"parsed by released nParse+ desktop clients. Their shape is defined upstream, by the pydantic " +
	"models in `nparseplus.core.plugins.registry`, and is not part of this API's versioning: they " +
	"sit outside `/api/v1` at fixed paths and may never move (ADR-0009)."

// securitySchemes are the two credentials this service accepts.
//
// They are declared here, once, and referred to by name from an Access declaration, so a security
// requirement cannot cite a scheme the document does not define. Neither is used by an operation
// yet — identity lands in Phase 2 — but the shape is fixed by canonical §6 and §10 rather than
// being open, and an operation added later refers to these rather than inventing a third spelling.
func securitySchemes() map[string]*huma.SecurityScheme {
	return map[string]*huma.SecurityScheme{
		SchemePAT: {
			Type:   "http",
			Scheme: "bearer",
			// The format is described here rather than in OpenAPI's `bearerFormat`, whose field
			// name and template value read to gosec's G101 as a pasted credential. A false
			// positive is still a finding somebody has to dismiss on every run, and the sentence
			// carries the same information to the only audience that reads either.
			Description: "A personal access token, sent as `Authorization: Bearer nprs_pat_…`, " +
				"where the prefix is followed by an 8-character public identifier and the " +
				"secret. A token in a query string is rejected with 401, with no exception: " +
				"query strings land in access logs, proxy logs and browser history.",
		},
		SchemeSession: {
			Type: "apiKey",
			In:   "cookie",
			// The one spelling of the cookie name, from the package that sets it. Two spellings
			// would be a document describing a cookie the server does not read.
			Name: auth.SessionCookieName,
			Description: "A browser session. It is the only credential that satisfies a " +
				"capability-floor operation — minting tokens, changing owners, setting trust — " +
				"because a token that could perform one would be equivalent to the account.",
		},
	}
}
