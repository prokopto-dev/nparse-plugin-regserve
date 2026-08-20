package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/registry"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
)

// Spec returns the OpenAPI document for every operation this service exposes.
//
// It is built by running the same registration code the server runs, so the document cannot
// describe a route that is not served or miss one that is. That is what "coverage derived from the
// route registry" means in AGENTS.md law 6: the permission gate walks this document, so a new
// operation appears in it the moment it is registered, declaration or not.
func Spec() *huma.OpenAPI {
	mux := http.NewServeMux()
	api := newHumaAPI(mux)

	// The stubs below stand in for the real dependencies. A document that described a different
	// set of operations depending on whether the instance generating it happened to have a
	// database attached would be useless as a published contract — the API is what this build
	// exposes, not what one deployment is currently able to answer.
	registerHealth(api, unavailable{})
	registerIndex(api, unavailable{})
	registerAuth(api, unavailable{}, unavailable{}, identity.NewRegistry())
	registerReleases(api, unavailablePublisher{})
	registerWeb(api, WebDeps{
		Sessions:  unavailable{},
		Tokens:    unavailableTokens{},
		Ownership: unavailableOwnership{},
		Providers: identity.NewRegistry(),
	})

	return api.OpenAPI()
}

// SpecJSON renders Spec as the bytes of openapi/openapi.json.
//
// Indented and newline-terminated because it is a checked-in file a human reads in a diff, and
// deterministic because gate GEN001 regenerates it and fails on any difference: Huma marshals the
// document through maps, which encoding/json emits in sorted key order.
func SpecJSON() ([]byte, error) {
	raw, err := json.MarshalIndent(Spec(), "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal the openapi document: %w", err)
	}
	return append(raw, '\n'), nil
}

// errSpecOnly is returned by the stubs. Reaching it means a spec-only API was asked to serve
// traffic, which is a wiring bug rather than a runtime condition.
var errSpecOnly = errors.New("this api instance exists to generate the openapi document and serves nothing")

type unavailable struct{}

func (unavailable) Listings(context.Context) ([]registry.Plugin, error) {
	return nil, errSpecOnly
}

func (unavailable) Listing(context.Context, core.PluginID) (registry.Plugin, error) {
	return registry.Plugin{}, errSpecOnly
}

func (unavailable) Ready(context.Context) error { return errSpecOnly }

func (unavailable) Begin(context.Context, identity.Kind, string) (auth.Begun, error) {
	return auth.Begun{}, errSpecOnly
}

func (unavailable) Complete(context.Context, identity.Kind, string, string, string) (
	auth.Completed, error,
) {
	return auth.Completed{}, errSpecOnly
}

func (unavailable) Create(context.Context, string) (auth.NewSession, error) {
	return auth.NewSession{}, errSpecOnly
}

func (unavailable) Revoke(context.Context, auth.Principal) error { return errSpecOnly }

func (unavailable) CSRFToken(auth.Principal) string { return "" }

func (unavailable) CheckCSRF(auth.Principal, string) bool { return false }

// unavailableTokens and unavailableOwnership are separate types rather than more methods on
// `unavailable` because a session and a token are both revoked, with different arguments. One
// stub cannot have two `Revoke`s, and collapsing the two domain methods onto one signature to
// make a test double simpler would be the tail wagging the dog.
type unavailableTokens struct{}

func (unavailableTokens) Mint(context.Context, auth.MintRequest) (auth.NewToken, error) {
	return auth.NewToken{}, errSpecOnly
}

func (unavailableTokens) List(context.Context, string) ([]auth.Listing, error) {
	return nil, errSpecOnly
}

func (unavailableTokens) Revoke(context.Context, string, string) error { return errSpecOnly }

// unavailablePublisher stands in for the publish path when the document is generated. The
// document describes what this BUILD exposes, not what one deployment happens to have wired.
type unavailablePublisher struct{}

func (unavailablePublisher) Publish(context.Context, release.Request) (release.Outcome, error) {
	return release.Outcome{}, errSpecOnly
}

type unavailableOwnership struct{}

func (unavailableOwnership) Mine(context.Context, string) ([]ownership.Plugin, error) {
	return nil, errSpecOnly
}

func (unavailableOwnership) Owners(context.Context, string, string) ([]ownership.Owner, error) {
	return nil, errSpecOnly
}

func (unavailableOwnership) RoleOf(context.Context, string, string) (ownership.Role, bool, error) {
	return "", false, errSpecOnly
}

func (unavailableOwnership) Add(context.Context, string, string, string, ownership.Role) error {
	return errSpecOnly
}

func (unavailableOwnership) Remove(context.Context, string, string, string) error {
	return errSpecOnly
}
