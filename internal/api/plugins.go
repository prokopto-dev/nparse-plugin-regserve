package api

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
)

// PathPlugins is where a plugin id is claimed. A POST to the collection, because what it creates is
// a plugin — the id inside the body rather than in the path, since the resource does not exist yet
// and a PUT to a path the caller chose would read as "create or replace" on something permanent.
const PathPlugins = "/plugins"

// tagPlugins groups plugin registration in the OpenAPI document.
const tagPlugins = "plugins"

// Claimer is what internal/api needs in order to register a plugin id.
type Claimer interface {
	ClaimID(ctx context.Context, c ownership.Claim, accountID string) error
}

type claimPluginInput struct {
	Body claimPluginBody
}

type claimPluginBody struct {
	PluginID string `json:"id" minLength:"2" maxLength:"40" doc:"The plugin's permanent id, matching the SDK's pattern. It is first-come, permanent, and NEVER RECYCLED — it identifies this plugin in every installed copy on every user's machine, so it cannot be released or reassigned later, even if the plugin is delisted."`

	Name string `json:"name" minLength:"1" maxLength:"120" doc:"What a human sees in the plugin browser."`

	Description string `json:"description,omitempty" maxLength:"500"`
	Author      string `json:"author,omitempty" maxLength:"120"`

	Homepage string `json:"homepage,omitempty" maxLength:"500" doc:"An https URL. It is rendered as a link in a desktop application and published to every client, so other schemes are refused: they are instructions to whatever renders the link rather than homepages."`
}

type claimPluginOutput struct {
	Status int
	Body   claimPluginResult
}

type claimPluginResult struct {
	PluginID string `json:"id"`
	Name     string `json:"name"`

	// Listed is always false here, and saying so is the point: claiming an id gets you a row and
	// an owner grant. It does not get you a listing.
	Listed bool `json:"listed" doc:"Always false for a newly claimed id: a plugin appears in the index only once a release of it has been approved, and the first release of a new id always goes to human review."`
}

// registerPlugins wires plugin registration.
func registerPlugins(api huma.API, claimer Claimer) {
	register(api,
		// CAPABILITY FLOOR: session-only, no scope, no token, ever. A personal access token is a
		// deployment credential for one plugin's pipeline (ADR-0005); one that could register new
		// ids would be a credential that grows its own reach every time it is used.
		Floor("plugin.claim"),
		huma.Operation{
			OperationID: "claimPlugin",
			Method:      http.MethodPost,
			Path:        BasePath + PathPlugins,
			Summary:     "Claim a plugin id",
			Description: "Registers a plugin id to your account and makes you its owner.\n\n" +
				"**Ids are first-come, permanent and never recycled.** An id identifies this " +
				"plugin in every installed copy on every user's machine, so it cannot be " +
				"released or reassigned later — delisting a plugin clears its listing and keeps " +
				"the claim. Choose carefully.\n\n" +
				"Claiming does not publish anything. The plugin appears in the index once a " +
				"release of it has been approved, and **the first release of a new id always " +
				"goes to human review**, whatever your trust level.\n\n" +
				"This is session-only: no personal access token can claim an id, however scoped.",
			Tags: []string{tagPlugins},
			Errors: []int{
				http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
				http.StatusConflict, http.StatusInternalServerError,
			},
		},
		func(ctx context.Context, in *claimPluginInput) (*claimPluginOutput, error) {
			claimant, ok := PrincipalFrom(ctx)
			if !ok {
				slog.ErrorContext(ctx, "claim reached a handler with no principal")
				return nil, NewProblem(http.StatusInternalServerError, CodeInternalError, "")
			}

			id, err := core.ParsePluginID(in.Body.PluginID)
			if err != nil {
				return nil, NewProblem(http.StatusBadRequest, CodeInvalidRequest, err.Error())
			}

			claim := ownership.Claim{
				PluginID:    id,
				Name:        in.Body.Name,
				Description: in.Body.Description,
				Author:      in.Body.Author,
				Homepage:    in.Body.Homepage,
			}
			if err := claimer.ClaimID(ctx, claim, claimant.AccountID); err != nil {
				return nil, claimProblem(ctx, in.Body.PluginID, err)
			}

			return &claimPluginOutput{
				Status: http.StatusCreated,
				Body: claimPluginResult{
					PluginID: id.String(),
					Name:     claim.Name,
					Listed:   false,
				},
			}, nil
		})
}

// claimProblem maps a claim failure onto a problem document.
func claimProblem(ctx context.Context, pluginID string, err error) error {
	switch {
	case errors.Is(err, ownership.ErrAlreadyClaimed):
		// 409 and not 404: the id existing is not a secret — the index publishes every listed one
		// — and telling somebody an id is taken is what lets them pick another. What this
		// deliberately does NOT say is WHO holds it, which would turn this endpoint into a way to
		// map ids to people.
		return NewProblem(http.StatusConflict, CodeConflict,
			"that plugin id is already claimed; ids are first-come and permanent, so pick another")

	case errors.Is(err, ownership.ErrBadListing), errors.Is(err, core.ErrInvalidPluginID):
		return NewProblem(http.StatusBadRequest, CodeInvalidRequest, err.Error())
	}

	slog.ErrorContext(ctx, "claim a plugin id", "plugin_id", pluginID, "error", err)
	return NewProblem(http.StatusInternalServerError, CodeInternalError, "")
}
