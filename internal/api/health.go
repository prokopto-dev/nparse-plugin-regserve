package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// statusBody is the body both probes return when they are happy. Two words rather than an empty
// 204, because a human curling a health endpoint should see an answer, not a blank.
type statusBody struct {
	Status string `json:"status" doc:"\"ok\" for liveness, \"ready\" for readiness"`
}

type statusOutput struct {
	Body statusBody
}

func registerHealth(api huma.API, rc ReadyChecker) {
	// Liveness touches nothing.
	//
	// Deliberately independent of the database: a registry whose disk is unavailable should still
	// answer "the process is up" so an orchestrator does not restart-loop a container that is
	// running fine and would recover. Readiness is where the database is reported.
	register(api, Public(), huma.Operation{
		OperationID: "getLiveness",
		Method:      http.MethodGet,
		Path:        "/healthz",
		Summary:     "Liveness",
		Description: "200 for as long as the process is up. It touches no dependency, so a " +
			"failure here means the process itself is gone.",
		Tags: []string{"health"},
	}, func(context.Context, *struct{}) (*statusOutput, error) {
		return &statusOutput{Body: statusBody{Status: "ok"}}, nil
	})

	// Readiness is registered only when there is something to check. The serve command always
	// supplies one, including on an instance with no catalogue.
	if rc == nil {
		return
	}

	// Readiness explains itself.
	//
	// A bare 503 tells an operator that something is wrong and nothing about what, which turns
	// every incident into a log-reading exercise. The reason is in the problem document's detail —
	// and it is the checker's own words, which is why no checker ever puts a filesystem path in
	// one: this response is unauthenticated.
	register(api, Public(), huma.Operation{
		OperationID: "getReadiness",
		Method:      http.MethodGet,
		Path:        "/readyz",
		Summary:     "Readiness",
		Description: "200 when the service can serve requests that touch the database, and 503 " +
			"naming the reason when it cannot.",
		Tags:   []string{"health"},
		Errors: []int{http.StatusServiceUnavailable},
	}, func(ctx context.Context, _ *struct{}) (*statusOutput, error) {
		if err := rc.Ready(ctx); err != nil {
			return nil, NewProblem(http.StatusServiceUnavailable, CodeServiceUnavailable,
				err.Error())
		}
		return &statusOutput{Body: statusBody{Status: "ready"}}, nil
	})
}
