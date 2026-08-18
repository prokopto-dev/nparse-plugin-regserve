package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// handleHealthz is liveness. It touches nothing.
//
// Deliberately independent of the database: a registry whose disk is unavailable should still
// answer "the process is up" so an orchestrator does not restart-loop a container that is running
// fine and would recover. Readiness is where the database is reported.
func handleHealthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz is readiness, and it explains itself.
//
// A bare 503 tells an operator that something is wrong and nothing about what, which turns every
// incident into a log-reading exercise. The reason is in the body.
func handleReadyz(w http.ResponseWriter, r *http.Request, rc ReadyChecker) {
	if err := rc.Ready(r.Context()); err != nil {
		WriteProblem(w, r, NewProblem(
			http.StatusServiceUnavailable,
			CodeServiceUnavailable,
			err.Error(),
		))
		return
	}
	writeJSON(w, r, http.StatusOK, map[string]string{"status": "ready"})
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(body); err != nil {
		slog.ErrorContext(r.Context(), "write json response", "path", r.URL.Path, "error", err)
	}
}
