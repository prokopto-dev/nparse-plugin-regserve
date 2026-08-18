package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// Code is a stable, machine-readable error identifier from a CLOSED enum.
//
// Clients switch on these, so a code is public API: adding one is a spec change and needs a page in
// docs/api/errors.md (gate DOC001). Renaming or removing one breaks every consumer that handled it.
type Code string

const (
	CodeNotFound               Code = "not_found"
	CodeInvalidRequest         Code = "invalid_request"
	CodeUnauthorized           Code = "unauthorized"
	CodeForbidden              Code = "forbidden"
	CodeGitHubIdentityRequired Code = "github_identity_required"
	CodeConflict               Code = "conflict"
	CodeMethodNotAllowed       Code = "method_not_allowed"
	CodeInternalError          Code = "internal_error"
	CodeServiceUnavailable     Code = "service_unavailable"
)

// Problem is an RFC 9457 application/problem+json document.
//
// The `code` member is the extension that matters: `status` is too coarse to act on and `detail` is
// prose that will be reworded. A client that needs to distinguish "you are not an owner" from "you
// have no GitHub identity linked" reads `code`.
type Problem struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Status int    `json:"status"`
	Code   Code   `json:"code"`
	Detail string `json:"detail,omitempty"`
}

const problemContentType = "application/problem+json"

// problemTypeBase is where a code's documentation lives. Keeping it a real, resolvable URL is the
// point of RFC 9457's `type`; a urn: that resolves to nothing helps nobody at 2am.
const problemTypeBase = "https://github.com/prokopto-dev/nparse-plugin-regserve/blob/main/docs/api/errors.md#"

// NewProblem builds a problem document. Title is derived from the code so the same code always
// renders the same title, and only `detail` varies with the situation.
func NewProblem(status int, code Code, detail string) Problem {
	return Problem{
		Type:   problemTypeBase + string(code),
		Title:  http.StatusText(status),
		Status: status,
		Code:   code,
		Detail: detail,
	}
}

// WriteProblem renders p. It is the only way this package emits an error body.
//
// Never 200-with-an-error-body: a status that says success and a payload that says failure is how
// bot authors end up parsing prose to find out whether their publish worked.
func WriteProblem(w http.ResponseWriter, r *http.Request, p Problem) {
	w.Header().Set("Content-Type", problemContentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(p.Status)

	if err := json.NewEncoder(w).Encode(p); err != nil {
		// The status line is already sent, so there is nothing to correct — but a silent failure
		// here would make an error look like an empty success to the caller.
		slog.ErrorContext(r.Context(), "write problem document", "code", p.Code, "error", err)
	}
}
