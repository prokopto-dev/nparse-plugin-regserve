package api

import (
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
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
//
// It is also the error type Huma uses. Handlers return it, `huma.NewError` builds it, and the
// OpenAPI document derives the error schema from it (`defineErrors` reflects over whatever
// `huma.NewError` returns), so the documented error model and the one on the wire cannot be two
// different things.
type Problem struct {
	Type   string `json:"type" doc:"A URI reference to the documentation for this error code"`
	Title  string `json:"title" doc:"A short, human-readable summary; it does not vary with the occurrence"`
	Status int    `json:"status" doc:"The HTTP status code, repeated for client convenience"`
	Code   Code   `json:"code" doc:"The stable machine-readable code to switch on; the enum is closed"`
	Detail string `json:"detail,omitempty" doc:"An explanation specific to this occurrence"`
}

// problemTypeBase is where a code's documentation lives. Keeping it a real, resolvable URL is the
// point of RFC 9457's `type`; a urn: that resolves to nothing helps nobody at 2am.
const problemTypeBase = "https://github.com/prokopto-dev/nparse-plugin-regserve/blob/main/docs/api/errors.md#"

// NewProblem builds a problem document. Title is derived from the code so the same code always
// renders the same title, and only `detail` varies with the situation.
func NewProblem(status int, code Code, detail string) *Problem {
	return &Problem{
		Type:   problemTypeBase + string(code),
		Title:  http.StatusText(status),
		Status: status,
		Code:   code,
		Detail: detail,
	}
}

// Error makes Problem an error, so a handler returns one instead of writing a response.
func (p *Problem) Error() string {
	if p.Detail == "" {
		return string(p.Code)
	}
	return string(p.Code) + ": " + p.Detail
}

// GetStatus makes Problem a huma.StatusError: Huma reads the status from the error a handler
// returns rather than the handler setting it on a ResponseWriter it never sees.
func (p *Problem) GetStatus() int { return p.Status }

// ContentType makes Problem a huma.ContentTypeFilter, which is how `application/json` becomes
// `application/problem+json` on an error response — for the document Huma writes AND for the one
// the OpenAPI document advertises.
func (p *Problem) ContentType(ct string) string {
	if ct == contentTypeJSON {
		return problemContentType
	}
	return ct
}

const problemContentType = "application/problem+json"

// Never 200-with-an-error-body: a status that says success and a payload that says failure is how
// bot authors end up parsing prose to find out whether their publish worked. Huma takes the status
// from GetStatus above, so the two cannot disagree.
var _ huma.StatusError = (*Problem)(nil)

// init replaces Huma's error constructor with ours.
//
// It has to be `init` rather than a line in the server constructor. `huma.NewError` is a package
// variable Huma reads while serving, so assigning it from a constructor would be a write racing
// every in-flight request in any test that builds two servers — the race detector would be right.
// An init runs once, before anything can be serving.
//
// Without this, every error Huma raises on its own — a body it could not parse, a parameter that
// failed validation, a panic recovered in a handler — would be a huma.ErrorModel: no `code`
// member, a different shape from the ones our handlers return, and outside the closed enum that
// docs/api/errors.md documents and DOC001 gates.
func init() {
	huma.NewError = func(status int, msg string, errs ...error) huma.StatusError {
		return NewProblem(status, codeForStatus(status), detailFor(status, msg, errs))
	}
}

// codeForStatus maps a status Huma chose onto the closed enum.
//
// The enum is closed, so a status with no code of its own has to land on one that exists rather
// than growing the enum by accident. Every 4xx Huma raises before a handler runs — 406 on a
// content type it cannot produce, 413 on an oversized body, 415, 422 on a failed validation — is
// the same thing to a client: the request was understood and is wrong, fix it and resend.
func codeForStatus(status int) Code {
	switch status {
	case http.StatusNotFound:
		return CodeNotFound
	case http.StatusUnauthorized:
		return CodeUnauthorized
	case http.StatusForbidden:
		return CodeForbidden
	case http.StatusConflict:
		return CodeConflict
	case http.StatusMethodNotAllowed:
		return CodeMethodNotAllowed
	case http.StatusServiceUnavailable:
		return CodeServiceUnavailable
	}
	if status >= http.StatusInternalServerError {
		return CodeInternalError
	}
	return CodeInvalidRequest
}

// internalErrorDetail is what a 500 says, always. See detailFor.
const internalErrorDetail = "the request could not be completed; quote the X-Request-Id header in a report"

// detailFor composes the human-readable half, and refuses to do so for a 500.
//
// Huma hands the underlying error to the error constructor when a handler returns something that
// is not a StatusError: `NewErrorWithContext(ctx, 500, "unexpected error occurred", err)`. That
// `err` is ours — a driver error, a file path, a query — and echoing it to an unauthenticated
// caller is how an index endpoint becomes an information-disclosure bug. A 500 carries a fixed
// sentence and the request id; the cause goes to the log, which is where the person who can act on
// it is looking.
func detailFor(status int, msg string, errs []error) string {
	if status >= http.StatusInternalServerError {
		return internalErrorDetail
	}

	parts := make([]string, 0, len(errs)+1)
	if msg != "" {
		parts = append(parts, msg)
	}
	for _, err := range errs {
		if err != nil {
			parts = append(parts, err.Error())
		}
	}
	return strings.Join(parts, "; ")
}
