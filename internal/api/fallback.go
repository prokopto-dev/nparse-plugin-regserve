package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"
)

// routeMux is the ServeMux every route is registered on, plus the two answers a mux has to give
// when no route matched.
//
// IT EXISTS BECAUSE THE ALTERNATIVE SHIPPED. `GET /` is a Go ServeMux CATCH-ALL — a pattern ending
// in a slash matches the whole subtree below it — so from the moment the front page was registered
// at `/`, every unrouted GET was answered `200` with the home page. Measured on the live
// deployment: `/definitely-not-a-page-xyz`, `/openapi.json`, `/docs`, `/tokens` and `/publish` all
// returned the directory. That is the confident mistake AGENTS.md is written against, and it is
// worse than a wrong page: it makes a route that is missing indistinguishable from one that is
// there, so nobody investigating a deployment can tell what it actually serves.
//
// Two changes fix it, and both belong on the mux rather than in a handler, because the mux decides
// which handler runs — and answers by itself when none does, before Huma is involved at all:
//
//   - The home page is registered as `/{$}`, which matches the root and nothing below it, so the
//     GET routing tree no longer contains a catch-all.
//   - A METHOD-LESS pattern is registered for every path a route claims, answering 405, and a
//     single `/` catch-all answers 404. Go prefers the pattern that names the request's method and
//     falls back to the method-less one, so these are reached only when no real route was.
//
// Both answers are problem documents. net/http's built-in 404 and 405 are `text/plain`, which
// docs/api/errors.md says no error response is, and which left `method_not_allowed` unreachable by
// any request even though the closed enum documents it — issue #18, which this closes.
type routeMux struct {
	*http.ServeMux

	// methods records which methods were registered against each PATH pattern, because that is
	// what a 405's Allow header has to name and http.ServeMux does not expose its routing table.
	// The map is written only from HandleFunc, which runs while New is building the handler and
	// never once it is serving.
	methods map[string][]string
}

// newRouteMux builds an empty mux. Routes go on with HandleFunc, which is the method Huma's
// humago adapter calls; installFallbacks closes it off once they are all on.
func newRouteMux() *routeMux {
	return &routeMux{ServeMux: http.NewServeMux(), methods: map[string][]string{}}
}

// HandleFunc registers one operation, recording its method and pinning `/` to the root.
//
// It is the whole of humago.Mux that Huma writes through; ServeHTTP comes from the embedded mux.
func (m *routeMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	method, path, found := strings.Cut(pattern, " ")
	if !found {
		// Every pattern the humago adapter builds is "METHOD /path". One that is not would land on
		// the mux as a path with no method — matching every method, and every path below it if it
		// ended in a slash — which is precisely the shape this type exists to prevent. Panicking
		// here is main wiring: New builds the handler before the server listens.
		panic("route pattern without a method: " + pattern)
	}
	m.methods[path] = append(m.methods[path], method)
	m.ServeMux.HandleFunc(method+" "+exactly(path), handler)
}

// installFallbacks registers what answers a request that matched no route.
//
// It runs ONCE, after every route, because the Allow header of a 405 is a fact about the whole set
// of registrations for a path rather than about any one of them.
func (m *routeMux) installFallbacks() {
	for path, methods := range m.methods {
		m.Handle(exactly(path), methodNotAllowed(allowHeader(methods)))
	}

	// The one pattern that is deliberately a catch-all, and the only one left. Everything above is
	// more specific than it, so it is reached exactly when nothing else matched.
	m.Handle("/", notFound())
}

// exactly renders a path so that it matches ITSELF and nothing below it.
//
// Only `/` needs it today: in Go's pattern language a trailing slash means "this subtree", so `/`
// alone is every path there is, and `/{$}` is the spelling for "the root, exactly". It is written
// as a rule about trailing slashes rather than as a special case for `/`, because a later route
// registered at `/something/` would be the same defect with a smaller blast radius.
//
// The OpenAPI document keeps `/`, which is the path a client requests. This is only what the mux
// is told.
func exactly(path string) string {
	if strings.HasSuffix(path, "/") {
		return path + "{$}"
	}
	return path
}

// notFound is the answer for a path this service does not route.
func notFound() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeProblemTo(w, r, NewProblem(http.StatusNotFound, CodeNotFound,
			"this registry has nothing at that path"))
	})
}

// methodNotAllowed is the answer for a path that IS routed, by some other method.
func methodNotAllowed(allow string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow is required on a 405 by RFC 9110 and is the only part of this response a client
		// can act on. The detail does not repeat it: the header is machine-readable and the method
		// came from the request, and a document that echoes what was sent is a document that
		// renders what was sent.
		w.Header().Set("Allow", allow)
		writeProblemTo(w, r, NewProblem(http.StatusMethodNotAllowed, CodeMethodNotAllowed,
			"that path does not answer this method; the Allow header lists the ones it does"))
	})
}

// allowHeader renders the Allow value for a path, saying what net/http would have said.
//
// HEAD is added wherever GET is registered because Go's ServeMux serves a HEAD request from a GET
// pattern whether or not anybody declared HEAD — so a path that answers GET answers HEAD, and an
// Allow header that omitted it would be describing a rule the router does not follow. Sorted, so
// the value does not vary with the order routes happen to be registered in.
func allowHeader(methods []string) string {
	allowed := make([]string, 0, len(methods)+1)
	for _, method := range methods {
		if !slices.Contains(allowed, method) {
			allowed = append(allowed, method)
		}
		if method == http.MethodGet && !slices.Contains(allowed, http.MethodHead) {
			allowed = append(allowed, http.MethodHead)
		}
	}
	slices.Sort(allowed)
	return strings.Join(allowed, ", ")
}

// writeProblemTo writes a problem document from a plain http.Handler.
//
// The callers are the refusals that happen OUTSIDE Huma — a token in a query string, and the two
// mux fallbacks — where there is no operation and therefore no huma.Context to write through. It
// is the same document type a handler returns, so a client parses one shape whatever refused it.
func writeProblemTo(w http.ResponseWriter, r *http.Request, problem *Problem) {
	body, err := json.Marshal(problem)
	if err != nil {
		// Unreachable: Problem is four strings and an int. Refusing loudly beats serving the
		// request we just decided to refuse.
		slog.ErrorContext(r.Context(), "render a problem document",
			"code", string(problem.Code), "error", err)
		http.Error(w, http.StatusText(problem.Status), problem.Status)
		return
	}

	w.Header().Set("Content-Type", problemContentType)
	w.WriteHeader(problem.Status)
	if _, err := w.Write(body); err != nil {
		slog.ErrorContext(r.Context(), "write a problem document",
			"code", string(problem.Code), "error", err)
	}
}
