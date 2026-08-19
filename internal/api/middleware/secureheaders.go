package middleware

import "net/http"

// SecureHeaders sets the response headers that apply to every route.
//
// It is one wrapper rather than a line in each handler because it has to cover the responses no
// handler produces: the 404 and 405 the mux answers by itself, and the problem documents the
// framework writes when it rejects a request before a handler runs.
//
// X-Content-Type-Options is the one that matters here. This service serves a JSON document to a
// desktop client and, when something goes wrong, an error document to a browser. Without nosniff a
// browser is free to decide a response is HTML based on its bytes, and "the registry served
// attacker-supplied content as HTML" is a bug class that costs nothing to close.
func SecureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Set before the handler runs: a handler that writes its status line first would
		// otherwise have already sent the headers by the time we got to add one.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
