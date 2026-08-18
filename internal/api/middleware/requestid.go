// Package middleware holds the plain http.Handler wrappers the server applies to every route.
//
// They are http.Handler wrappers rather than framework middleware because /healthz and the index
// endpoints are raw handlers that no framework sees, and a request id that covers only some of the
// routes is a request id nobody can rely on in a bug report.
package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
)

// HeaderRequestID is the header read from the client and always sent back.
const HeaderRequestID = "X-Request-Id"

type ctxKey int

const (
	ctxKeyRequestID ctxKey = iota
	ctxKeyLogger
)

// maxClientRequestID bounds an echoed client value. Without a cap, a caller chooses how much of
// every one of our log lines they get to write.
const maxClientRequestID = 128

// RequestID attaches a request id to the context and the response, and puts a logger carrying it
// into the context.
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := sanitiseClientID(r.Header.Get(HeaderRequestID))
		if id == "" {
			id = newID()
		}

		// Set before calling next: a handler that panics or hijacks must still have produced a
		// response carrying the id, because that id is the only way to find the request in a log.
		w.Header().Set(HeaderRequestID, id)

		ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
		ctx = context.WithValue(ctx, ctxKeyLogger, slog.Default().With("request_id", id))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// sanitiseClientID accepts a client-supplied id only if it is printable ASCII within the length
// cap. CR, LF and NUL are the ones that matter: an echoed newline is header injection on the way
// out and log injection on the way in, and both are silent.
func sanitiseClientID(v string) string {
	if v == "" || len(v) > maxClientRequestID {
		return ""
	}
	for i := range len(v) {
		if v[i] < 0x20 || v[i] > 0x7e {
			return ""
		}
	}
	return v
}

func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the platform's entropy source is broken. A request id is
		// diagnostic, not security-bearing, so degrade rather than refuse the request.
		return "unavailable"
	}
	return hex.EncodeToString(b[:])
}

// RequestIDOf returns the request id, or "" outside a wrapped request.
func RequestIDOf(ctx context.Context) string {
	id, _ := ctx.Value(ctxKeyRequestID).(string)
	return id
}

// Logger returns the request-scoped logger, falling back to the default so a caller never has to
// nil-check it.
func Logger(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKeyLogger).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}
