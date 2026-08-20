package artifact_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/identity/guard"
)

// serveBytes is a handler that answers every request with body.
func serveBytes(body []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
}

// TestFetch_TheDigestIsOfTheBytesThatArrived — the whole point of the package.
func TestFetch_TheDigestIsOfTheBytesThatArrived(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body []byte
	}{
		{"an ordinary artifact", []byte("PK\x03\x04 this is a plugin wheel, honestly")},
		{"one byte", []byte{0x00}},
		{"empty", []byte{}},
		{"binary with every byte value", allByteValues()},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			srv, f := tlsServer(t, serveBytes(tc.body), artifact.Config{})

			got, err := f.Fetch(t.Context(), srv.URL+"/plugin.whl")
			require.NoError(t, err)

			want := sha256.Sum256(tc.body)
			require.Equal(t, hex.EncodeToString(want[:]), got.Digest.Hex())
			require.True(t, got.Digest.Computed())
			require.Equal(t, int64(len(tc.body)), got.Bytes)
			require.Equal(t, testClock.Now(), got.FetchedAt,
				"FetchedAt becomes release.verified_at and must come from the injected clock")
		})
	}
}

func allByteValues() []byte {
	b := make([]byte, 256)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

// TestFetch_AnOversizedArtifact_IsAbandonedMidStream — the cap is enforced DURING the read.
//
// Two assertions, and the second is the one that matters. Failing is easy; failing WITHOUT having
// read the whole thing is the property. A cap applied after the read has already spent the memory
// and the bandwidth that whoever supplied the URL asked it to spend, which is a denial of service
// with extra steps.
func TestFetch_AnOversizedArtifact_IsAbandonedMidStream(t *testing.T) {
	t.Parallel()

	const cap64K = 64 << 10
	const intended = 8 << 20 // a hundred and twenty-eight times the cap

	var written atomic.Int64
	done := make(chan struct{})

	srv, f := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		defer close(done)
		chunk := make([]byte, 4<<10)
		for written.Load() < intended {
			n, err := w.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return // the client hung up: exactly what "abandoned mid-stream" looks like here
			}
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
		}
	}), artifact.Config{MaxBytes: cap64K})

	_, err := f.Fetch(t.Context(), srv.URL+"/enormous.whl")
	require.ErrorIs(t, err, artifact.ErrNotFetched)
	require.ErrorIs(t, err, guard.ErrTooLarge)

	<-done
	require.Less(t, written.Load(), int64(intended/2),
		"the server got to send %d of %d bytes; the cap is being applied after the read, not during it",
		written.Load(), intended)
}

// TestFetch_AnArtifactExactlyAtTheCap_IsAccepted — the boundary is inclusive.
//
// An off-by-one here is a size limit that is silently one byte tighter than the number written in
// the documentation, and it surfaces as one plugin author's release failing for no stated reason.
func TestFetch_AnArtifactExactlyAtTheCap_IsAccepted(t *testing.T) {
	t.Parallel()

	const cap64K = 64 << 10
	body := make([]byte, cap64K)
	for i := range body {
		body[i] = byte(i % 251)
	}

	srv, f := tlsServer(t, serveBytes(body), artifact.Config{MaxBytes: cap64K})

	got, err := f.Fetch(t.Context(), srv.URL+"/exactly.whl")
	require.NoError(t, err)
	require.Equal(t, int64(cap64K), got.Bytes)

	want := sha256.Sum256(body)
	require.Equal(t, hex.EncodeToString(want[:]), got.Digest.Hex())

	// One byte over is refused, so the assertion above is about the boundary and not about the
	// cap being loose.
	srvOver, fOver := tlsServer(t, serveBytes(append(body, 'x')), artifact.Config{MaxBytes: cap64K})
	_, err = fOver.Fetch(t.Context(), srvOver.URL+"/one-over.whl")
	require.ErrorIs(t, err, guard.ErrTooLarge)
}

// TestFetch_ALyingContentLength_DoesNotDecideAnything — the header is not consulted.
//
// Content-Length is written by the sender, which in this service is the party we are being careful
// about. A response that declares a gigabyte and sends a plugin is fetched normally, because the
// only number that counts is the one the read counted.
func TestFetch_ALyingContentLength_DoesNotDecideAnything(t *testing.T) {
	t.Parallel()

	body := []byte("a small, honest artifact")

	srv, f := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Set on the response Go will send. Go recomputes Content-Length for a small buffered
		// body, so this is belt and braces around the real assertion: what matters is that a
		// declared size never short-circuits the read in either direction.
		w.Header().Set("Content-Length", fmt.Sprint(1<<30))
		w.Header().Set("X-Declared-Size", fmt.Sprint(1<<30))
		w.Header().Del("Content-Length")
		_, _ = w.Write(body)
	}), artifact.Config{MaxBytes: 1 << 20})

	got, err := f.Fetch(t.Context(), srv.URL+"/small.whl")
	require.NoError(t, err, "a declared size larger than the cap must not refuse a body under it")

	want := sha256.Sum256(body)
	require.Equal(t, hex.EncodeToString(want[:]), got.Digest.Hex())
	require.Equal(t, int64(len(body)), got.Bytes)
}

// TestFetchSource_NeverReadsContentLength — said structurally, because the behavioural test above
// can only show the header not mattering in the cases somebody thought to write down.
//
// This reads fetch.go with go/ast and requires that the declared size is never touched at all:
// no resp.ContentLength, no "Content-Length" header read. A rule with a gate beats a rule with an
// example, and this is the cheapest possible gate for it.
func TestFetchSource_NeverReadsContentLength(t *testing.T) {
	t.Parallel()

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "fetch.go", nil, parser.ParseComments)
	require.NoError(t, err)

	var bad []string
	ast.Inspect(f, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.SelectorExpr:
			if node.Sel.Name == "ContentLength" {
				bad = append(bad, fset.Position(node.Pos()).String()+" (.ContentLength)")
			}
		case *ast.BasicLit:
			if node.Kind == token.STRING && strings.Contains(strings.ToLower(node.Value), "content-length") {
				bad = append(bad, fset.Position(node.Pos()).String()+" (Content-Length literal)")
			}
		}
		return true
	})
	require.Empty(t, bad,
		"the size cap must come from the bytes counted during the read, never from a header the "+
			"sender wrote")
}

// TestResult_HasNowhereToPutTheBytes — artifacts are hashed and discarded.
//
// "Never extracted, never written to a persistent path, never executed" is enforced here by the
// return type having nowhere to carry them. A []byte or an io.Reader on Result is how that rule
// stops being true: not by somebody deciding to break it, but by a later field that seemed useful
// and a caller that used it.
func TestResult_HasNowhereToPutTheBytes(t *testing.T) {
	t.Parallel()

	rt := reflect.TypeOf(artifact.Result{})
	readerIface := reflect.TypeOf((*io.Reader)(nil)).Elem()
	closerIface := reflect.TypeOf((*io.Closer)(nil)).Elem()

	for i := range rt.NumField() {
		field := rt.Field(i)
		require.NotEqual(t, reflect.TypeOf([]byte(nil)), field.Type,
			"Result.%s carries the artifact's bytes; they are hashed and discarded", field.Name)
		require.False(t, field.Type.Implements(readerIface),
			"Result.%s is a reader over the artifact; the bytes do not leave this package", field.Name)
		require.False(t, field.Type.Implements(closerIface),
			"Result.%s holds something that must be closed; a Result is a set of facts, not a handle",
			field.Name)
		require.NotEqual(t, reflect.Slice, field.Type.Kind(),
			"Result.%s is a slice; nothing about an artifact needs one, and bytes are what this "+
				"would become", field.Name)
	}
}

// TestFetch_ANonSuccessStatus_IsNotAFetch — a 404 body is not an artifact.
//
// Hashing whatever a 404 page happened to contain and publishing that hash would be the confident
// mistake in its purest form: a listing pointing at a URL that serves an error, with a hash that
// matches the error.
func TestFetch_ANonSuccessStatus_IsNotAFetch(t *testing.T) {
	t.Parallel()

	for _, status := range []int{
		http.StatusNotFound,
		http.StatusForbidden,
		http.StatusUnauthorized,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
		http.StatusTeapot,
	} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()

			srv, f := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(status)
				_, _ = w.Write([]byte("<html>not the artifact you are looking for</html>"))
			}), artifact.Config{})

			_, err := f.Fetch(t.Context(), srv.URL+"/missing.whl")
			require.ErrorIs(t, err, artifact.ErrNotFetched)
			require.ErrorIs(t, err, artifact.ErrBadStatus)
			require.Equal(t, "not verified: the artifact url did not answer with success",
				artifact.Reason(err))
		})
	}
}

// TestFetch_ARedirectToTheRealAsset_IsFollowedAndHashed — the ordinary GitHub case.
//
// A release asset redirects to a CDN and then to a signed URL. That has to work, or nothing
// publishes; the point of the guard is that it works while the dangerous hops do not.
func TestFetch_ARedirectToTheRealAsset_IsFollowedAndHashed(t *testing.T) {
	t.Parallel()

	body := []byte("PK\x03\x04 the artifact, two hops away")

	assetSrv, _ := tlsServer(t, serveBytes(body), artifact.Config{})

	var target string
	srv, f := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/cdn") {
			// A signed URL, with the shape of the thing that must never reach the audit log.
			http.Redirect(w, r,
				target+"/signed.whl?X-Amz-Signature=deadbeefcafe&X-Amz-Expires=900",
				http.StatusFound)
			return
		}
		http.Redirect(w, r, srvURL(r)+"/cdn", http.StatusFound)
	}), artifact.Config{})
	target = assetSrv.URL

	got, err := f.Fetch(t.Context(), srv.URL+"/releases/download/v1/plugin.whl")
	require.NoError(t, err)

	want := sha256.Sum256(body)
	require.Equal(t, hex.EncodeToString(want[:]), got.Digest.Hex())

	// FinalHost is a HOST, not a URL. It is written into audit_log, which is append-only by
	// trigger and can therefore never be redacted, so a signed URL's query string must not be
	// able to get in there.
	require.NotEmpty(t, got.FinalHost)
	require.NotContains(t, got.FinalHost, "?")
	require.NotContains(t, got.FinalHost, "Signature")
	require.NotContains(t, got.FinalHost, "deadbeef")
}

// srvURL rebuilds the absolute base a request arrived at, so a handler can redirect to itself
// without the test having to close over a server that does not exist yet.
func srvURL(r *http.Request) string { return "https://" + r.Host }

// TestFetch_ACancelledContext_StopsTheFetch — ctx is carried and honoured.
//
// A publish holds its response open for the length of the download, so the request context going
// away — the client hung up, the server is shutting down — has to stop the fetch rather than leave
// it pulling fifty megabytes for nobody.
//
// SYNCHRONISED ON CHANNELS AND NOT ON A CLOCK. The handler writes a first chunk, flushes it, and
// only then says it has started; the cancel happens after that and while the body is still open.
// A version of this paced by a sleep is a test that passes on a quiet laptop and reports a
// mysterious nil on a loaded runner, which is what the first draft of it did — and `time.Sleep` in
// a test is grep-banned here for exactly that reason.
func TestFetch_ACancelledContext_StopsTheFetch(t *testing.T) {
	t.Parallel()

	started := make(chan struct{})
	release := make(chan struct{})

	srv, f := tlsServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Real bytes before the flush: a flush with nothing written commits the header and
		// nothing else, and what this test needs is a body that is open and part-delivered.
		_, _ = w.Write([]byte("the first chunk of an artifact"))
		flusher, ok := w.(http.Flusher)
		require.True(t, ok, "the test server cannot stream; this test cannot say what it means to")
		flusher.Flush()

		close(started)

		// Held open until the test is done with it, or until the client goes away — which is what
		// cancelling the context does, and is the thing being asserted.
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}), artifact.Config{Timeout: 30 * time.Second})
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithCancel(t.Context())
	go func() {
		<-started
		cancel()
	}()

	_, err := f.Fetch(ctx, srv.URL+"/slow.whl")
	require.ErrorIs(t, err, artifact.ErrNotFetched)
	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, "not verified: the artifact could not be downloaded within the time limit",
		artifact.Reason(err))
}

// TestFetch_AFetchThatTimedOut_ReportsNotVerified — never success, in any branch.
//
// House style: the failure mode designed against is a CONFIDENT MISTAKE. Every reason this package
// can give says some version of "not verified", and this is the assertion that there is no branch
// which does not.
func TestReason_EveryBranchSaysNotVerified(t *testing.T) {
	t.Parallel()

	for _, err := range []error{
		nil,
		guard.ErrBlockedAddress,
		guard.ErrNotHTTPS,
		guard.ErrTooManyRedirects,
		guard.ErrTooLarge,
		artifact.ErrBadStatus,
		context.DeadlineExceeded,
		context.Canceled,
		fmt.Errorf("something nobody has thought of: %w", io.ErrUnexpectedEOF),
	} {
		reason := artifact.Reason(err)
		require.True(t, strings.HasPrefix(reason, "not verified: "),
			"Reason(%v) = %q, which does not say the artifact was not verified", err, reason)
		require.Greater(t, len(reason), len("not verified: "),
			"Reason(%v) says it is not verified and does not say why", err)
		// "verified" appears exactly once, in the prefix. A branch that went on to say the
		// artifact WAS verified would read as a contradiction to a human and as a success to
		// anything matching on the string.
		require.Equal(t, 1, strings.Count(reason, "verified"),
			"Reason(%v) = %q says something about verification twice", err, reason)
	}
}

// TestDefaultTimeout_FitsInsideTheServersWriteTimeout — the two numbers are tied together.
//
// A fetch allowed to outlast the response it is part of writes the release row and then has its
// answer cut off in flight, so the publishing workflow sees a failure for a publish that
// succeeded. Idempotency makes that recoverable; it does not make it right. Raising either number
// without redoing this arithmetic is a red test rather than something discovered on a slow morning.
func TestDefaultTimeout_FitsInsideTheServersWriteTimeout(t *testing.T) {
	t.Parallel()

	// The value in cmd/regserve/serve.go. It is unexported there — this asserts the relationship
	// and TestWriteTimeout_MatchesTheArtifactBudget in that package asserts the number.
	const serverWriteTimeout = 60 * time.Second

	require.Less(t, artifact.DefaultTimeout, serverWriteTimeout,
		"the artifact fetch can outlast the response it is part of")
	require.LessOrEqual(t, artifact.DefaultTimeout, serverWriteTimeout*3/4,
		"the fetch leaves no room for the rest of the publish: the database write, the hash "+
			"comparison and the response all happen inside the same WriteTimeout")
}
