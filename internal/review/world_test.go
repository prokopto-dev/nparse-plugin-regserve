package review_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

func TestMain(m *testing.M) { storetest.Main(m) }

var now = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

// steppingClock advances a millisecond every time it is read.
//
// It exists for the queue-ordering test and says something the FIXED clock cannot. Under a frozen
// clock every release shares one submitted_at, so the order falls to the ULID tiebreaker -- and a
// ULID's low bits are random, which means a test asserting chronological order under a fixed clock
// is asserting something the code cannot provide and does not need to. Real submissions arrive at
// different microseconds; this is the clock that reproduces that.
type steppingClock struct {
	mu sync.Mutex
	at time.Time
}

func newSteppingClock() *steppingClock { return &steppingClock{at: now} }

func (c *steppingClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(time.Millisecond)
	return c.at
}

// The queue is tested against a database that got its rows THROUGH THE PUBLISH PATH, not through
// hand-written inserts.
//
// That is deliberate. A fixture that inserted release rows directly could put the database in
// states publishing cannot produce — an approved release with no hash, a pending release whose
// hash nobody computed — and every assertion made against it would be about a shape that does not
// occur. Going through release.Publisher means the queue is tested against exactly what it will
// meet, including the parts that are awkward.

type world struct {
	db  *store.DB
	srv *httptest.Server

	pub   *release.Publisher
	queue *review.Queue

	// fetcher is the real, guarded fetcher this fixture uses. A test double that needs to act
	// BEFORE the fetch delegates to it rather than faking a result -- it could not fake one
	// anyway, since artifact.Result carries a Digest nothing outside internal/artifact can build.
	fetcher *artifact.Fetcher

	// serving is what the artifact server hands back, and whether it answers at all. Tests flip
	// these to produce an unfetchable artifact without tearing anything down.
	serving   []byte
	available bool

	plugin   string
	owner    string
	reviewer string
}

func newWorld(t *testing.T) *world { return buildWorld(t, false) }

// newSteppingWorld is newWorld with a clock that advances, for the one test whose subject is order.
func newSteppingWorld(t *testing.T) *world { return buildWorld(t, true) }

func buildWorld(t *testing.T, stepping bool) *world {
	t.Helper()

	db := storetest.New(t)
	w := &world{
		db:        db,
		serving:   []byte("PK\x03\x04 an artifact"),
		available: true,
		plugin:    "merchant-mode",
	}

	w.srv = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		if !w.available {
			rw.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = rw.Write(w.serving)
	}))
	t.Cleanup(w.srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(w.srv.Certificate())
	fetcher, err := artifact.NewFetcher(clock.Fixed{T: now}, artifact.Config{
		Timeout:        5 * time.Second,
		PermitLoopback: true,
		RootCAs:        pool,
	})
	require.NoError(t, err)

	clk := clock.Clock(clock.Fixed{T: now})
	if stepping {
		clk = newSteppingClock()
	}
	w.fetcher = fetcher
	w.pub = release.NewPublisher(db, clk, fetcher)
	w.queue = review.NewQueue(db, clk, fetcher)

	w.owner = w.account(t, "prokopto-dev")
	w.reviewer = w.account(t, "themaintainer")

	w.claim(t, w.plugin, "Merchant Mode")
	return w
}

// claim registers a plugin id to the fixture's owner.
//
// Separate from buildWorld because release_one_pending_per_plugin permits ONE waiting release per
// plugin, so any test whose subject is a queue with several entries in it needs several plugins --
// which is the shape a real queue has, and was not the shape these tests used to build.
func (w *world) claim(t *testing.T, id, name string) {
	t.Helper()

	require.NoError(t, w.db.Tx(t.Context(), func(q *store.Queries) error {
		if err := q.InsertPlugin(t.Context(), sqlitegen.InsertPluginParams{
			ID:        id,
			Name:      name,
			ClaimedAt: core.MicrosFromTime(now).Int64(),
			UpdatedAt: core.MicrosFromTime(now).Int64(),
		}); err != nil {
			return err
		}
		return q.InsertPluginOwner(t.Context(), sqlitegen.InsertPluginOwnerParams{
			PluginID:  id,
			AccountID: w.owner,
			Role:      ownership.RoleOwner.String(),
			GrantedAt: core.MicrosFromTime(now).Int64(),
		})
	}))
}

func (w *world) account(t *testing.T, handle string) string {
	t.Helper()

	id, err := core.NewULID(now)
	require.NoError(t, err)
	identityID, err := core.NewULID(now)
	require.NoError(t, err)

	require.NoError(t, w.db.Tx(t.Context(), func(q *store.Queries) error {
		if err := q.InsertAccount(t.Context(), sqlitegen.InsertAccountParams{
			ID:          id.String(),
			DisplayName: handle,
			CreatedAt:   core.MicrosFromTime(now).Int64(),
			UpdatedAt:   core.MicrosFromTime(now).Int64(),
		}); err != nil {
			return err
		}
		return q.InsertIdentity(t.Context(), sqlitegen.InsertIdentityParams{
			ID:           identityID.String(),
			AccountID:    id.String(),
			ProviderKind: "github",
			Subject:      "sub-" + handle,
			Handle:       handle,
			LinkedAt:     core.MicrosFromTime(now).Int64(),
			RefreshedAt:  core.MicrosFromTime(now).Int64(),
		})
	}))
	return id.String()
}

// publish submits a release of the fixture's plugin through the real publish path.
func (w *world) publish(t *testing.T, version string) release.Outcome {
	t.Helper()
	return w.publishFor(t, w.plugin, version)
}

// publishFor is publish against a named plugin, for the tests that need more than one.
func (w *world) publishFor(t *testing.T, pluginID, version string) release.Outcome {
	t.Helper()

	sum := sha256.Sum256(w.serving)
	sub, err := release.NewSubmission(release.RawSubmission{
		PluginID:       pluginID,
		Version:        version,
		ArtifactURL:    w.srv.URL + "/" + version + ".whl",
		ArtifactSHA256: hex.EncodeToString(sum[:]),
		SDKSpecifier:   ">=1.0,<2",
	})
	require.NoError(t, err)

	out, err := w.pub.Publish(t.Context(), release.Request{
		Submission: sub, AccountID: w.owner, IdempotencyKey: "key-" + pluginID + "-" + version,
	})
	require.NoError(t, err)
	return out
}

// state reads a release's state straight out of the row.
func (w *world) state(t *testing.T, releaseID string) string {
	t.Helper()

	row, err := w.db.Read().GetReleaseByID(t.Context(), releaseID)
	require.NoError(t, err)
	return row.State
}

// listed is what the index would render: the plugin ids with a live release.
func (w *world) listed(t *testing.T) []string {
	t.Helper()

	rows, err := w.db.Read().ListListings(t.Context())
	require.NoError(t, err)

	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ID+"@"+r.Version)
	}
	return out
}

// releaseStates counts rows per state, so "history is kept" is an assertion rather than a hope.
func (w *world) releaseStates(t *testing.T) map[string]int {
	t.Helper()

	rows := storetest.Column(t, w.db, `SELECT state || ':' || count(*) FROM "release" GROUP BY state`)
	out := map[string]int{}
	for _, row := range rows {
		parts := strings.SplitN(row, ":", 2)
		n, err := strconv.Atoi(parts[1])
		require.NoError(t, err)
		out[parts[0]] = n
	}
	return out
}

// auditDetails returns the detail objects of every audit row with the given action.
func (w *world) auditDetails(t *testing.T, action string) []map[string]any {
	t.Helper()

	rows := storetest.Column(t, w.db,
		`SELECT detail FROM audit_log WHERE action = ? ORDER BY recorded_at, id`, action)

	out := make([]map[string]any, 0, len(rows))
	for _, raw := range rows {
		var detail map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &detail))
		out = append(out, detail)
	}
	return out
}

// fixedClock is the clock the fixture shares, so submitted_at and verified_at are exact.
func fixedClock() clock.Clock { return clock.Fixed{T: now} }
