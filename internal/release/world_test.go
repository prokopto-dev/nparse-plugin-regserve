package release_test

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/clock"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/ownership"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

func TestMain(m *testing.M) { storetest.Main(m) }

var now = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

// THE FETCHER IN THESE TESTS IS A REAL ONE, over a real socket, against a real TLS server.
//
// That is not thoroughness for its own sake — it is forced, and the forcing is the mechanism.
// artifact.Digest has an unexported field and no exported constructor, so no test in this package
// can fabricate one. A test that wants a successful publish has to serve bytes and let the fetcher
// hash them, which means every assertion below about a stored hash is an assertion about a hash
// that was computed from bytes that existed. A mock would have let this whole file lie.

// world is a database with an owner, a maintainer, a stranger, and one claimed plugin.
type world struct {
	db     *store.DB
	pub    *release.Publisher
	srv    *httptest.Server
	body   []byte
	plugin string

	// redirectTo makes the artifact server answer with a 302 before serving, so a test can prove
	// the host rule reads the SUBMITTED url rather than where the chain landed.
	redirectTo string

	// fetches counts requests the artifact server received, so "refused before anything was
	// downloaded" is an assertion rather than a claim.
	fetches atomic.Int64

	// fetcher is the real, guarded fetcher this fixture publishes through. A test double that
	// wants to do something BEFORE the fetch delegates to it rather than faking a result — it
	// could not fake one anyway, because artifact.Result carries a Digest nothing outside
	// internal/artifact can construct.
	fetcher *artifact.Fetcher

	owner      string
	maintainer string
	stranger   string

	// noIdentity is an account with no provider identity at all. Only GitHub identities may
	// publish, and that is a CHECK against identity_provider.kind rather than a toggle.
	noIdentity string
}

// newWorld builds the fixture, serving body at the artifact URL.
func newWorld(t *testing.T, body []byte) *world {
	t.Helper()

	db := storetest.New(t)
	w := &world{db: db, body: body, plugin: "merchant-mode"}

	w.srv = httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		w.fetches.Add(1)
		// A redirect hop, when a test asks for one: a real release asset redirects before the
		// bytes arrive, and the host rule must not notice.
		if w.redirectTo != "" && !strings.HasPrefix(r.URL.Path, "/actual/") {
			http.Redirect(rw, r, w.redirectTo, http.StatusFound)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/missing.whl") {
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = rw.Write(w.body)
	}))
	t.Cleanup(w.srv.Close)

	pool := x509.NewCertPool()
	pool.AddCert(w.srv.Certificate())
	fetcher, err := artifact.NewFetcher(clock.Fixed{T: now}, artifact.Config{
		Timeout: 5 * time.Second,
		// The narrow relaxations, and only these: loopback so the fetch reaches httptest, and the
		// server's own certificate so verification succeeds rather than being switched off. Every
		// other address category is still refused.
		PermitLoopback: true,
		RootCAs:        pool,
	})
	require.NoError(t, err)

	w.fetcher = fetcher
	w.pub = release.NewPublisher(db, clock.Fixed{T: now}, fetcher)

	w.owner = w.account(t, "prokopto-dev", true)
	w.maintainer = w.account(t, "octocat", true)
	w.stranger = w.account(t, "nobody", true)
	w.noIdentity = w.account(t, "ghost", false)

	require.NoError(t, db.Tx(t.Context(), func(q *store.Queries) error {
		if err := q.InsertPlugin(t.Context(), sqlitegen.InsertPluginParams{
			ID:        w.plugin,
			Name:      "Merchant Mode",
			ClaimedAt: core.MicrosFromTime(now).Int64(),
			UpdatedAt: core.MicrosFromTime(now).Int64(),
		}); err != nil {
			return err
		}
		if err := q.InsertPluginOwner(t.Context(), sqlitegen.InsertPluginOwnerParams{
			PluginID:  w.plugin,
			AccountID: w.owner,
			Role:      ownership.RoleOwner.String(),
			GrantedAt: core.MicrosFromTime(now).Int64(),
		}); err != nil {
			return err
		}
		return q.InsertPluginOwner(t.Context(), sqlitegen.InsertPluginOwnerParams{
			PluginID:  w.plugin,
			AccountID: w.maintainer,
			Role:      ownership.RoleMaintainer.String(),
			GrantedAt: core.MicrosFromTime(now).Int64(),
		})
	}))
	return w
}

// account creates an account, optionally with a GitHub identity.
func (w *world) account(t *testing.T, handle string, withIdentity bool) string {
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
		if !withIdentity {
			return nil
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

// artifactURL is where the fixture serves the body.
func (w *world) artifactURL() string { return w.srv.URL + "/merchant-mode-1.0.0.whl" }

// truth is the sha256 of the bytes the fixture actually serves.
func (w *world) truth() string {
	sum := sha256.Sum256(w.body)
	return hex.EncodeToString(sum[:])
}

// submit builds a raw submission with the correct hash, which each test then perturbs.
func (w *world) submit(t *testing.T, mutate func(*release.RawSubmission)) release.Submission {
	t.Helper()

	raw := release.RawSubmission{
		PluginID:       w.plugin,
		Version:        "1.0.0",
		ArtifactURL:    w.artifactURL(),
		ArtifactSHA256: w.truth(),
		SDKSpecifier:   ">=1.0,<2",
	}
	if mutate != nil {
		mutate(&raw)
	}
	sub, err := release.NewSubmission(raw)
	require.NoError(t, err)
	return sub
}

// publish runs one publish as the owner, with a fresh idempotency key.
func (w *world) publish(t *testing.T, sub release.Submission, key string) (release.Outcome, error) {
	t.Helper()

	return w.pub.Publish(t.Context(), release.Request{
		Submission:     sub,
		AccountID:      w.owner,
		IdempotencyKey: key,
	})
}

// storedHash reads release.artifact_sha256 straight back out of the database.
//
// Through the row and not through the Outcome, because what is being asserted is what was WRITTEN
// — an outcome is a report about a write and this is the write.
func (w *world) storedHash(t *testing.T, releaseID string) *string {
	t.Helper()

	row, err := w.db.Read().GetReleaseByID(t.Context(), releaseID)
	require.NoError(t, err)
	return row.ArtifactSha256
}

// flipOneHexDigit returns a valid but different sha256.
func flipOneHexDigit(s string) string {
	b := []byte(s)
	if b[0] == 'a' {
		b[0] = 'b'
	} else {
		b[0] = 'a'
	}
	return string(b)
}

// fixedClock is the clock every part of this fixture shares, so verified_at and submitted_at are
// exact assertions rather than "near enough".
func fixedClock() clock.Clock { return clock.Fixed{T: now} }

// grant gives an account the plugin as a maintainer.
func (w *world) grant(t *testing.T, accountID string) {
	t.Helper()

	require.NoError(t, w.db.Tx(t.Context(), func(q *store.Queries) error {
		return q.InsertPluginOwner(t.Context(), sqlitegen.InsertPluginOwnerParams{
			PluginID:  w.plugin,
			AccountID: accountID,
			Role:      ownership.RoleMaintainer.String(),
			GrantedAt: core.MicrosFromTime(now).Int64(),
		})
	}))
}

// revoke removes an account's grant, which is what a concurrent owner removal looks like from the
// publish path's point of view.
func (w *world) revoke(t *testing.T, accountID string) {
	t.Helper()

	require.NoError(t, w.db.Tx(t.Context(), func(q *store.Queries) error {
		_, err := q.DeletePluginOwner(t.Context(), sqlitegen.DeletePluginOwnerParams{
			PluginID:  w.plugin,
			AccountID: accountID,
		})
		return err
	}))
}

// delist clears a plugin's listing while KEEPING its claim, which is what delisting is: the row
// survives for ever because ids are never recycled. Written through storetest.Exec rather than a
// query, because nothing in production delists from this package and adding one for a test to call
// would be a query nobody maintains.
func (w *world) delist(t *testing.T, pluginID string) {
	t.Helper()

	// The reason is not optional: a CHECK requires it, because a listing that vanishes without a
	// stated reason is indistinguishable from a bug.
	storetest.Exec(t, w.db,
		`UPDATE plugin SET delisted_at = ?, delisted_reason = ? WHERE id = ?`,
		core.MicrosFromTime(now).Int64(), "delisted by a test", pluginID)
}

// releaseCount is how many release rows exist at all.
//
// It is the assertion that a REFUSED publish wrote nothing and that a REPLAY did nothing rather
// than doing the same thing twice — neither of which any outcome value can show, because both of
// them are about a row that should not be there. Read through storetest.Column rather than through
// a query, because nothing in production has a reason to count releases and adding a query for a
// test to use would be a query nobody maintains.
func (w *world) releaseCount(t *testing.T) int {
	t.Helper()

	got := storetest.Column(t, w.db, `SELECT count(*) FROM "release"`)
	require.Len(t, got, 1)

	n, err := strconv.Atoi(got[0])
	require.NoError(t, err)
	return n
}

// auditDetail reads back the detail object of the publish audit row for a release.
//
// audit_log is append-only by trigger, so what this returns is what a human will read during an
// incident years from now and the only version of it there will ever be.
func (w *world) auditDetail(t *testing.T, releaseID string) map[string]any {
	t.Helper()
	_ = releaseID // the publish row is keyed on the PLUGIN; a release id is inside the detail

	rows := storetest.Column(t, w.db,
		`SELECT detail FROM audit_log WHERE action = ? AND subject_id = ? ORDER BY recorded_at, id`,
		"plugin.publish", w.plugin)
	require.Len(t, rows, 1, "expected exactly one publish audit row for %s", w.plugin)

	var detail map[string]any
	require.NoError(t, json.Unmarshal([]byte(rows[0]), &detail))
	return detail
}

// storedURLs is every artifact_url in the database.
//
// The assertion it serves is about what would be PUBLISHED: the index renders this column verbatim
// to every client, so "no row exists" and "no url is stored" are the two halves of "there is
// nothing to leak".
func (w *world) storedURLs(t *testing.T) []string {
	t.Helper()

	return storetest.Column(t, w.db, `SELECT artifact_url FROM "release"`)
}

// --- helpers the quarantine and trust tests need ----------------------------------------------

// approve makes a pending release the plugin's live one, by the same route a reviewer would: it
// supersedes whatever is live and flips the state, in one transaction.
//
// It is written here rather than borrowed from internal/review because this package must not
// depend on that one — the publish path decides, the review path decides, and neither is a client
// of the other. What matters for these tests is that the row ends in the state the index reads.
func (w *world) approve(t *testing.T, releaseID string) {
	t.Helper()

	require.NoError(t, w.db.Tx(t.Context(), func(q *store.Queries) error {
		if _, err := q.SupersedeApprovedRelease(t.Context(), w.plugin); err != nil {
			return err
		}
		changed, err := q.ApproveRelease(t.Context(), sqlitegen.ApproveReleaseParams{
			ReviewedAt: ptr(core.MicrosFromTime(now).Int64()),
			ID:         releaseID,
		})
		if err != nil {
			return err
		}
		require.Equal(t, int64(1), changed)
		return nil
	}))
}

// setTrust assigns a tier through the real service, so the audit row and the CHECK are exercised
// rather than bypassed.
func (w *world) setTrust(t *testing.T, accountID string, level release.Trust) {
	t.Helper()

	require.NoError(t, w.pub.SetTrust(t.Context(), accountID, level, w.owner,
		"set by a test, because a tier with no stated reason is refused"))
}

// stateOf reads a release's state straight out of the row.
func (w *world) stateOf(t *testing.T, releaseID string) string {
	t.Helper()

	row, err := w.db.Read().GetReleaseByID(t.Context(), releaseID)
	require.NoError(t, err)
	return row.State
}

// listed is what the index would render.
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

// secondHost starts another artifact server on a different hostname, for the host-change rule.
//
// `127.0.0.1` and `localhost` resolve to the same place and are different HOSTNAMES, which is
// exactly what the rule compares — it reads the submitted URL, not where a redirect landed.
func (w *world) secondHost(t *testing.T) string {
	t.Helper()

	return strings.Replace(w.srv.URL, "127.0.0.1", "localhost", 1)
}

// fetchCount is how many times the artifact server has been asked for anything.
func (w *world) fetchCount() int64 { return w.fetches.Load() }

// auditDetailFor returns the publish audit row for one release.
//
// Matched on the release id INSIDE the detail rather than on row order. The subject of a publish
// row is the plugin, and under a fixed clock every row shares a recorded_at so the order falls to
// the ULID tiebreaker, whose low bits are random — "the last row" is not a thing this can ask for.
func (w *world) auditDetailFor(t *testing.T, releaseID string) map[string]any {
	t.Helper()

	rows := storetest.Column(t, w.db,
		`SELECT detail FROM audit_log WHERE action = ? AND subject_id = ?`,
		"plugin.publish", w.plugin)
	require.NotEmpty(t, rows)

	for _, raw := range rows {
		var detail map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &detail))
		if detail["release"] == releaseID {
			return detail
		}
	}
	require.FailNowf(t, "no publish audit row", "nothing recorded for release %s", releaseID)
	return nil
}

// auditDetails returns the detail objects of every audit row with the given action.
func (w *world) auditDetails(t *testing.T, action string) []map[string]any {
	t.Helper()

	rows := storetest.Column(t, w.db, `SELECT detail FROM audit_log WHERE action = ?`, action)

	out := make([]map[string]any, 0, len(rows))
	for _, raw := range rows {
		var detail map[string]any
		require.NoError(t, json.Unmarshal([]byte(raw), &detail))
		out = append(out, detail)
	}
	return out
}
