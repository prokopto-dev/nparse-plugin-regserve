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
