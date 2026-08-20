package release_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/artifact"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/release"
)

// --- THE INVARIANT: a stored sha256 was computed by the server -------------------------------

// TestPublish_ADeliberatelyWrongSubmittedHash_StoresTheTruthFromTheBytes.
//
// THIS IS THE TEST THE WHOLE MECHANISM EXISTS FOR. The submitter claims one hash; the artifact
// hashes to another. What gets stored must be the second one — the truth about bytes this server
// read — and the disagreement must be RECORDED rather than quietly resolved in either direction.
//
// Storing the submitted value would be catastrophic and completely invisible: the listing would
// look correct, the client would verify the artifact against the published hash, and the check
// would pass for exactly the bytes an attacker chose. Storing ours and saying nothing would be
// quieter and nearly as bad — the author approved one set of bytes and users would receive
// another, with nothing anywhere recording that the two had ever differed.
func TestPublish_ADeliberatelyWrongSubmittedHash_StoresTheTruthFromTheBytes(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 the real bytes, whatever anybody claims about them"))

	lie := flipOneHexDigit(w.truth())
	require.NotEqual(t, w.truth(), lie, "the fixture must actually submit a wrong hash")

	sub := w.submit(t, func(raw *release.RawSubmission) { raw.ArtifactSHA256 = lie })
	out, err := w.publish(t, sub, "key-mismatch")
	require.NoError(t, err)

	// THE STORED VALUE IS THE ONE COMPUTED FROM THE BYTES, read back out of the row rather than
	// out of the outcome.
	stored := w.storedHash(t, out.ReleaseID)
	require.NotNil(t, stored)
	require.Equal(t, w.truth(), *stored,
		"the stored hash is not the one this server computed from the artifact it fetched")
	require.NotEqual(t, lie, *stored,
		"THE SUBMITTED HASH WAS STORED. Every client would verify perfectly against bytes the "+
			"submitter chose, which is the exact failure ADR-0008 exists to prevent")

	// It is NOT published. A mismatch means something between the author's build and our fetch
	// changed the bytes, and that is precisely the event worth stopping.
	require.Equal(t, release.StatePending, out.State)
	require.False(t, out.Verified,
		"a release whose submitted hash did not match must never report as verified")

	// The mismatch is RECORDED, not silently corrected.
	require.Contains(t, out.Review, "does not match")

	row, err := w.db.Read().GetReleaseByID(t.Context(), out.ReleaseID)
	require.NoError(t, err)
	require.NotNil(t, row.ReviewNote)
	require.Contains(t, *row.ReviewNote, "does not match")

	// And in the audit log, with BOTH halves — a mismatch is unreadable with only one.
	detail := w.auditDetail(t, out.ReleaseID)
	require.Equal(t, w.truth(), detail["computed_sha256"])
	require.Equal(t, lie, detail["submitted_sha256"],
		"the claimed hash is not recorded; an incident review cannot see what was claimed")
	require.Equal(t, false, detail["verified"])
}

// TestPublish_TheHappyPath_StoresTheComputedHashAndRecordsWhenItWasComputed.
//
// The ordinary case, and the one that proves the mechanism is not simply refusing everything.
func TestPublish_TheHappyPath_StoresTheComputedHashAndRecordsWhenItWasComputed(t *testing.T) {
	t.Parallel()

	body := []byte("PK\x03\x04 an artifact whose hash the submitter got right")
	w := newWorld(t, body)

	out, err := w.publish(t, w.submit(t, nil), "key-happy")
	require.NoError(t, err)

	require.True(t, out.Verified)
	require.Equal(t, w.truth(), out.SHA256)
	require.Equal(t, int64(len(body)), *out.Bytes)

	row, err := w.db.Read().GetReleaseByID(t.Context(), out.ReleaseID)
	require.NoError(t, err)
	require.Equal(t, w.truth(), *row.ArtifactSha256)

	// verified_at is the DATABASE's own record that this server computed the hash, and the
	// release_a_stored_hash_was_verified_or_imported CHECK is what ties the two together: a
	// publish row carrying a hash and no verified_at is a row SQLite refuses.
	require.NotNil(t, row.VerifiedAt,
		"the hash was stored with no record of when this server computed it")
	require.Equal(t, "publish", row.Source)

	// Still pending: a new plugin id always gets human review, and trust levels that would let a
	// version bump publish automatically are not built yet.
	require.Equal(t, release.StatePending, out.State)
	require.False(t, out.Replayed)
}

// TestPublish_AnArtifactThatCouldNotBeFetched_IsNotPublishedAndSaysSo.
//
// "We could not check" and "we checked and it was fine" must never produce the same outcome. This
// is the rule ADR-0008 names as the one most likely to be optimised away later by somebody reading
// a timeout as a transient annoyance.
func TestPublish_AnArtifactThatCouldNotBeFetched_IsNotPublishedAndSaysSo(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("never served"))

	sub := w.submit(t, func(raw *release.RawSubmission) {
		raw.ArtifactURL = w.srv.URL + "/missing.whl" // the fixture answers 404 for this path
	})
	out, err := w.publish(t, sub, "key-unfetchable")

	// NOT an error. The submission is recorded so a human can see that something arrived and could
	// not be checked — dropping it would make "we could not check" indistinguishable from
	// "nothing happened".
	require.NoError(t, err)
	require.False(t, out.Verified)
	require.Equal(t, release.StatePending, out.State)
	require.Empty(t, out.SHA256, "a hash was reported for bytes this server never read")
	require.True(t, strings.HasPrefix(out.Review, "not verified: "),
		"the review note does not say the artifact was not verified: %q", out.Review)

	row, err := w.db.Read().GetReleaseByID(t.Context(), out.ReleaseID)
	require.NoError(t, err)
	require.Nil(t, row.ArtifactSha256, "a hash was STORED for bytes this server never read")
	require.Nil(t, row.VerifiedAt)
	require.Nil(t, row.ArtifactBytes)
}

// TestPublish_AnUnreachableFetcher_IsStillNotASuccess — the same rule, for a fetcher that fails
// for a reason no server can produce on demand.
func TestPublish_AnUnreachableFetcher_IsStillNotASuccess(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("the bytes"))
	w.pub = release.NewPublisher(w.db, fixedClock(), failingFetcher{err: context.DeadlineExceeded})

	out, err := w.publish(t, w.submit(t, nil), "key-timeout")
	require.NoError(t, err)

	require.False(t, out.Verified)
	require.Empty(t, out.SHA256)
	require.Equal(t, artifact.Reason(context.DeadlineExceeded), out.Review)
	require.Nil(t, w.storedHash(t, out.ReleaseID))
}

// failingFetcher fails every fetch. It cannot fabricate a SUCCESS — artifact.Result carries an
// artifact.Digest, which nothing outside internal/artifact can construct — which is exactly the
// property that makes this double safe to have.
type failingFetcher struct{ err error }

func (f failingFetcher) Fetch(context.Context, string) (artifact.Result, error) {
	return artifact.Result{}, f.err
}

// --- idempotency -----------------------------------------------------------------------------

// TestPublish_AReplayedKey_ReturnsTheOriginalRatherThanASecondRelease.
//
// The dominant caller is a release workflow and workflows get re-run: by a maintainer clicking
// "re-run failed jobs", by a runner that lost its network after the row was written. Without this,
// the second run meets the version uniqueness index and the author reads "version already exists"
// for a version they published once.
func TestPublish_AReplayedKey_ReturnsTheOriginalRatherThanASecondRelease(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 published once"))
	sub := w.submit(t, nil)

	first, err := w.publish(t, sub, "workflow-run-1")
	require.NoError(t, err)
	require.False(t, first.Replayed)

	second, err := w.publish(t, sub, "workflow-run-1")
	require.NoError(t, err)

	require.True(t, second.Replayed)
	require.Equal(t, first.ReleaseID, second.ReleaseID, "a re-run minted a second release")
	require.Equal(t, first.SHA256, second.SHA256)
	require.Equal(t, first.State, second.State)

	// One row, not two. The count is what proves the replay did nothing rather than doing the same
	// thing twice.
	require.Equal(t, 1, w.releaseCount(t))
}

// TestPublish_AKeyReusedForADifferentRequest_IsAConflict.
//
// Answering with the first release's id would tell a caller their NEW version published when it
// did not, which is the confident mistake in miniature.
func TestPublish_AKeyReusedForADifferentRequest_IsAConflict(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 published once"))

	_, err := w.publish(t, w.submit(t, nil), "workflow-run-1")
	require.NoError(t, err)

	tests := []struct {
		name   string
		mutate func(*release.RawSubmission)
	}{
		{"a different version", func(r *release.RawSubmission) { r.Version = "1.0.1" }},
		{"a different url", func(r *release.RawSubmission) { r.ArtifactURL = w.srv.URL + "/other.whl" }},
		{
			// The claimed hash is part of the identity of the request. Two submissions of one
			// version with different claimed hashes are different requests.
			"a different claimed hash",
			func(r *release.RawSubmission) { r.ArtifactSHA256 = flipOneHexDigit(w.truth()) },
		},
		{"different notes", func(r *release.RawSubmission) { r.Notes = "now with a changelog" }},
		{"a different specifier", func(r *release.RawSubmission) { r.SDKSpecifier = ">=2.0" }},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := w.publish(t, w.submit(t, tc.mutate), "workflow-run-1")
			require.ErrorIs(t, err, release.ErrIdempotencyKeyReused)
		})
	}

	require.Equal(t, 1, w.releaseCount(t), "a reused key wrote a second release")
}

// TestPublish_NoIdempotencyKey_IsRefused — canonical §6 requires one.
func TestPublish_NoIdempotencyKey_IsRefused(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("bytes"))

	for _, key := range []string{"", "   ", "\t\n"} {
		_, err := w.pub.Publish(t.Context(), release.Request{
			Submission:     w.submit(t, nil),
			AccountID:      w.owner,
			IdempotencyKey: key,
		})
		require.ErrorIs(t, err, release.ErrNoIdempotencyKey)
	}
	require.Zero(t, w.releaseCount(t))
}

// --- authority -------------------------------------------------------------------------------

// TestPublish_Authority_IsOwnershipAtRequestTime — ADR-0005, checked per request.
func TestPublish_Authority_IsOwnershipAtRequestTime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		account func(w *world) string
		wantErr error
	}{
		{"an owner may publish", func(w *world) string { return w.owner }, nil},
		{
			// A maintainer may publish and may NOT change who holds the plugin. That difference is
			// the entire reason the role exists.
			"a maintainer may publish",
			func(w *world) string { return w.maintainer },
			nil,
		},
		{
			// The same answer as "no such plugin". Telling somebody "that plugin exists and is
			// not yours" enumerates claimed ids, and ids are permanent.
			"a stranger may not, and is told nothing about the plugin",
			func(w *world) string { return w.stranger },
			release.ErrNotPublishable,
		},
		{
			"an account with no github identity may not",
			func(w *world) string { return w.noIdentity },
			release.ErrGitHubIdentityRequired,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t, []byte("PK\x03\x04 bytes"))
			if tc.wantErr == release.ErrGitHubIdentityRequired {
				// The account has to hold the plugin, or ownership refuses it first and this case
				// would pass for the wrong reason.
				w.grant(t, w.noIdentity)
			}

			_, err := w.pub.Publish(t.Context(), release.Request{
				Submission:     w.submit(t, nil),
				AccountID:      tc.account(w),
				IdempotencyKey: "key-authority",
			})
			if tc.wantErr == nil {
				require.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, tc.wantErr)
			require.Zero(t, w.releaseCount(t), "a refused publish wrote a row")
		})
	}
}

// TestPublish_AnOwnerRemovedDuringTheFetch_DoesNotGetOneMoreRelease.
//
// The fetch takes up to forty-five seconds and happens OUTSIDE the write transaction, because
// SQLite has one writer and holding it across a download would block every other publish. That
// makes a window: ownership is checked before the fetch, and it must be checked AGAIN inside the
// transaction that writes. ADR-0005 wants the authority and the change decided against one
// snapshot, and a check made only before a forty-five-second download is not that.
func TestPublish_AnOwnerRemovedDuringTheFetch_DoesNotGetOneMoreRelease(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 bytes"))

	// A fetcher that revokes the grant while it is "downloading" — which is exactly what a
	// concurrent owner removal looks like from the publish path's point of view.
	w.pub = release.NewPublisher(w.db, fixedClock(), revokingFetcher{w: w, t: t})

	_, err := w.publish(t, w.submit(t, nil), "key-revoked-midway")
	require.ErrorIs(t, err, release.ErrNotPublishable,
		"the grant was revoked while the artifact downloaded and the release was written anyway")
	require.Zero(t, w.releaseCount(t))
}

// revokingFetcher removes the caller's grant, then fetches normally.
type revokingFetcher struct {
	w *world
	t *testing.T
}

func (f revokingFetcher) Fetch(ctx context.Context, rawURL string) (artifact.Result, error) {
	f.w.revoke(f.t, f.w.owner)
	return f.w.fetcher.Fetch(ctx, rawURL)
}

// --- versions --------------------------------------------------------------------------------

// TestPublish_AVersionAlreadyUsed_IsRefusedWhateverStateItIsIn.
//
// A version is used once per plugin, EVER, over a table nothing deletes from. A rejected 1.0.0
// does not free 1.0.0: the number is what a client has already seen, and reusing it is how
// different bytes ship under a version somebody already installed.
func TestPublish_AVersionAlreadyUsed_IsRefusedWhateverStateItIsIn(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 bytes"))

	_, err := w.publish(t, w.submit(t, nil), "key-first")
	require.NoError(t, err)

	_, err = w.publish(t, w.submit(t, nil), "key-second-attempt")
	require.ErrorIs(t, err, release.ErrVersionExists)
	require.Equal(t, 1, w.releaseCount(t))
}

// --- notes -----------------------------------------------------------------------------------

// TestPublish_Notes_AreStoredNormalisedOrTheReleaseIsRefused (ADR-0013).
func TestPublish_Notes_AreStoredNormalisedOrTheReleaseIsRefused(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 bytes"))

	out, err := w.publish(t, w.submit(t, func(r *release.RawSubmission) {
		r.Notes = "  Fixed the thing.\r\nAnd the other thing.\r\n  "
	}), "key-notes")
	require.NoError(t, err)

	row, err := w.db.Read().GetReleaseByID(t.Context(), out.ReleaseID)
	require.NoError(t, err)
	require.NotNil(t, row.Notes)
	require.Equal(t, "Fixed the thing.\nAnd the other thing.", *row.Notes,
		"line endings are normalised so the same notes from Windows and Linux are the same bytes")
}

// --- audit -----------------------------------------------------------------------------------

// TestPublish_TheAuditRow_NamesWhoAndWhatAndCarriesNoCredential.
//
// audit_log is append-only by trigger, so anything written here can never be redacted. A signed
// CDN URL keeps its signature in the query string, which is why the detail carries HOSTS.
func TestPublish_TheAuditRow_NamesWhoAndWhatAndCarriesNoCredential(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 bytes"))

	out, err := w.publish(t, w.submit(t, nil), "key-audit")
	require.NoError(t, err)

	detail := w.auditDetail(t, out.ReleaseID)
	require.Equal(t, "1.0.0", detail["version"])
	require.Equal(t, true, detail["verified"])
	require.Equal(t, w.truth(), detail["computed_sha256"])
	require.Equal(t, "127.0.0.1", detail["artifact_host"])

	// On the happy path the submitted digest equals the stored one, so recording it twice would
	// say nothing. It appears only on a mismatch, where both halves are needed to read the row.
	require.NotContains(t, detail, "submitted_sha256")

	raw, err := json.Marshal(detail)
	require.NoError(t, err)
	require.NotContains(t, string(raw), "?", "the audit detail carries a url rather than a host")
}

// --- errors that must not be swallowed --------------------------------------------------------

// TestNewSubmission_RefusesHostileInput — every field is checked, before anything is downloaded.
func TestNewSubmission_RefusesHostileInput(t *testing.T) {
	t.Parallel()

	base := release.RawSubmission{
		PluginID:       "merchant-mode",
		Version:        "1.0.0",
		ArtifactURL:    "https://example.com/x.whl",
		ArtifactSHA256: strings.Repeat("a", 64),
		SDKSpecifier:   ">=1.0,<2",
	}

	tests := []struct {
		name   string
		mutate func(*release.RawSubmission)
		wantIs error
	}{
		{"an id that is not one", func(r *release.RawSubmission) { r.PluginID = "Not An Id" }, nil},
		{"no version", func(r *release.RawSubmission) { r.Version = "" }, release.ErrNoVersion},
		{
			"a version with a newline in it",
			func(r *release.RawSubmission) { r.Version = "1.0.0\nrm -rf" },
			release.ErrNoVersion,
		},
		{
			"a version longer than the cap",
			func(r *release.RawSubmission) { r.Version = strings.Repeat("1", 65) },
			release.ErrNoVersion,
		},
		{
			"an http url",
			func(r *release.RawSubmission) { r.ArtifactURL = "http://example.com/x.whl" },
			artifact.ErrBadArtifactURL,
		},
		{
			// It would fetch fine. It must not be STORED: artifact_url is rendered into the index
			// and served to every client, and this registry cannot take it back once cached.
			"a url carrying credentials in userinfo",
			func(r *release.RawSubmission) { r.ArtifactURL = "https://tok@example.com/x.whl" },
			artifact.ErrBadArtifactURL,
		},
		{
			// A signed url's signature IS a bearer credential for those bytes. Publishing one
			// hands it to everybody who polls the index, cached, for as long as it is valid.
			"a signed url",
			func(r *release.RawSubmission) {
				r.ArtifactURL = "https://cdn.example.com/x.whl?X-Amz-Signature=deadbeefcafe"
			},
			artifact.ErrBadArtifactURL,
		},
		{
			"a url with any query string at all",
			func(r *release.RawSubmission) { r.ArtifactURL = "https://example.com/x.whl?v=1" },
			artifact.ErrBadArtifactURL,
		},
		{
			"a url with a fragment",
			func(r *release.RawSubmission) { r.ArtifactURL = "https://example.com/x.whl#sha256=ab" },
			artifact.ErrBadArtifactURL,
		},
		{
			"a sha256 that is not one",
			func(r *release.RawSubmission) { r.ArtifactSHA256 = "sha256:" + strings.Repeat("a", 64) },
			artifact.ErrInvalidDigest,
		},
		{
			"no sdk specifier",
			func(r *release.RawSubmission) { r.SDKSpecifier = "" },
			release.ErrNoSDKSpecifier,
		},
		{
			"notes over the cap",
			func(r *release.RawSubmission) { r.Notes = strings.Repeat("a", 2049) },
			release.ErrNotesTooLong,
		},
		{
			"notes containing an escape sequence",
			func(r *release.RawSubmission) { r.Notes = "fixed \x1b[31mthings\x1b[0m" },
			release.ErrNotesControlCharacter,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			raw := base
			tc.mutate(&raw)

			_, err := release.NewSubmission(raw)
			require.Error(t, err)
			if tc.wantIs != nil {
				require.ErrorIs(t, err, tc.wantIs)
			}
		})
	}
}

// TestNewSubmission_AcceptsWhatARealReleaseLooksLike — the floor is not a wall.
//
// A validation rule that refused a legitimate version would be a publish failure with no
// explanation anybody could act on, so the shapes a real plugin uses are asserted rather than
// assumed.
func TestNewSubmission_AcceptsWhatARealReleaseLooksLike(t *testing.T) {
	t.Parallel()

	for _, version := range []string{
		"1.0.0", "0.1", "2026.8.20", "1.0.0rc1", "1.0.0.dev1",
		"1!2.0", "1.0.0+local.1", "1.0.0-beta.2", "v1.0.0",
	} {
		t.Run(version, func(t *testing.T) {
			t.Parallel()

			sub, err := release.NewSubmission(release.RawSubmission{
				PluginID:       "merchant-mode",
				Version:        version,
				ArtifactURL:    "https://example.com/x.whl",
				ArtifactSHA256: strings.Repeat("a", 64),
				SDKSpecifier:   ">=1.0,<2",
			})
			require.NoError(t, err)
			require.Equal(t, version, sub.Version)
		})
	}
}

// TestNewSubmission_AnAbsentMinimumAppVersion_StaysAbsent.
//
// Nil and empty are different statements on the wire — the field is string-or-null and null means
// "no constraint" — but a workflow that interpolated an unset variable meant no constraint too.
func TestNewSubmission_AnAbsentMinimumAppVersion_StaysAbsent(t *testing.T) {
	t.Parallel()

	empty := ""
	set := " 1.2.0 "

	for _, tc := range []struct {
		name string
		in   *string
		want *string
	}{
		{"absent", nil, nil},
		{"empty", &empty, nil},
		{"set, and trimmed", &set, ptr("1.2.0")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			sub, err := release.NewSubmission(release.RawSubmission{
				PluginID:          "merchant-mode",
				Version:           "1.0.0",
				ArtifactURL:       "https://example.com/x.whl",
				ArtifactSHA256:    strings.Repeat("a", 64),
				SDKSpecifier:      ">=1.0,<2",
				MinimumAppVersion: tc.in,
			})
			require.NoError(t, err)
			require.Equal(t, tc.want, sub.MinimumAppVersion)
		})
	}
}

func ptr[T any](v T) *T { return &v }

// TestPublish_ACredentialBearingURL_NeverReachesTheColumn — end to end, at the layer that matters.
//
// release.artifact_url is rendered verbatim into the index and served to every client. The
// submission validator is what refuses these, and this asserts the consequence rather than the
// mechanism: whatever the shape, the row does not exist and there is nothing to publish.
//
// It goes through Publish rather than NewSubmission so that the assertion is about the DATABASE.
// A validator that was correct and a publish path that skipped it would pass the unit test and
// fail this one.
func TestPublish_ACredentialBearingURL_NeverReachesTheColumn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		url  string
	}{
		{"a signed cdn url", "https://cdn.example.com/x.whl?X-Amz-Signature=deadbeefcafe"},
		{"an azure sas", "https://a.blob.core.windows.net/c/x.whl?sv=2021-08-06&sig=abc123def"},
		{"a token in userinfo", "https://ghp_secrettoken@example.com/x.whl"},
		{"a fragment", "https://example.com/x.whl#sha256=deadbeefcafe"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			w := newWorld(t, []byte("PK\x03\x04 bytes"))

			// Refused at construction: the publish never happens, so the server never spends
			// forty-five seconds downloading on behalf of a request it was always going to reject.
			_, err := release.NewSubmission(release.RawSubmission{
				PluginID:       w.plugin,
				Version:        "1.0.0",
				ArtifactURL:    tc.url,
				ArtifactSHA256: w.truth(),
				SDKSpecifier:   ">=1.0,<2",
			})
			require.ErrorIs(t, err, artifact.ErrBadArtifactURL)

			// And nothing was written, so there is nothing for the index to render.
			require.Zero(t, w.releaseCount(t))
			require.Empty(t, w.storedURLs(t))
		})
	}
}

// TestPublish_TheStoredURL_IsExactlyWhatWasSubmitted — and it is query-free.
//
// The fetch follows redirects, and a GitHub release asset ends on a signed CDN url. What gets
// STORED is the submitted url, not where the redirect chain landed -- if the final url were
// stored, every listing would carry an expiring signature and the whole rule above would be
// pointless. This is the assertion that the two are not confused.
func TestPublish_TheStoredURL_IsExactlyWhatWasSubmitted(t *testing.T) {
	t.Parallel()

	w := newWorld(t, []byte("PK\x03\x04 bytes"))

	out, err := w.publish(t, w.submit(t, nil), "key-stored-url")
	require.NoError(t, err)

	row, err := w.db.Read().GetReleaseByID(t.Context(), out.ReleaseID)
	require.NoError(t, err)
	require.Equal(t, w.artifactURL(), row.ArtifactUrl)
	require.NotContains(t, row.ArtifactUrl, "?")
	require.NotContains(t, row.ArtifactUrl, "#")
	require.NotContains(t, row.ArtifactUrl, "@")
}
