package review_test

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/review"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store"
	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/sqlitegen"
)

// TestIsReviewer_ResolvesThroughAProvenIdentity.
//
// A configured handle grants nothing until somebody has AUTHENTICATED as it. That is the same rule
// ownership.Add keeps and it is kept for the same reason: a grant to a name nobody has proved they
// hold is a grant to whoever registers that name next.
func TestIsReviewer_ResolvesThroughAProvenIdentity(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	tests := []struct {
		name      string
		configure []string
		account   func() string
		want      bool
	}{
		{
			name:      "a configured handle somebody has signed in with",
			configure: []string{"themaintainer"},
			account:   func() string { return w.reviewer },
			want:      true,
		},
		{
			// GitHub compares handles case-insensitively and so did owners.json. An operator
			// writing TheMaintainer means the person, not a queue nobody can reach.
			name:      "the same handle in a different case",
			configure: []string{"TheMaintainer"},
			account:   func() string { return w.reviewer },
			want:      true,
		},
		{
			name:      "a handle written the way people write them",
			configure: []string{"  @themaintainer  "},
			account:   func() string { return w.reviewer },
			want:      true,
		},
		{
			name:      "an account that is not configured",
			configure: []string{"themaintainer"},
			account:   func() string { return w.owner },
			want:      false,
		},
		{
			// THE DEFAULT, and it must never be "everybody". A service that opened moderation
			// because a variable was unset would be the worst possible reading of a missing value.
			name:      "nobody configured",
			configure: nil,
			account:   func() string { return w.reviewer },
			want:      false,
		},
		{
			name:      "a configured handle nobody has signed in with",
			configure: []string{"a-name-nobody-holds"},
			account:   func() string { return w.reviewer },
			want:      false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := review.NewReviewers(w.db, tc.configure).IsReviewer(t.Context(), tc.account())
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestIsReviewer_OnlyGitHubIdentitiesCount.
//
// The configured list is GitHub handles. Matching across providers would let somebody who happens
// to hold the same name elsewhere moderate this registry — which is exactly the confusion the
// (provider, subject) identity model exists to remove.
func TestIsReviewer_OnlyGitHubIdentitiesCount(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	// A non-github identity is not something the API can create today — identity_provider.kind is
	// a CHECK against 'github'. Asserting the account resolves through provider_kind at all is the
	// half that is testable, and it is the half that would break if somebody matched on handle
	// alone.
	rows, err := w.db.Read().ListHandlesForAccount(t.Context(), w.reviewer)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	require.Equal(t, "github", rows[0].ProviderKind)

	got, err := review.NewReviewers(w.db, []string{"themaintainer"}).IsReviewer(t.Context(), w.reviewer)
	require.NoError(t, err)
	require.True(t, got)
}

// TestIsReviewer_ReadsPerRequest.
//
// An account that signs in after boot is recognised without a restart, and an operator removing a
// handle takes effect on the next call. Resolving the list to account ids at startup would make
// both of those need a redeploy, and the second is the one that matters during an incident.
func TestIsReviewer_ReadsPerRequest(t *testing.T) {
	t.Parallel()

	w := newWorld(t)
	reviewers := review.NewReviewers(w.db, []string{"latecomer"})

	// Nobody holds that handle yet.
	got, err := reviewers.IsReviewer(t.Context(), w.owner)
	require.NoError(t, err)
	require.False(t, got)

	// The account links the identity afterwards, as a first sign-in would.
	require.NoError(t, w.db.Tx(t.Context(), func(q *store.Queries) error {
		return q.InsertIdentity(t.Context(), sqlitegen.InsertIdentityParams{
			ID:           "01ARZ3NDEKTSV4RRFFQ69G5FYY",
			AccountID:    w.owner,
			ProviderKind: "github",
			Subject:      "sub-latecomer",
			Handle:       "latecomer",
			LinkedAt:     1,
			RefreshedAt:  1,
		})
	}))

	got, err = reviewers.IsReviewer(t.Context(), w.owner)
	require.NoError(t, err)
	require.True(t, got, "the same Reviewers must see an identity linked after it was built")
}

// TestParseHandleList_TakesWhatAnOperatorWrites.
func TestParseHandleList_TakesWhatAnOperatorWrites(t *testing.T) {
	t.Parallel()

	tests := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"   ", 0},
		{"alice", 1},
		{"alice,bob", 2},
		{" alice , bob ", 2},
		{"alice,,bob", 2},
		{"alice,bob,", 2}, // a trailing comma is a typo, not a grant
		{"@alice, @bob", 2},
	}

	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			require.Len(t, review.ParseHandleList(tc.in), tc.want)
		})
	}
}

// TestNewReviewers_AnEmptySetMeansNobody — asserted directly, because the alternative reading of a
// missing value is catastrophic and one careless refactor away.
func TestNewReviewers_AnEmptySetMeansNobody(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	for _, configured := range [][]string{nil, {}, {""}, {"   "}, {"@"}} {
		reviewers := review.NewReviewers(w.db, configured)
		require.Zero(t, reviewers.Count())

		for _, account := range []string{w.owner, w.reviewer, ""} {
			got, err := reviewers.IsReviewer(t.Context(), account)
			require.NoError(t, err)
			require.False(t, got, "an empty reviewer set admitted somebody")
		}
	}
}

// TestReviewers_Configured_SeparatesNobodyMayReviewFromYouMayNot.
//
// The two are the same answer from IsReviewer, the same missing link on a page and the same empty
// queue -- and only one of them is a broken deployment. Configured is what tells them apart, so it
// is asserted over the same shapes an operator can actually leave REGSERVE_REVIEWERS in.
func TestReviewers_Configured_SeparatesNobodyMayReviewFromYouMayNot(t *testing.T) {
	t.Parallel()

	w := newWorld(t)

	for _, handles := range [][]string{nil, {}, {""}, {"   "}, {"@"}} {
		require.False(t, review.NewReviewers(w.db, handles).Configured(),
			"%q names nobody and must not read as a configured registry", handles)
	}

	configured := review.NewReviewers(w.db, review.ParseHandleList("themaintainer"))
	require.True(t, configured.Configured())

	// And it is a fact about the CONFIGURATION, not about any account: a handle nobody has signed
	// in with still means somebody may review, and it must not read as an unconfigured registry
	// just because the one caller asking is not that person.
	got, err := configured.IsReviewer(t.Context(), w.owner)
	require.NoError(t, err)
	require.False(t, got)
	require.True(t, configured.Configured())
}

// TestLogConfiguration_NoReviewersAndAnEmptyQueue_IsStillAWarning.
//
// The level is the assertion, and it is the defect: this case used to be logged at Info. A
// deployment that has never set REGSERVE_REVIEWERS -- which the compose file defaults to empty, so
// it is the ordinary one -- announced "nothing can ever be approved" at the level operators filter
// out, and an empty queue is not evidence the setting is fine. It is what an unreachable queue
// looks like.
//
// NOT parallel: it replaces the default slog handler, which is process-wide. Go releases the
// parallel tests in a package only once the sequential ones have finished, so this does not
// overlap them; the cleanup puts the original back either way.
func TestLogConfiguration_NoReviewersAndAnEmptyQueue_IsStillAWarning(t *testing.T) {
	w := newWorld(t)

	tests := []struct {
		name     string
		handles  []string
		pending  int64
		wantWarn bool
	}{
		{name: "nobody configured, nothing waiting", wantWarn: true},
		{name: "nobody configured, a backlog", pending: 3, wantWarn: true},
		{name: "somebody configured", handles: []string{"themaintainer"}, pending: 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			logged := captureLogs(t)
			review.NewReviewers(w.db, tc.handles).LogConfiguration(t.Context(), tc.pending)

			line := logged()
			require.NotEmpty(t, line, "boot must say what moderation this instance can do")

			if !tc.wantWarn {
				require.NotContains(t, line, `"level":"WARN"`,
					"a configured registry is not a fault and must not warn about itself")
				return
			}

			require.Contains(t, line, `"level":"WARN"`,
				"a registry nobody can moderate must be loud at boot")
			require.Contains(t, line, review.EnvVar(),
				"the warning has to name the variable that fixes it")
		})
	}
}

// captureLogs redirects the default logger into a buffer for the duration of one test and hands
// back a reader for what it collected.
func captureLogs(t *testing.T) func() string {
	t.Helper()

	var buf bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })

	return buf.String
}
