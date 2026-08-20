package release

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// The version comparison, and especially the cases where it must answer I DO NOT KNOW.
//
// An internal test because the function is deliberately unexported: it is not a PEP 440
// implementation and must never be mistaken for one. The client evaluates version semantics; this
// answers the single narrower question the quarantine rule asks, and is allowed to decline.

func TestCompareVersions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		current, candidate string
		want               versionOrder
	}{
		// The ordinary advances. These are what almost every publish looks like.
		{name: "patch bump", current: "1.0.0", candidate: "1.0.1", want: versionHigher},
		{name: "minor bump", current: "1.0.9", candidate: "1.1.0", want: versionHigher},
		{name: "major bump", current: "1.9.9", candidate: "2.0.0", want: versionHigher},
		{name: "double digits sort numerically, not lexically", current: "1.9.0", candidate: "1.10.0", want: versionHigher},
		{name: "a leading v is decoration", current: "v1.0.0", candidate: "v1.0.1", want: versionHigher},
		{name: "mixed decoration", current: "1.0.0", candidate: "v1.0.1", want: versionHigher},
		{name: "a date scheme", current: "2026.8.19", candidate: "2026.8.20", want: versionHigher},
		{name: "fewer components on the left", current: "1.2", candidate: "1.2.1", want: versionHigher},

		// The regressions. Each of these is a downgrade: ship an old number with new bytes and a
		// client comparing version strings believes it is up to date.
		{name: "the same version", current: "1.0.0", candidate: "1.0.0", want: versionEqual},
		{name: "trailing zeros are the same version", current: "1.2", candidate: "1.2.0", want: versionEqual},
		{name: "a patch backwards", current: "1.0.1", candidate: "1.0.0", want: versionLower},
		{name: "a major backwards", current: "2.0.0", candidate: "1.9.9", want: versionLower},
		{name: "double digits backwards", current: "1.10.0", candidate: "1.9.0", want: versionLower},

		// The epoch: a deliberate restart of a numbering scheme, which outranks everything without
		// one. Getting this backwards would quarantine every release after a renumbering.
		{name: "an epoch outranks no epoch", current: "2.0", candidate: "1!1.0", want: versionHigher},
		{name: "and going back below one is a regression", current: "1!1.0", candidate: "2.0", want: versionLower},
		{name: "within one epoch, the numbers decide", current: "1!1.0", candidate: "1!1.1", want: versionHigher},

		// THE DECLINED CASES. Each has an answer under PEP 440 and none of them is one this
		// service should be deciding — so each sends the release to a human instead.
		{name: "a release candidate against its release", current: "1.0.0", candidate: "1.0.0rc1", want: versionUnknown},
		{name: "a release against its own candidate", current: "1.0.0rc1", candidate: "1.0.0", want: versionUnknown},
		{name: "alpha against beta", current: "1.0.0a1", candidate: "1.0.0b2", want: versionUnknown},
		{name: "a local version", current: "1.0.0", candidate: "1.0.0+local.1", want: versionUnknown},
		{name: "a dev release", current: "1.0.0", candidate: "1.0.0.dev1", want: versionUnknown},
		{name: "a hyphenated pre-release", current: "1.0.0", candidate: "1.0.0-beta.2", want: versionUnknown},
		{name: "no numeric spine at all", current: "stable", candidate: "latest", want: versionUnknown},
		{name: "a git sha", current: "1.0.0", candidate: "deadbeef", want: versionUnknown},
		{name: "an unparseable epoch", current: "1.0", candidate: "x!1.0", want: versionUnknown},
		{name: "empty", current: "", candidate: "1.0.0", want: versionUnknown},

		// A pre-release still compares when the NUMBERS already differ. `1.2.0rc1` beats `1.1.0`
		// whatever `rc1` means, and declining here would quarantine every release-candidate
		// workflow for no reason.
		{name: "a candidate that is clearly ahead", current: "1.1.0", candidate: "1.2.0rc1", want: versionHigher},
		{name: "a candidate that is clearly behind", current: "1.2.0", candidate: "1.1.0rc1", want: versionLower},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, compareVersions(tc.current, tc.candidate),
				"comparing %q against %q", tc.current, tc.candidate)
		})
	}
}

// TestCompareVersions_TheZeroValueIsTheSafeAnswer.
//
// versionUnknown is iota, so a versionOrder nobody assigned reads as "I do not know" and sends the
// release to review. If versionEqual or versionHigher were first, a forgotten assignment somewhere
// would publish something automatically.
func TestCompareVersions_TheZeroValueIsTheSafeAnswer(t *testing.T) {
	t.Parallel()

	var unset versionOrder
	require.Equal(t, versionUnknown, unset,
		"the zero versionOrder must be the answer that sends a release to a human")
}
