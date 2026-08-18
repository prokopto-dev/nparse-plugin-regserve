package core_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
)

// TestMicros_RoundTrip_PreservesInstantAndZone — every `_at` column goes through this conversion,
// so an error here is an error in every timestamp the service stores.
//
// The zone assertion is the one that matters: a value that round-trips to the same instant in a
// local zone still renders differently on the wire, and that bug only appears for people who are
// not in the deployer's timezone.
func TestMicros_RoundTrip_PreservesInstantAndZone(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   time.Time
		want core.Micros
	}{
		{"the epoch", time.Unix(0, 0).UTC(), 0},
		{"a whole second", time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC), 1787054400_000000},
		{"microsecond precision survives", time.Date(2026, 8, 18, 12, 0, 0, 123456000, time.UTC), 1787054400_123456},
		{"a non-UTC zone is normalised", time.Date(2026, 8, 18, 12, 0, 0, 0, time.FixedZone("east", 3600)), 1787050800_000000},
		{"before the epoch", time.Date(1969, 12, 31, 23, 59, 59, 0, time.UTC), -1_000000},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := core.MicrosFromTime(tc.in)
			require.Equal(t, tc.want, got)
			require.Equal(t, int64(tc.want), got.Int64())

			back := got.Time()
			require.True(t, back.Equal(tc.in), "%s did not round-trip: got %s", tc.in, back)
			require.Equal(t, time.UTC, back.Location(), "a stored timestamp reads back in UTC or not at all")
		})
	}
}

// TestMicros_SubMicrosecondPrecision_Truncates — nanoseconds are not stored, and a caller that
// hands one over gets the truncation the column implies rather than a rounded value that would
// order two rows differently from the order they were written in.
func TestMicros_SubMicrosecondPrecision_Truncates(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 8, 18, 12, 0, 0, 999, time.UTC) // 999 nanoseconds
	got := core.MicrosFromTime(at)

	require.Equal(t, core.Micros(1787054400_000000), got)
	require.Empty(t, cmp.Diff(time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC), got.Time()))
}
