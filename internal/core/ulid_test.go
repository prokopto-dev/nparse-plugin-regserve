package core_test

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/core"
)

// TestNewULID_SameMillisecond_IdsDiffer — the 80 random bits are what make an id unguessable, and
// a generator that returned the timestamp alone would produce collisions on the primary key of
// every table the moment two releases were submitted together.
func TestNewULID_SameMillisecond_IdsDiffer(t *testing.T) {
	t.Parallel()

	at := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)

	seen := make(map[core.ULID]struct{}, 1000)
	for range 1000 {
		id, err := core.NewULID(at)
		require.NoError(t, err)
		require.Len(t, id.String(), core.ULIDLen)

		_, dup := seen[id]
		require.False(t, dup, "two ids minted in the same millisecond collided: %s", id)
		seen[id] = struct{}{}
	}
}

// TestNewULID_LaterInstant_SortsAfter — lexicographic order is creation order.
//
// This is the property the schema leans on: a plain ORDER BY on a TEXT primary key is an ordering
// by time, and an index on it appends rather than fragmenting. Lose it and every "the most recent
// row" query silently returns an arbitrary one.
func TestNewULID_LaterInstant_SortsAfter(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	var ids []string
	for _, offset := range []time.Duration{0, time.Millisecond, time.Second, time.Hour, 400 * 24 * time.Hour} {
		id, err := core.NewULID(base.Add(offset))
		require.NoError(t, err)
		ids = append(ids, id.String())
	}

	sorted := make([]string, len(ids))
	copy(sorted, ids)
	sort.Strings(sorted)
	require.Equal(t, ids, sorted, "ids did not sort into the order they were created in")
}

// TestNewULID_RoundTripsThroughParse — anything the generator emits must be accepted by the
// validator, or a row this service wrote could not be read back through its own boundary.
func TestNewULID_RoundTripsThroughParse(t *testing.T) {
	t.Parallel()

	for _, at := range []time.Time{
		time.UnixMilli(0).UTC(),
		time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC),
		time.UnixMilli(int64(1)<<48 - 1).UTC(), // the last instant a 48-bit timestamp can hold
	} {
		id, err := core.NewULID(at)
		require.NoError(t, err)

		got, err := core.ParseULID(id.String())
		require.NoError(t, err, "generator emitted %q, which its own parser rejects", id)
		require.Equal(t, id, got)
	}
}

// TestNewULID_OutsideTheTimestampRange_Rejected — truncating an out-of-range instant would mint an
// id that sorts before ids created years earlier, which is worse than refusing.
func TestNewULID_OutsideTheTimestampRange_Rejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		at   time.Time
	}{
		{"before the epoch", time.Date(1969, 1, 1, 0, 0, 0, 0, time.UTC)},
		{"past the 48-bit ceiling", time.UnixMilli(int64(1) << 48).UTC()},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := core.NewULID(tc.at)
			require.ErrorIs(t, err, core.ErrInvalidULID)
		})
	}
}

func TestParseULID_Invalid_Rejected(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"too short", "01JQ8"},
		{"too long", "01ARZ3NDEKTSV4RRFFQ69G5FAVX"},
		{"lowercase", "01arz3ndektsv4rrffq69g5fav"},
		{"letter I is not in the alphabet", "01ARZ3NDEKTSV4RRFFQ69G5FAI"},
		{"letter L is not in the alphabet", "01ARZ3NDEKTSV4RRFFQ69G5FAL"},
		{"letter O is not in the alphabet", "01ARZ3NDEKTSV4RRFFQ69G5FAO"},
		{"letter U is not in the alphabet", "01ARZ3NDEKTSV4RRFFQ69G5FAU"},
		{"overflows 128 bits", "81ARZ3NDEKTSV4RRFFQ69G5FAV"},
		{"a plugin id is not a ULID", "merchant-mode"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := core.ParseULID(tc.in)
			require.ErrorIs(t, err, core.ErrInvalidULID)
		})
	}
}

// TestParseULID_KnownVector_Accepted — the alphabet and length are pinned against a ULID from the
// specification rather than against our own encoder, which would agree with itself either way.
func TestParseULID_KnownVector_Accepted(t *testing.T) {
	t.Parallel()

	got, err := core.ParseULID("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	require.NoError(t, err)
	require.Equal(t, "01ARZ3NDEKTSV4RRFFQ69G5FAV", got.String())
}
