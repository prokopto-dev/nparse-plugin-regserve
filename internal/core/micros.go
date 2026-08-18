package core

import "time"

// Micros is a Unix timestamp in **microseconds**, UTC.
//
// It is the type of every `_at` column (canonical §2). Microseconds rather than nanoseconds
// because a nanosecond int64 runs out in 2262 and buys nothing here; microseconds rather than
// seconds because two releases submitted in the same second must still order.
//
// It is a distinct type from int64 so that a value read from a column cannot be handed to
// something expecting milliseconds without the compiler objecting. The conversion to and from
// time.Time happens here and at the API edge, and nowhere in between.
type Micros int64

// MicrosFromTime converts an instant to storage form. The caller supplies the instant, which is
// how CLOCK001 stays true: this package never reads the wall clock.
func MicrosFromTime(t time.Time) Micros {
	return Micros(t.UTC().UnixMicro())
}

// Time returns the instant, in UTC.
//
// UTC unconditionally: the zone a timestamp was written in is not stored, so returning anything
// else would be inventing information. Rendering in a local zone is a presentation decision made
// at the edge that needs it.
func (m Micros) Time() time.Time { return time.UnixMicro(int64(m)).UTC() }

// Int64 returns the raw column value.
func (m Micros) Int64() int64 { return int64(m) }
