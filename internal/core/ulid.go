package core

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// ErrInvalidULID is returned by ParseULID for anything that is not a canonical 26-character
// Crockford base32 ULID.
var ErrInvalidULID = errors.New("invalid ULID")

// ULIDLen is the encoded length: 130 bits of base32 over 128 bits of value, two of which are the
// leading zeroes that make the division exact.
const ULIDLen = 26

// crockford is Crockford's base32 alphabet: the digits and the uppercase letters minus I, L, O
// and U. The exclusions are the point — an id read aloud or copied out of a log cannot turn a 1
// into an I, and U is dropped so that no accidental obscenity appears in an identifier a user
// might see.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// ULID is an internal primary key: a 48-bit millisecond timestamp followed by 80 bits from
// crypto/rand, in Crockford base32 (canonical §3).
//
// The timestamp is leading and big-endian, so lexicographic order on the TEXT column is creation
// order — which is what makes a plain `ORDER BY id` on a table of releases mean something, and
// what stops an index on a random key fragmenting. The 80 random bits come from crypto/rand
// because an id that can be predicted is an id that can be probed for.
type ULID string

// maxULIDMillis is what a 48-bit timestamp can hold: 10889-08-02. A time beyond it is a bug in the
// caller's clock, not something to silently truncate into a smaller, earlier id.
const maxULIDMillis = int64(1)<<48 - 1

// NewULID builds a ULID for the instant now.
//
// The instant is a parameter rather than a call to time.Now, which is what keeps CLOCK001 true and
// what lets a test assert that two ids minted in the same millisecond still differ.
func NewULID(now time.Time) (ULID, error) {
	ms := now.UTC().UnixMilli()
	if ms < 0 || ms > maxULIDMillis {
		return "", fmt.Errorf("%w: %s is outside the 48-bit timestamp range", ErrInvalidULID,
			now.UTC().Format(time.RFC3339))
	}

	// The timestamp is the leading 48 bits, big-endian, which is what makes the encoded id sort by
	// time. PutUint64 writes eight bytes and the top two are zero by the range check above, so the
	// low six are exactly the 48 bits wanted.
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(ms)) //nolint:gosec // G115: ms is range-checked above
	var b [16]byte
	copy(b[:6], ts[2:])

	// crypto/rand.Read never returns a short read, and an error here means the operating system's
	// entropy source failed. That is not a condition to paper over with a fallback: every id in
	// this database is either unguessable or it is not.
	if _, err := rand.Read(b[6:]); err != nil {
		return "", fmt.Errorf("read randomness for a ULID: %w", err)
	}
	return ULID(encodeULID(b)), nil
}

// ParseULID validates s. It is the only way a string from outside becomes a ULID.
func ParseULID(s string) (ULID, error) {
	if len(s) != ULIDLen {
		return "", fmt.Errorf("%w: %q is %d characters, not %d", ErrInvalidULID, s, len(s), ULIDLen)
	}
	// The first character carries only three significant bits, so anything above '7' encodes a
	// value wider than 128 bits. Accepting one would produce an id that cannot round-trip.
	if s[0] > '7' {
		return "", fmt.Errorf("%w: %q overflows 128 bits", ErrInvalidULID, s)
	}
	for i := 0; i < len(s); i++ {
		// Uppercase only. Crockford's decoder is case-insensitive, but accepting both spellings
		// would make two rows with visually different primary keys refer to the same id, and
		// SQLite's default TEXT comparison is case-sensitive, so they would both be stored.
		if !isCrockford(s[i]) {
			return "", fmt.Errorf("%w: %q contains %q", ErrInvalidULID, s, s[i])
		}
	}
	return ULID(s), nil
}

// String returns the id as a plain string.
func (u ULID) String() string { return string(u) }

func isCrockford(c byte) bool {
	for i := 0; i < len(crockford); i++ {
		if crockford[i] == c {
			return true
		}
	}
	return false
}

// encodeULID renders 128 bits as 26 base32 characters.
//
// It feeds bits through a small accumulator rather than unrolling 26 hand-written index
// expressions: 130 is 26 groups of five exactly once two leading zero bits are prepended, and a
// loop that says so is checkable by reading it.
func encodeULID(b [16]byte) string {
	var out [ULIDLen]byte

	acc, nbits := uint32(0), uint(2) // the two leading zero bits
	i := 0
	for _, by := range b {
		acc = acc<<8 | uint32(by)
		nbits += 8
		for nbits >= 5 {
			nbits -= 5
			out[i] = crockford[(acc>>nbits)&0x1f]
			i++
		}
	}
	return string(out[:])
}
