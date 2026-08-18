// Package clock is the only place in this repository that may call time.Now.
//
// Gate CLOCK001 enforces that. The rule is not fussiness: publish decisions, token expiry and
// quarantine windows are all time-dependent, and a test that cannot control the clock either
// sleeps — making the suite slow and flaky — or asserts nothing about the boundary it exists to
// check.
package clock

import "time"

// Clock is the injected source of time. Every service takes one.
type Clock interface {
	Now() time.Time
}

// System is the real clock. It is the only implementation permitted to call time.Now.
type System struct{}

// Now returns the current time in UTC.
//
// UTC at the boundary, always: the database stores microseconds since the epoch, and a local-zone
// value that round-trips through a formatter somewhere in between is a bug that only appears for
// people who are not in the deployer's timezone.
func (System) Now() time.Time { return time.Now().UTC() }

// Fixed is a clock frozen at a chosen instant, for tests.
type Fixed struct {
	T time.Time
}

// Now returns the fixed instant.
func (f Fixed) Now() time.Time { return f.T.UTC() }

var (
	_ Clock = System{}
	_ Clock = Fixed{}
)
