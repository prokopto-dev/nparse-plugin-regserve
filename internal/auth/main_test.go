package auth_test

import (
	"testing"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// TestMain runs the goroutine-leak check after the suite. Every test in this package opens a real
// SQLite database — there are no mocks of the database anywhere in this repository — so a leak here
// is a connection nobody closed.
func TestMain(m *testing.M) { storetest.Main(m) }
