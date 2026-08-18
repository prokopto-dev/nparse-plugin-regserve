package store_test

import (
	"testing"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// TestMain runs the goroutine-leak check after the suite. A leaked goroutine here is almost always
// a database connection nobody closed, which in production is a file handle and a lock held past
// the request that took it.
func TestMain(m *testing.M) { storetest.Main(m) }
