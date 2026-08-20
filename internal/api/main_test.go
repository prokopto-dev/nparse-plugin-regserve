package api_test

import (
	"testing"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/store/storetest"
)

// TestMain is here because the capability-floor test builds a real database rather than a fake
// principal. storetest.Main removes the template database afterwards and then runs the
// goroutine-leak check — an httptest server or a connection that outlives its test shows up there,
// which is the point of finding it in CI rather than in a flaky suite.
func TestMain(m *testing.M) { storetest.Main(m) }
