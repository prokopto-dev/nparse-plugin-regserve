package api

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/auth"
)

// TestCallbackInput_StateCookieTag_MatchesAuth — the one duplicated string, pinned.
//
// Huma reads a cookie from a struct tag, and a struct tag has to be a literal. That puts the cookie
// name in two places: here and internal/auth. The failure if they drift is silent — the callback
// simply never sees the cookie, and every login fails with "this sign-in did not start in this
// browser", which reads as a bug in the state check rather than as a typo in a tag.
//
// An internal test because the input type is unexported, and exporting one for a test would be a
// worse trade than a second file.
func TestCallbackInput_StateCookieTag_MatchesAuth(t *testing.T) {
	t.Parallel()

	field, ok := reflect.TypeOf(callbackInput{}).FieldByName("StateCookie")
	require.True(t, ok, "the callback must read the state cookie from a tagged field")
	require.Equal(t, auth.OAuthStateCookieName, field.Tag.Get("cookie"))
}
