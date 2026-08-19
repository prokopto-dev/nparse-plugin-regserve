package authz_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/prokopto-dev/nparse-plugin-regserve/internal/authz"
)

// The two spellings are different on purpose — a dot narrows a role, a colon narrows a token — and
// the whole point of separate types is that one cannot be passed where the other is meant. These
// tests pin the spellings so a permission written with a colon is caught at the declaration rather
// than at the comparison that silently never matches.

func TestPermission_Valid_AcceptsResourceDotAction(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   authz.Permission
		want bool
	}{
		{name: "resource.action", in: "plugin.publish", want: true},
		{name: "underscored action", in: "owner.manage_transfer", want: true},
		{name: "digits after a letter", in: "plugin2.publish", want: true},
		{name: "empty", in: "", want: false},
		{name: "no action", in: "plugin", want: false},
		{name: "scope spelling", in: "plugin:publish", want: false},
		{name: "uppercase", in: "Plugin.Publish", want: false},
		{name: "leading digit", in: "2plugin.publish", want: false},
		{name: "trailing dot", in: "plugin.", want: false},
		{name: "three parts", in: "plugin.release.publish", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, tt.in.Valid(), "permission %q", tt.in)
		})
	}
}

func TestScope_Valid_AcceptsFamilyColonVerb(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   authz.Scope
		want bool
	}{
		{name: "family:verb", in: "plugin:publish", want: true},
		{name: "underscored verb", in: "plugin:read_all", want: true},
		{name: "empty", in: "", want: false},
		{name: "permission spelling", in: "plugin.publish", want: false},
		{name: "wildcard", in: "admin:*", want: false},
		{name: "uppercase", in: "Plugin:Publish", want: false},
		{name: "no verb", in: "plugin:", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, tt.in.Valid(), "scope %q", tt.in)
		})
	}
}

func TestPermissionAndScope_String_RoundTrips(t *testing.T) {
	t.Parallel()

	require.Equal(t, "plugin.publish", authz.Permission("plugin.publish").String())
	require.Equal(t, "plugin:publish", authz.Scope("plugin:publish").String())
}
