package guard

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// The address policy, asserted directly.
//
// It is tested here rather than through a socket because the interesting cases cannot be dialled:
// 169.254.169.254 either does not answer or, on a cloud host, answers with credentials. A table
// over the decision function is the only way to check every category, and the categories are the
// whole point — a CIDR list is a list somebody has to remember to extend.

func TestBlocked_RefusesEverythingNotOnThePublicInternet(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		addr string
		want bool
		why  string
	}{
		{name: "loopback v4", addr: "127.0.0.1", want: true, why: "the service itself, and every other service on the box"},
		{name: "loopback v6", addr: "::1", want: true, why: "as above"},
		{name: "ipv4-mapped loopback", addr: "::ffff:127.0.0.1", want: true, why: "the same address in a spelling Is4 answers false to"},
		{name: "unspecified v4", addr: "0.0.0.0", want: true, why: "routes to localhost on most stacks"},
		{name: "unspecified v6", addr: "::", want: true, why: "as above"},
		{name: "private 10/8", addr: "10.0.0.5", want: true, why: "the droplet's private network"},
		{name: "private 172.16/12", addr: "172.20.0.3", want: true, why: "the docker bridge this container is on"},
		{name: "private 192.168/16", addr: "192.168.1.1", want: true, why: "a home router's admin page"},
		{name: "unique local v6", addr: "fd00::1", want: true, why: "the v6 equivalent of private"},
		{name: "cloud metadata", addr: "169.254.169.254", want: true, why: "hands out credentials to anything that can reach it"},
		{name: "alibaba metadata", addr: "100.100.100.200", want: true, why: "metadata, and NOT link-local, so it needs naming"},
		{name: "aws imds over v6", addr: "fd00:ec2::254", want: true, why: "metadata over v6"},
		{name: "link-local v4", addr: "169.254.10.1", want: true, why: "the range cloud metadata lives in"},
		{name: "link-local v6", addr: "fe80::1", want: true, why: "as above"},
		{name: "multicast v4", addr: "224.0.0.1", want: true, why: "not a host"},
		{name: "multicast v6", addr: "ff02::1", want: true, why: "not a host"},
		{name: "carrier-grade nat", addr: "100.64.0.1", want: true, why: "neither private nor link-local by Go's definitions, and where a provider's internals sit"},
		{name: "carrier-grade nat top", addr: "100.127.255.255", want: true, why: "the end of 100.64.0.0/10"},

		{name: "a public v4 address", addr: "140.82.121.4", want: false, why: "github.com; the whole point is that this works"},
		{name: "a public v6 address", addr: "2606:50c0:8000::153", want: false, why: "as above"},
		{name: "just outside cgnat", addr: "100.128.0.1", want: false, why: "100.128/9 is ordinary public space; over-blocking is a bug too"},
		{name: "just below cgnat", addr: "100.63.255.255", want: false, why: "as above"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := blocked(netip.MustParseAddr(tt.addr), false)
			require.Equal(t, tt.want, got, "%s (%s): %s", tt.name, tt.addr, tt.why)
		})
	}
}

// TestBlocked_PermitLoopback_WidensNothingElse — the test escape hatch is exactly one category.
//
// PermitLoopback exists so a test can point this client at an httptest server. If it widened the
// policy any further, every test using it would be testing a client that is not the one production
// builds — and the private and metadata ranges are the ones that matter.
func TestBlocked_PermitLoopback_WidensNothingElse(t *testing.T) {
	t.Parallel()

	require.False(t, blocked(netip.MustParseAddr("127.0.0.1"), true),
		"a test must be able to dial its own httptest server")

	for _, addr := range []string{
		"10.0.0.5", "192.168.1.1", "169.254.169.254", "100.100.100.200", "fd00::1", "224.0.0.1",
	} {
		require.True(t, blocked(netip.MustParseAddr(addr), true),
			"PermitLoopback must not unblock %s", addr)
	}
}

// TestControl_RefusesWhatItCannotCheck — an unparseable address is refused, not waved through.
//
// The Control hook is called with a literal address, so a name arriving here means the resolver
// handed us something this code does not understand. "We do not know what this is" has exactly one
// safe reading.
func TestControl_RefusesWhatItCannotCheck(t *testing.T) {
	t.Parallel()

	check := control(false)

	require.ErrorIs(t, check("udp", "140.82.121.4:443", nil), ErrBlockedAddress,
		"only tcp is dialled; a guard that forgot udp is a guard with a hole shaped like udp")
	require.ErrorIs(t, check("tcp", "not-an-address:443", nil), ErrBlockedAddress)
	require.NoError(t, check("tcp4", "140.82.121.4:443", nil))
}
