package source

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_HostIPs_configured(t *testing.T) {
	t.Parallel()

	hostIPs, err := HostIPs(false, netip.MustParseAddr("198.18.0.9"))
	require.NoError(t, err)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("198.18.0.9")}, hostIPs)

	_, err = HostIPs(false, netip.Addr{})
	assert.Error(t, err)
}

func Test_HostIPs_automatic(t *testing.T) {
	t.Parallel()

	hostIPs, err := HostIPs(true, netip.Addr{})
	require.NoError(t, err)

	seen := make(map[netip.Addr]struct{}, len(hostIPs))
	for _, ip := range hostIPs {
		assert.True(t, ip.IsValid())
		assert.True(t, ip.IsGlobalUnicast())
		assert.False(t, ip.IsLoopback())
		assert.False(t, ip.IsLinkLocalUnicast())
		assert.False(t, ip.Is4In6())
		_, duplicate := seen[ip]
		assert.False(t, duplicate, "duplicate host IP %s", ip)
		seen[ip] = struct{}{}
	}
}
