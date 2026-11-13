package catalog

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func duplicateProtocolServers() []models.Server {
	return []models.Server{
		{
			VPN:        vpn.OpenVPN,
			Hostname:   "br-1.example.com",
			ServerName: "br-1",
			Number:     1,
			Country:    "Brazil",
			Region:     "The Americas",
			City:       "Sao Paulo",
			Categories: []string{"standard"},
			TCP:        true,
			UDP:        true,
			IPs:        []netip.Addr{mustAddr("198.51.100.1")},
		},
		{
			VPN:        vpn.Wireguard,
			Hostname:   "br-1.example.com",
			ServerName: "br-1",
			Number:     1,
			Country:    "Brazil",
			Region:     "The Americas",
			City:       "Sao Paulo",
			Categories: []string{"standard"},
			IPs:        []netip.Addr{mustAddr("198.51.100.1")},
			WgPubKey:   "public-key",
		},
	}
}

func Test_Catalog_Query_MergesDuplicateHostnames(t *testing.T) {
	t.Parallel()

	catalog := New(fakeSource{servers: duplicateProtocolServers()})

	page, err := catalog.Query(Query{})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	candidate := page.Items[0]
	assert.Equal(t, []string{"openvpn-udp", "openvpn-tcp", "wireguard"},
		candidate.Protocols)
	assert.Equal(t, []string{"198.51.100.1"}, candidate.IPs)
	assert.Equal(t, "public-key", candidate.WGPublicKey)
	assert.Equal(t, 1, page.TotalEstimate)
}

func Test_Catalog_Query_ProtocolFilterKeepsWireGuard(t *testing.T) {
	t.Parallel()

	catalog := New(fakeSource{servers: duplicateProtocolServers()})

	page, err := catalog.Query(Query{Protocols: []string{"wireguard"}})
	require.NoError(t, err)
	require.Len(t, page.Items, 1)
	assert.Equal(t, []string{"wireguard"}, page.Items[0].Protocols)
	assert.Equal(t, "public-key", page.Items[0].WGPublicKey)
}

func Test_Catalog_Get_MergesDuplicateHostnames(t *testing.T) {
	t.Parallel()

	catalog := New(fakeSource{servers: duplicateProtocolServers()})

	candidate, found, err := catalog.Get("BR-1.example.com")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, "br-1.example.com", candidate.Hostname)
	assert.Equal(t, []string{"openvpn-udp", "openvpn-tcp", "wireguard"},
		candidate.Protocols)
	assert.Equal(t, []string{"198.51.100.1"}, candidate.IPs)
	assert.Equal(t, "public-key", candidate.WGPublicKey)
}

func Test_Catalog_Detail_ReportsEveryTransport(t *testing.T) {
	t.Parallel()

	catalog := New(fakeSource{servers: duplicateProtocolServers()})

	detail, found, err := catalog.Detail("br-1.example.com")
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, []string{"wireguard", "openvpn-udp", "openvpn-tcp"},
		detail.AvailableTransports)
}

func Test_Catalog_Facets_CountEachHostnameOnce(t *testing.T) {
	t.Parallel()

	catalog := New(fakeSource{servers: duplicateProtocolServers()})

	facets, err := catalog.Facets()
	require.NoError(t, err)
	assert.Equal(t, []FacetValue{{Value: "Brazil", Count: 1}},
		facets.Countries)
	assert.Equal(t, []FacetValue{{Value: "Sao Paulo", Count: 1}},
		facets.Cities)
}
