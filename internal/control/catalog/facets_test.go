package catalog

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustAddr(value string) netip.Addr {
	return netip.MustParseAddr(value)
}

func testServers() []models.Server {
	return []models.Server{
		{
			VPN:        vpn.OpenVPN,
			Hostname:   "nl-1.example.com",
			ServerName: "nl-1",
			Number:     1,
			Country:    "Netherlands",
			Region:     "North Holland",
			City:       "Amsterdam",
			ISP:        "M247",
			Categories: []string{"standard"},
			TCP:        true,
			UDP:        true,
			Free:       true,
			Stream:     true,
			IPs:        []netip.Addr{mustAddr("198.51.100.1")},
			WgPubKey:   "public-key",
		},
		{
			VPN:        vpn.Wireguard,
			Hostname:   "de-2.example.com",
			ServerName: "de-2",
			Number:     2,
			Country:    "Germany",
			City:       "Berlin",
			ISP:        "M247",
			Categories: []string{"standard", "p2p"},
			Owned:      true,
			Premium:    true,
			Stream:     true,
		},
		{
			VPN:        vpn.Wireguard,
			Hostname:   "us-3.example.com",
			ServerName: "us-3",
			Number:     3,
			Country:    "United States",
			City:       "New York",
			ISP:        "Datacamp",
			Categories: []string{"standard"},
			Free:       true,
		},
	}
}

func Test_Candidate(t *testing.T) {
	t.Parallel()

	servers := testServers()

	openvpn := Candidate(servers[0])
	assert.Equal(t, "nl-1.example.com", openvpn.Hostname)
	assert.Equal(t, "nl-1", openvpn.Name)
	assert.Equal(t, "free", openvpn.Tier)
	assert.Equal(t, []string{"openvpn-udp", "openvpn-tcp"},
		openvpn.Protocols)
	assert.Equal(t, []string{"198.51.100.1"}, openvpn.IPs)
	assert.Equal(t, "public-key", openvpn.WGPublicKey)

	wireguard := Candidate(servers[1])
	assert.Equal(t, "premium", wireguard.Tier)
	assert.Equal(t, []string{"wireguard"}, wireguard.Protocols)
	assert.True(t, wireguard.Owned)
	assert.Nil(t, wireguard.IPs)
}

func Test_buildFacets(t *testing.T) {
	t.Parallel()

	facets := buildFacets(testServers())

	assert.Equal(t, []FacetValue{
		{Value: "Germany", Count: 1},
		{Value: "Netherlands", Count: 1},
		{Value: "United States", Count: 1},
	}, facets.Countries)
	assert.Equal(t, []FacetValue{
		{Value: "M247", Count: 2},
		{Value: "Datacamp", Count: 1},
	}, facets.ISPs)
	assert.Equal(t, []FacetValue{
		{Value: "standard", Count: 3},
		{Value: "p2p", Count: 1},
	}, facets.Categories)
	assert.Equal(t, []FacetValue{
		{Value: "free", Count: 2},
		{Value: "premium", Count: 1},
	}, facets.Tiers)
	assert.Equal(t, []FacetValue{
		{Value: "Amsterdam", Count: 1},
		{Value: "Berlin", Count: 1},
		{Value: "New York", Count: 1},
	}, facets.Cities)
	assert.Equal(t, []FacetValue{
		{Value: "North Holland", Count: 1},
	}, facets.Regions)
}

type fakeSource struct {
	servers []models.Server
	err     error
}

func (f fakeSource) Servers() ([]models.Server, error) {
	return f.servers, f.err
}

func Test_Catalog_Facets(t *testing.T) {
	t.Parallel()

	catalog := New(fakeSource{servers: testServers()})
	facets, err := catalog.Facets()
	require.NoError(t, err)
	assert.Len(t, facets.Countries, 3)

	empty := New(nil)
	facets, err = empty.Facets()
	require.NoError(t, err)
	assert.NotNil(t, facets.Countries)
	assert.Empty(t, facets.Countries)
}
