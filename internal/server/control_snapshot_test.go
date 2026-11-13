package server

import (
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_applySnapshotToSettings_PinnedHostnameOverridesLocationFilters(t *testing.T) {
	t.Parallel()

	const pinnedHostname = "us12912.nordvpn.com"
	pinnedEndpoint := netip.MustParseAddr("187.13.209.214")

	testCases := map[string]struct {
		snapshot           state.TunnelSnapshot
		expectedCountries  []string
		expectedRegions    []string
		expectedCities     []string
		expectedISPs       []string
		expectedCategories []string
		expectedVPNType    string
		expectedSelection  string
		expectedProtocol   string
		expectedHostnames  []string
		expectedEndpointIP netip.Addr
	}{
		"wireguard_target_clears_stale_brazil_filters": {
			snapshot: state.TunnelSnapshot{
				Settings: state.TunnelSettings{
					Hostnames: []string{pinnedHostname},
				},
				ServerHostname:  pinnedHostname,
				EndpointIP:      pinnedEndpoint,
				Transport:       vpn.Wireguard,
				TransportDetail: vpn.Wireguard,
			},
			expectedVPNType:    vpn.Wireguard,
			expectedSelection:  vpn.Wireguard,
			expectedHostnames:  []string{pinnedHostname},
			expectedEndpointIP: pinnedEndpoint,
		},
		"snapshot_location_filters_are_authoritative": {
			snapshot: state.TunnelSnapshot{
				Settings: state.TunnelSettings{
					Countries: []string{"United States"},
					Cities:    []string{"New York"},
					Hostnames: []string{pinnedHostname},
				},
				ServerHostname:  pinnedHostname,
				EndpointIP:      pinnedEndpoint,
				Transport:       vpn.Wireguard,
				TransportDetail: vpn.Wireguard,
			},
			expectedCountries:  []string{"United States"},
			expectedCities:     []string{"New York"},
			expectedVPNType:    vpn.Wireguard,
			expectedSelection:  vpn.Wireguard,
			expectedHostnames:  []string{pinnedHostname},
			expectedEndpointIP: pinnedEndpoint,
		},
		"openvpn_tcp_target_sets_protocol_and_clears_filters": {
			snapshot: state.TunnelSnapshot{
				Settings: state.TunnelSettings{
					Hostnames: []string{"br53.nordvpn.com"},
				},
				ServerHostname:  "br53.nordvpn.com",
				EndpointIP:      netip.MustParseAddr("177.54.151.174"),
				Transport:       vpn.OpenVPN,
				TransportDetail: "openvpn-tcp",
			},
			expectedVPNType:    vpn.OpenVPN,
			expectedSelection:  vpn.OpenVPN,
			expectedProtocol:   constants.TCP,
			expectedHostnames:  []string{"br53.nordvpn.com"},
			expectedEndpointIP: netip.MustParseAddr("177.54.151.174"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			current := settings.VPN{
				Type: vpn.OpenVPN,
				Provider: settings.Provider{
					Name: "nordvpn",
					ServerSelection: settings.ServerSelection{
						VPN:        vpn.OpenVPN,
						Countries:  []string{"Brazil"},
						Regions:    []string{"The Americas"},
						Cities:     []string{"Sao Paulo"},
						ISPs:       []string{"old-isp"},
						Categories: []string{"P2P"},
						OpenVPN: settings.OpenVPNSelection{
							Protocol: constants.TCP,
						},
					},
				},
			}

			updated, err := applySnapshotToSettings(current, testCase.snapshot)
			require.NoError(t, err)

			assert.Equal(t, testCase.expectedVPNType, updated.Type)
			assert.Equal(t, testCase.expectedSelection,
				updated.Provider.ServerSelection.VPN)
			assert.Equal(t, testCase.expectedCountries,
				updated.Provider.ServerSelection.Countries)
			assert.Equal(t, testCase.expectedRegions,
				updated.Provider.ServerSelection.Regions)
			assert.Equal(t, testCase.expectedCities,
				updated.Provider.ServerSelection.Cities)
			assert.Equal(t, testCase.expectedISPs,
				updated.Provider.ServerSelection.ISPs)
			assert.Equal(t, testCase.expectedCategories,
				updated.Provider.ServerSelection.Categories)
			assert.Equal(t, testCase.expectedHostnames,
				updated.Provider.ServerSelection.Hostnames)
			switch testCase.expectedVPNType {
			case vpn.Wireguard:
				assert.Equal(t, testCase.expectedEndpointIP,
					updated.Provider.ServerSelection.Wireguard.EndpointIP)
			case vpn.OpenVPN:
				assert.Equal(t, testCase.expectedEndpointIP,
					updated.Provider.ServerSelection.OpenVPN.EndpointIP)
			}
			if testCase.expectedProtocol != "" {
				assert.Equal(t, testCase.expectedProtocol,
					updated.Provider.ServerSelection.OpenVPN.Protocol)
			}
		})
	}
}
