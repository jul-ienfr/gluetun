package vpn

import (
	"context"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants/vpn"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/provider"
	"github.com/stretchr/testify/assert"
)

type targetProvider struct {
	connection    models.Connection
	err           error
	calls         int
	selectionVPN  string
	selectionMode string
}

func (p *targetProvider) GetConnection(selection settings.ServerSelection,
	_ bool,
) (models.Connection, error) {
	p.calls++
	p.selectionVPN = selection.VPN
	p.selectionMode = selection.Mode
	return p.connection, p.err
}

func (p *targetProvider) OpenVPNConfig(_ models.Connection,
	_ settings.OpenVPN, _ bool,
) []string {
	return nil
}

func (p *targetProvider) Name() string {
	return "nordvpn"
}

func (p *targetProvider) FetchServers(_ context.Context, _ int) (
	[]models.Server, error,
) {
	return nil, nil
}

type targetProviders map[string]provider.Provider

func (p targetProviders) Get(name string) provider.Provider {
	return p[name]
}

func Test_ladderDriver_targetFor(t *testing.T) {
	t.Parallel()

	providerAddress := netip.MustParseAddr("203.0.113.5")
	explicitAddress := netip.MustParseAddr("198.51.100.9")

	testCases := map[string]struct {
		base            settings.VPN
		providerAddress netip.Addr
		providerErr     error
		expected        netip.Addr
		expectedCalls   int
	}{
		"provider_catalogue_fills_the_endpoint": {
			base: settings.VPN{
				Provider: settings.Provider{
					Name: "nordvpn",
					ServerSelection: settings.ServerSelection{
						Hostnames: []string{"us1.nordvpn.com"},
					},
				},
			},
			providerAddress: providerAddress,
			expected:        providerAddress,
			expectedCalls:   1,
		},
		"provider_error_keeps_the_endpoint_empty": {
			base: settings.VPN{
				Provider: settings.Provider{
					Name: "nordvpn",
					ServerSelection: settings.ServerSelection{
						Hostnames: []string{"us1.nordvpn.com"},
					},
				},
			},
			providerErr:   assert.AnError,
			expected:      netip.Addr{},
			expectedCalls: 1,
		},
		"explicit_endpoint_is_not_resolved_again": {
			base: settings.VPN{
				Type: vpn.OpenVPN,
				Provider: settings.Provider{
					Name: "nordvpn",
					ServerSelection: settings.ServerSelection{
						Hostnames: []string{"us1.nordvpn.com"},
						OpenVPN: settings.OpenVPNSelection{
							EndpointIP: explicitAddress,
						},
					},
				},
			},
			providerAddress: providerAddress,
			expected:        explicitAddress,
			expectedCalls:   0,
		},
		"empty_hostname_skips_the_provider": {
			base: settings.VPN{
				Provider: settings.Provider{Name: "nordvpn"},
			},
			providerAddress: providerAddress,
			expected:        netip.Addr{},
			expectedCalls:   0,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			providerConf := &targetProvider{
				connection: models.Connection{IP: testCase.providerAddress},
				err:        testCase.providerErr,
			}
			loop := &Loop{providers: targetProviders{
				"nordvpn": providerConf,
			}}

			driver := newLadderDriver(loop, testCase.base)

			assert.Equal(t, testCase.expected, driver.target.EndpointIP)
			assert.Equal(t, testCase.expectedCalls, providerConf.calls)
			if testCase.expectedCalls > 0 {
				assert.Equal(t, vpn.OpenVPN, providerConf.selectionVPN)
				assert.Equal(t, "random", providerConf.selectionMode)
			}
		})
	}
}
