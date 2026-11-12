package jobs

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCatalog struct {
	server Server
	found  bool
	err    error
}

func (f fakeCatalog) Lookup(_ context.Context, _ string,
) (server Server, found bool, err error) {
	if f.err != nil {
		return Server{}, false, f.err
	}
	return f.server, f.found, nil
}

type fakeResolver struct {
	addresses []netip.Addr
	err       error
}

func (f fakeResolver) LookupNetIP(_ context.Context, _, _ string,
) (addresses []netip.Addr, err error) {
	return f.addresses, f.err
}

type fakeProber struct {
	err       error
	calls     int
	transport Transport
	address   string
}

func (f *fakeProber) Probe(_ context.Context, transport Transport,
	address string,
) error {
	f.calls++
	f.transport = transport
	f.address = address
	return f.err
}

type blockingProber struct{}

func (blockingProber) Probe(ctx context.Context, _ Transport, _ string) error {
	<-ctx.Done()
	return ctx.Err()
}

func testTarget() Target {
	return Target{
		Provider: "nordvpn",
		VPN:      VPNWireGuard,
		Hostname: "nl-1234.nordvpn.com",
		Port:     51820,
	}
}

func testOpenVPNTarget(port uint16) Target {
	return Target{
		Provider: "nordvpn",
		VPN:      VPNOpenVPN,
		Hostname: "nl-1234.nordvpn.com",
		Port:     port,
	}
}

func testServer() Server {
	return Server{
		Hostname:  "nl-1234.nordvpn.com",
		IPs:       []netip.Addr{netip.MustParseAddr("203.0.113.10")},
		Protocols: []string{VPNOpenVPN, VPNWireGuard},
	}
}

func Test_PreflightCheck(t *testing.T) {
	t.Parallel()

	wireGuardCredentials := Credentials{WireGuard: true}
	openVPNCredentials := Credentials{OpenVPN: true}
	catalogServer := testServer()
	catalogIP := netip.MustParseAddr("203.0.113.10")
	alternateIP := netip.MustParseAddr("198.51.100.7")

	testCases := map[string]struct {
		target           Target
		transport        Transport
		credentials      Credentials
		server           Server
		found            bool
		catalogErr       error
		resolved         []netip.Addr
		resolveErr       error
		probeErr         error
		expectedErr      error
		expectedMessage  string
		expectProbe      bool
		expectedAddress  string
		expectedPort     uint16
		expectedIP       string
		expectedResolved []netip.Addr
	}{
		"wireguard success": {
			target:           testTarget(),
			transport:        TransportWireGuard,
			credentials:      wireGuardCredentials,
			server:           catalogServer,
			found:            true,
			resolved:         []netip.Addr{catalogIP},
			expectedAddress:  "203.0.113.10:51820",
			expectedPort:     51820,
			expectedIP:       "203.0.113.10",
			expectedResolved: []netip.Addr{catalogIP},
		},
		"openvpn UDP default port": {
			target:           testOpenVPNTarget(0),
			transport:        TransportOpenVPNUDP,
			credentials:      openVPNCredentials,
			server:           catalogServer,
			found:            true,
			resolved:         []netip.Addr{catalogIP},
			expectedAddress:  "203.0.113.10:1194",
			expectedPort:     1194,
			expectedIP:       "203.0.113.10",
			expectedResolved: []netip.Addr{catalogIP},
		},
		"openvpn TCP explicit port": {
			target:           testOpenVPNTarget(443),
			transport:        TransportOpenVPNTCP,
			credentials:      openVPNCredentials,
			server:           catalogServer,
			found:            true,
			resolved:         []netip.Addr{catalogIP},
			expectedAddress:  "203.0.113.10:443",
			expectedPort:     443,
			expectedIP:       "203.0.113.10",
			expectedResolved: []netip.Addr{catalogIP},
		},
		"catalog addresses when resolution is empty": {
			target:           testTarget(),
			transport:        TransportWireGuard,
			credentials:      wireGuardCredentials,
			server:           catalogServer,
			found:            true,
			expectedAddress:  "203.0.113.10:51820",
			expectedPort:     51820,
			expectedIP:       "203.0.113.10",
			expectedResolved: []netip.Addr{catalogIP},
		},
		"explicit endpoint advertised by catalog": {
			target: func() Target {
				target := testTarget()
				target.EndpointIP = catalogIP
				return target
			}(),
			transport:        TransportWireGuard,
			credentials:      wireGuardCredentials,
			server:           catalogServer,
			found:            true,
			resolved:         []netip.Addr{alternateIP},
			expectedAddress:  "203.0.113.10:51820",
			expectedPort:     51820,
			expectedIP:       "203.0.113.10",
			expectedResolved: []netip.Addr{alternateIP},
		},
		"unknown target": {
			target:      testTarget(),
			transport:   TransportWireGuard,
			credentials: wireGuardCredentials,
			expectedErr: ErrUnknownTarget,
		},
		"catalog error": {
			target:          testTarget(),
			transport:       TransportWireGuard,
			credentials:     wireGuardCredentials,
			catalogErr:      errors.New("catalog unavailable"),
			expectedMessage: "catalog unavailable",
		},
		"missing WireGuard credentials": {
			target:      testTarget(),
			transport:   TransportWireGuard,
			found:       true,
			server:      catalogServer,
			expectedErr: ErrMissingCredentials,
		},
		"unsupported protocol": {
			target:      testTarget(),
			transport:   TransportWireGuard,
			credentials: wireGuardCredentials,
			server: Server{
				Hostname:  "nl-1234.nordvpn.com",
				IPs:       []netip.Addr{catalogIP},
				Protocols: []string{VPNOpenVPN},
			},
			found:       true,
			expectedErr: ErrTransportUnsupported,
		},
		"resolution failure": {
			target:      testTarget(),
			transport:   TransportWireGuard,
			credentials: wireGuardCredentials,
			server:      catalogServer,
			found:       true,
			resolveErr:  errors.New("no such host"),
			expectedErr: ErrResolutionFailed,
		},
		"no addresses": {
			target:      testTarget(),
			transport:   TransportWireGuard,
			credentials: wireGuardCredentials,
			server: Server{
				Hostname:  "nl-1234.nordvpn.com",
				Protocols: []string{VPNWireGuard},
			},
			found:       true,
			expectedErr: ErrResolutionFailed,
		},
		"endpoint IP mismatch": {
			target: func() Target {
				target := testTarget()
				target.EndpointIP = netip.MustParseAddr("198.51.100.99")
				return target
			}(),
			transport:   TransportWireGuard,
			credentials: wireGuardCredentials,
			server:      catalogServer,
			found:       true,
			resolved:    []netip.Addr{catalogIP},
			expectedErr: ErrEndpointIPMismatch,
		},
		"probe failure": {
			target:      testTarget(),
			transport:   TransportWireGuard,
			credentials: wireGuardCredentials,
			server:      catalogServer,
			found:       true,
			resolved:    []netip.Addr{catalogIP},
			probeErr:    errors.New("connection refused"),
			expectedErr: ErrEndpointUnreachable,
			expectProbe: true,
		},
		"unknown transport": {
			target:      testTarget(),
			transport:   "bogus",
			credentials: wireGuardCredentials,
			expectedErr: ErrInvalidTarget,
		},
		"transport VPN mismatch": {
			target:      testTarget(),
			transport:   TransportOpenVPNTCP,
			credentials: wireGuardCredentials,
			expectedErr: ErrInvalidTarget,
		},
		"empty hostname": {
			target: func() Target {
				target := testTarget()
				target.Hostname = ""
				return target
			}(),
			transport:   TransportWireGuard,
			credentials: wireGuardCredentials,
			expectedErr: ErrInvalidTarget,
		},
		"empty provider": {
			target: func() Target {
				target := testTarget()
				target.Provider = ""
				return target
			}(),
			transport:   TransportWireGuard,
			credentials: wireGuardCredentials,
			expectedErr: ErrInvalidTarget,
		},
		"unknown VPN": {
			target: func() Target {
				target := testTarget()
				target.VPN = "pptp"
				return target
			}(),
			transport:   TransportWireGuard,
			credentials: wireGuardCredentials,
			expectedErr: ErrInvalidTarget,
		},
		"non public endpoint": {
			target: func() Target {
				target := testTarget()
				target.EndpointIP = netip.MustParseAddr("224.0.0.1")
				return target
			}(),
			transport:   TransportWireGuard,
			credentials: wireGuardCredentials,
			expectedErr: ErrInvalidTarget,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			prober := &fakeProber{err: testCase.probeErr}
			preflight := NewPreflight(PreflightSettings{
				Catalog: fakeCatalog{
					server: testCase.server,
					found:  testCase.found,
					err:    testCase.catalogErr,
				},
				Resolver: fakeResolver{
					addresses: testCase.resolved,
					err:       testCase.resolveErr,
				},
				Prober:      prober,
				Credentials: testCase.credentials,
				Timeout:     time.Second,
			})

			result, err := preflight.Check(context.Background(),
				PreflightRequest{
					Target:    testCase.target,
					Transport: testCase.transport,
				})

			if testCase.expectedErr != nil {
				assert.ErrorIs(t, err, testCase.expectedErr)
				assert.Equal(t, testCase.expectProbe, prober.calls > 0)
				return
			}
			if testCase.expectedMessage != "" {
				assert.ErrorContains(t, err, testCase.expectedMessage)
				assert.Zero(t, prober.calls)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, testCase.target.Provider, result.Provider)
			assert.Equal(t, testCase.target.Hostname, result.Hostname)
			assert.Equal(t, testCase.transport, result.Transport)
			assert.Equal(t, testCase.expectedPort, result.Port)
			assert.Equal(t, testCase.expectedIP, result.EndpointIP.String())
			assert.Equal(t, testCase.expectedResolved, result.ResolvedIPs)
			assert.Equal(t, 1, prober.calls)
			assert.Equal(t, testCase.transport, prober.transport)
			assert.Equal(t, testCase.expectedAddress, prober.address)
		})
	}
}

func Test_PreflightCheckTimeout(t *testing.T) {
	t.Parallel()

	preflight := NewPreflight(PreflightSettings{
		Catalog: fakeCatalog{
			server: testServer(),
			found:  true,
		},
		Resolver: fakeResolver{
			addresses: []netip.Addr{netip.MustParseAddr("203.0.113.10")},
		},
		Prober:      blockingProber{},
		Credentials: Credentials{WireGuard: true},
	})

	result, err := preflight.Check(context.Background(), PreflightRequest{
		Target:    testTarget(),
		Transport: TransportWireGuard,
		Timeout:   10 * time.Millisecond,
	})
	assert.Equal(t, PreflightResult{}, result)
	assert.ErrorIs(t, err, ErrEndpointUnreachable)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func Test_NewPreflightPanicsOnNilCatalog(t *testing.T) {
	t.Parallel()

	assert.Panics(t, func() {
		NewPreflight(PreflightSettings{})
	})
}

func Test_networkProberProbeTCP(t *testing.T) {
	t.Parallel()

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	err = networkProber{}.Probe(context.Background(),
		TransportOpenVPNTCP, listener.Addr().String())
	assert.NoError(t, err)
}

func Test_networkProberProbeUDP(t *testing.T) {
	t.Parallel()

	err := networkProber{}.Probe(context.Background(),
		TransportWireGuard, "127.0.0.1:51820")
	assert.NoError(t, err)
}
