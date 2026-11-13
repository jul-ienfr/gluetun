package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"syscall"
	"testing"
	"time"
)

type fakeResolver struct {
	addresses []netip.Addr
	err       error
	calls     int
}

func (r *fakeResolver) LookupNetIP(ctx context.Context, network, host string) (
	[]netip.Addr, error,
) {
	r.calls++
	return r.addresses, r.err
}

type fakeDialer struct {
	network string
	address string
	err     error
	calls   int
}

func (d *fakeDialer) DialContext(ctx context.Context, network, address string) (
	net.Conn, error,
) {
	d.calls++
	d.network = network
	d.address = address
	if d.err != nil {
		return nil, d.err
	}
	return fakeConn{}, nil
}

type fakeConn struct{}

func (fakeConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (fakeConn) Write(p []byte) (int, error)      { return len(p), nil }
func (fakeConn) Close() error                     { return nil }
func (fakeConn) LocalAddr() net.Addr              { return fakeAddr{} }
func (fakeConn) RemoteAddr() net.Addr             { return fakeAddr{} }
func (fakeConn) SetDeadline(time.Time) error      { return nil }
func (fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (fakeConn) SetWriteDeadline(time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

func TestPreflightSuccess(t *testing.T) {
	t.Parallel()

	dialer := &fakeDialer{}
	preflight := NewPreflight(PreflightSettings{
		Resolver: &fakeResolver{
			addresses: []netip.Addr{netip.MustParseAddr("1.2.3.4")},
		},
		Dialer: dialer,
		Credentials: Credentials{
			OpenVPN: true,
		},
	})

	target, err := preflight.Check(context.Background(), OpenVPNTCP,
		Target{Hostname: "example.com"})
	if err != nil {
		t.Fatalf("checking target: %v", err)
	}
	if target.EndpointIP != netip.MustParseAddr("1.2.3.4") {
		t.Fatalf("endpoint: %s", target.EndpointIP)
	}
	if target.Port != 1194 {
		t.Fatalf("port: %d", target.Port)
	}
	if dialer.network != "tcp" || dialer.address != "1.2.3.4:1194" {
		t.Fatalf("dial: %s %s", dialer.network, dialer.address)
	}
}

func TestPreflightExplicitEndpointSkipsDNS(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{err: errors.New("dns unavailable before tunnel")}
	dialer := &fakeDialer{}
	preflight := NewPreflight(PreflightSettings{
		Resolver:    resolver,
		Dialer:      dialer,
		Credentials: Credentials{OpenVPN: true},
	})
	endpoint := netip.MustParseAddr("1.2.3.4")

	target, err := preflight.Check(context.Background(), OpenVPNUDP,
		Target{Hostname: "example.com", EndpointIP: endpoint})
	if err != nil {
		t.Fatalf("checking target: %v", err)
	}
	if target.EndpointIP != endpoint {
		t.Fatalf("endpoint: %s", target.EndpointIP)
	}
	if resolver.calls != 0 {
		t.Fatalf("resolver calls: %d, want 0", resolver.calls)
	}
	if dialer.address != "1.2.3.4:1194" {
		t.Fatalf("dial address: %s", dialer.address)
	}
}

func TestPreflightErrors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		preflight PreflightSettings
		transport Transport
		target    Target
		expected  Reason
	}{
		"missing credentials": {
			preflight: PreflightSettings{
				Resolver: &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("1.2.3.4")}},
			},
			transport: OpenVPNUDP,
			target:    Target{Hostname: "example.com"},
			expected:  ReasonAuth,
		},
		"unknown transport": {
			preflight: PreflightSettings{
				Credentials: Credentials{OpenVPN: true},
			},
			transport: Transport("gre"),
			target:    Target{Hostname: "example.com"},
			expected:  ReasonConfigInvalid,
		},
		"resolution failure": {
			preflight: PreflightSettings{
				Resolver:    &fakeResolver{err: errors.New("nope")},
				Credentials: Credentials{OpenVPN: true},
			},
			transport: OpenVPNUDP,
			target:    Target{Hostname: "example.com"},
			expected:  ReasonConfigInvalid,
		},
		"tcp refused": {
			preflight: PreflightSettings{
				Resolver:    &fakeResolver{addresses: []netip.Addr{netip.MustParseAddr("1.2.3.4")}},
				Dialer:      &fakeDialer{err: syscall.ECONNREFUSED},
				Credentials: Credentials{OpenVPN: true},
			},
			transport: OpenVPNTCP,
			target:    Target{Hostname: "example.com"},
			expected:  ReasonTCPRefused,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			preflight := NewPreflight(testCase.preflight)
			_, err := preflight.Check(context.Background(), testCase.transport,
				testCase.target)
			if err == nil {
				t.Fatal("expected an error")
			}
			reason := ReasonOf(err)
			if reason != testCase.expected {
				t.Fatalf("expected %q, got %q (%v)", testCase.expected, reason, err)
			}
		})
	}
}

func TestPreflightUsesExplicitEndpointWithoutResolution(t *testing.T) {
	t.Parallel()

	dialer := &fakeDialer{}
	preflight := NewPreflight(PreflightSettings{
		Resolver:    &fakeResolver{},
		Dialer:      dialer,
		Credentials: Credentials{WireGuard: true},
	})
	target, err := preflight.Check(context.Background(), WireGuard, Target{
		Hostname:   "example.com",
		EndpointIP: netip.MustParseAddr("1.2.3.4"),
		Port:       51821,
	})
	if err != nil {
		t.Fatalf("checking target: %v", err)
	}
	if target.Port != 51821 || dialer.address != "1.2.3.4:51821" {
		t.Fatalf("target: %+v, dial: %s", target, dialer.address)
	}
	if dialer.network != "udp" {
		t.Fatalf("network: %s", dialer.network)
	}
}
