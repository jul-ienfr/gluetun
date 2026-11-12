package transport

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

const defaultPreflightTimeout = 10 * time.Second

type Target struct {
	Hostname   string     `json:"hostname"`
	EndpointIP netip.Addr `json:"endpoint_ip,omitempty"`
	Port       uint16     `json:"port,omitempty"`
}

type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string) (
		addresses []netip.Addr, err error)
}

type Dialer interface {
	DialContext(ctx context.Context, network, address string) (
		connection net.Conn, err error)
}

type Credentials struct {
	OpenVPN   bool
	WireGuard bool
}

func (c Credentials) Supports(transport Transport) bool {
	switch transport {
	case WireGuard:
		return c.WireGuard
	case OpenVPNUDP, OpenVPNTCP:
		return c.OpenVPN
	}
	return false
}

type PreflightSettings struct {
	Resolver    Resolver
	Dialer      Dialer
	Credentials Credentials
	Timeout     time.Duration
	Ports       map[Transport]uint16
}

type Preflight struct {
	resolver    Resolver
	dialer      Dialer
	credentials Credentials
	timeout     time.Duration
	ports       map[Transport]uint16
}

func NewPreflight(settings PreflightSettings) *Preflight {
	resolver := settings.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := settings.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	timeout := settings.Timeout
	if timeout <= 0 {
		timeout = defaultPreflightTimeout
	}
	ports := settings.Ports
	if ports == nil {
		ports = make(map[Transport]uint16)
	}
	return &Preflight{
		resolver:    resolver,
		dialer:      dialer,
		credentials: settings.Credentials,
		timeout:     timeout,
		ports:       ports,
	}
}

func (p *Preflight) Check(ctx context.Context, transport Transport,
	target Target,
) (resolved Target, err error) {
	if !transport.Valid() {
		return Target{}, NewFailure(ReasonConfigInvalid,
			fmt.Errorf("%w: unknown transport %q", ErrInvalidPolicy, transport))
	}
	if target.Hostname == "" {
		return Target{}, NewFailure(ReasonConfigInvalid,
			fmt.Errorf("hostname is empty"))
	}
	if !p.credentials.Supports(transport) {
		return Target{}, NewFailure(ReasonAuth,
			fmt.Errorf("no credentials for transport %q", transport))
	}

	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	addresses, err := p.resolver.LookupNetIP(ctx, "ip", target.Hostname)
	if err != nil {
		return Target{}, NewFailure(ReasonConfigInvalid,
			fmt.Errorf("resolving %q: %w", target.Hostname, err))
	}
	addresses = unmapAddrs(addresses)

	endpoint := target.EndpointIP
	if endpoint.IsValid() {
		endpoint = endpoint.Unmap()
		if len(addresses) > 0 && !containsAddr(addresses, endpoint) {
			return Target{}, NewFailure(ReasonConfigInvalid,
				fmt.Errorf("%s is not advertised by %q", endpoint,
					target.Hostname))
		}
	} else {
		if len(addresses) == 0 {
			return Target{}, NewFailure(ReasonConfigInvalid,
				fmt.Errorf("hostname %q has no IP address", target.Hostname))
		}
		endpoint = addresses[0]
	}
	if !endpoint.IsValid() {
		return Target{}, NewFailure(ReasonConfigInvalid,
			fmt.Errorf("hostname %q has no usable IP address", target.Hostname))
	}

	port := target.Port
	if port == 0 {
		port = p.portFor(transport)
	}

	address := net.JoinHostPort(endpoint.String(),
		strconv.FormatUint(uint64(port), 10))
	connection, err := p.dialer.DialContext(ctx, transport.Network(), address)
	if err != nil {
		return Target{}, NewFailure(Classify(err, transport),
			fmt.Errorf("dialing %s %s: %w", transport.Network(), address, err))
	}
	_ = connection.Close()

	return Target{
		Hostname:   target.Hostname,
		EndpointIP: endpoint,
		Port:       port,
	}, nil
}

func (p *Preflight) portFor(transport Transport) uint16 {
	port := p.ports[transport]
	if port != 0 {
		return port
	}
	return transport.DefaultPort()
}

func unmapAddrs(addresses []netip.Addr) []netip.Addr {
	normalized := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !address.IsValid() {
			continue
		}
		address = address.Unmap()
		if _, ok := seen[address]; ok {
			continue
		}
		seen[address] = struct{}{}
		normalized = append(normalized, address)
	}
	return normalized
}

func containsAddr(addresses []netip.Addr, address netip.Addr) bool {
	for _, candidate := range addresses {
		if candidate == address {
			return true
		}
	}
	return false
}
