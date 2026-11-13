// Package jobs orchestrates deterministic switch and rotation jobs.
package jobs

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/qdm12/gluetun/internal/egress/consensus"
)

// Transport is one transport of the switch job ladder.
type Transport string

// Transports of the ladder.
const (
	TransportWireGuard  Transport = "wireguard"
	TransportOpenVPNUDP Transport = "openvpn-udp"
	TransportOpenVPNTCP Transport = "openvpn-tcp"
)

// VPN types.
const (
	VPNOpenVPN   = "openvpn"
	VPNWireGuard = "wireguard"
)

const (
	defaultPreflightTimeout = 10 * time.Second
	defaultWireGuardPort    = 51820
	defaultOpenVPNPort      = 1194
)

// Preflight errors.
var (
	ErrInvalidTarget        = errors.New("invalid target")
	ErrUnknownTarget        = errors.New("unknown target")
	ErrEndpointIPMismatch   = errors.New("endpoint IP mismatch")
	ErrTransportUnsupported = errors.New("transport unsupported")
	ErrMissingCredentials   = errors.New("missing credentials")
	ErrResolutionFailed     = errors.New("resolution failed")
	ErrEndpointUnreachable  = errors.New("endpoint unreachable")
)

// Credentials records which VPN transports the station can authenticate.
type Credentials struct {
	OpenVPN   bool
	WireGuard bool
}

// Supports reports whether credentials exist for a transport.
func (c Credentials) Supports(transport Transport) bool {
	switch transport {
	case TransportOpenVPNUDP, TransportOpenVPNTCP:
		return c.OpenVPN
	case TransportWireGuard:
		return c.WireGuard
	}
	return false
}

// Server is the catalog view required by the preflight.
type Server struct {
	Hostname  string
	IPs       []netip.Addr
	Protocols []string
}

// Catalog looks up a server hostname in the provider catalog.
type Catalog interface {
	Lookup(ctx context.Context, hostname string,
	) (server Server, found bool, err error)
}

// Resolver resolves a hostname to IP addresses.
type Resolver interface {
	LookupNetIP(ctx context.Context, network, host string,
	) (addresses []netip.Addr, err error)
}

// Prober checks transport reachability for one endpoint address.
type Prober interface {
	Probe(ctx context.Context, transport Transport, address string) error
}

// Target is the normalized switch target validated by the preflight.
type Target struct {
	Provider        string     `json:"provider,omitempty"`
	VPN             string     `json:"vpn,omitempty"`
	TransportDetail string     `json:"transport_detail,omitempty"`
	Hostname        string     `json:"hostname,omitempty"`
	EndpointIP      netip.Addr `json:"endpoint_ip,omitempty"`
	Port            uint16     `json:"port,omitempty"`
}

// PreflightSettings configure the preflight checker.
type PreflightSettings struct {
	Catalog     Catalog
	Resolver    Resolver
	Prober      Prober
	Credentials Credentials
	Timeout     time.Duration
}

// Preflight validates a target without touching the tunnel.
type Preflight struct {
	catalog     Catalog
	resolver    Resolver
	prober      Prober
	credentials Credentials
	timeout     time.Duration
}

// NewPreflight creates a preflight checker.
func NewPreflight(settings PreflightSettings) *Preflight {
	if settings.Catalog == nil {
		panic("preflight catalog is nil")
	}
	resolver := settings.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	prober := settings.Prober
	if prober == nil {
		prober = networkProber{}
	}
	timeout := settings.Timeout
	if timeout <= 0 {
		timeout = defaultPreflightTimeout
	}
	return &Preflight{
		catalog:     settings.Catalog,
		resolver:    resolver,
		prober:      prober,
		credentials: settings.Credentials,
		timeout:     timeout,
	}
}

// PreflightRequest is one target validation request.
type PreflightRequest struct {
	Target    Target
	Transport Transport
	Timeout   time.Duration
}

// PreflightResult is the proven, ready-to-apply target.
type PreflightResult struct {
	Provider    string
	Hostname    string
	EndpointIP  netip.Addr
	ResolvedIPs []netip.Addr
	Transport   Transport
	Port        uint16
}

// Check validates the target against the catalog, the credentials, the DNS
// resolution and the transport reachability. It never changes the tunnel.
func (p *Preflight) Check(ctx context.Context,
	request PreflightRequest,
) (result PreflightResult, err error) {
	err = validateRequest(request)
	if err != nil {
		return PreflightResult{}, err
	}

	timeout := request.Timeout
	if timeout <= 0 {
		timeout = p.timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if !p.credentials.Supports(request.Transport) {
		return PreflightResult{}, fmt.Errorf("%w: transport %q",
			ErrMissingCredentials, request.Transport)
	}

	server, found, err := p.catalog.Lookup(ctx, request.Target.Hostname)
	if err != nil {
		return PreflightResult{}, fmt.Errorf("looking up target in catalog: %w", err)
	}
	if !found {
		return PreflightResult{}, fmt.Errorf("%w: hostname %q",
			ErrUnknownTarget, request.Target.Hostname)
	}

	err = validateProtocols(server, request.Target.VPN)
	if err != nil {
		return PreflightResult{}, err
	}

	resolved, err := p.resolver.LookupNetIP(ctx, "ip", request.Target.Hostname)
	if err != nil {
		return PreflightResult{}, fmt.Errorf("%w: %w", ErrResolutionFailed, err)
	}
	resolved = unmapAddrs(resolved)

	candidates := resolved
	if len(candidates) == 0 {
		candidates = unmapAddrs(server.IPs)
	}
	if len(candidates) == 0 {
		return PreflightResult{}, fmt.Errorf(
			"%w: hostname %q has no IP address",
			ErrResolutionFailed, request.Target.Hostname)
	}

	endpoint := request.Target.EndpointIP
	if endpoint.IsValid() {
		endpoint = endpoint.Unmap()
		if !containsAddr(candidates, endpoint) &&
			!containsAddr(unmapAddrs(server.IPs), endpoint) {
			return PreflightResult{}, fmt.Errorf(
				"%w: %s is not advertised by %q",
				ErrEndpointIPMismatch, endpoint, request.Target.Hostname)
		}
	} else {
		endpoint = candidates[0]
	}

	port := request.Target.portFor(request.Transport)
	address := net.JoinHostPort(endpoint.String(),
		strconv.FormatUint(uint64(port), 10))

	err = p.prober.Probe(ctx, request.Transport, address)
	if err != nil {
		return PreflightResult{}, fmt.Errorf("%w: %s %s: %w",
			ErrEndpointUnreachable, request.Transport, address, err)
	}

	return PreflightResult{
		Provider:    request.Target.Provider,
		Hostname:    request.Target.Hostname,
		EndpointIP:  endpoint,
		ResolvedIPs: candidates,
		Transport:   request.Transport,
		Port:        port,
	}, nil
}

func validateRequest(request PreflightRequest) error {
	switch {
	case request.Target.Provider == "":
		return fmt.Errorf("%w: provider is empty", ErrInvalidTarget)
	case request.Target.Hostname == "":
		return fmt.Errorf("%w: hostname is empty", ErrInvalidTarget)
	case request.Target.VPN != VPNOpenVPN && request.Target.VPN != VPNWireGuard:
		return fmt.Errorf("%w: unknown VPN %q", ErrInvalidTarget,
			request.Target.VPN)
	}

	expectedVPN, ok := transportVPN(request.Transport)
	if !ok {
		return fmt.Errorf("%w: unknown transport %q", ErrInvalidTarget,
			request.Transport)
	}
	if request.Target.VPN != expectedVPN {
		return fmt.Errorf("%w: transport %q requires VPN %q, got %q",
			ErrInvalidTarget, request.Transport, expectedVPN,
			request.Target.VPN)
	}

	if request.Target.EndpointIP.IsValid() {
		reason := consensus.RejectionReason(request.Target.EndpointIP,
			consensus.Options{AllowTestNets: true})
		if reason != "" {
			return fmt.Errorf("%w: endpoint IP %s is not public: %s",
				ErrInvalidTarget, request.Target.EndpointIP, reason)
		}
	}
	return nil
}

func validateProtocols(server Server, vpn string) error {
	if !slices.Contains(server.Protocols, vpn) {
		return fmt.Errorf("%w: server %q does not support VPN %q",
			ErrTransportUnsupported, server.Hostname, vpn)
	}
	return nil
}

func transportVPN(transport Transport) (vpn string, ok bool) {
	switch transport {
	case TransportWireGuard:
		return VPNWireGuard, true
	case TransportOpenVPNUDP, TransportOpenVPNTCP:
		return VPNOpenVPN, true
	}
	return "", false
}

func (t Target) portFor(transport Transport) uint16 {
	if t.Port != 0 {
		return t.Port
	}
	switch transport {
	case TransportWireGuard:
		return defaultWireGuardPort
	case TransportOpenVPNUDP, TransportOpenVPNTCP:
		return defaultOpenVPNPort
	}
	return 0
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
	return slices.Contains(addresses, address)
}

// networkProber probes transports with real sockets.
type networkProber struct{}

func (networkProber) Probe(ctx context.Context, transport Transport,
	address string,
) error {
	network := "udp"
	if transport == TransportOpenVPNTCP {
		network = "tcp"
	}

	var dialer net.Dialer
	connection, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return fmt.Errorf("dialing %s: %w", network, err)
	}
	return connection.Close()
}
