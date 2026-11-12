package catalog

import (
	"errors"
	"fmt"
	"net/netip"
)

// ErrEndpointIPMismatch is returned when an explicit endpoint IP is not
// advertised by the target hostname.
var ErrEndpointIPMismatch = errors.New("endpoint IP mismatch")

// AvailableTransports returns the transports of the ladder supported by the
// candidate, in ladder order.
func AvailableTransports(candidate ServerCandidate) []string {
	supported := make(map[string]struct{}, len(candidate.Protocols))
	for _, protocol := range candidate.Protocols {
		supported[protocol] = struct{}{}
	}

	ladder := []string{"wireguard", "openvpn-udp", "openvpn-tcp"}
	transports := make([]string, 0, len(ladder))
	for _, transport := range ladder {
		if _, ok := supported[transport]; ok {
			transports = append(transports, transport)
		}
	}
	return transports
}

// ValidateEndpointIP checks that the endpoint address is advertised by the
// candidate. An invalid address means no explicit endpoint was requested.
func ValidateEndpointIP(candidate ServerCandidate,
	endpoint netip.Addr,
) error {
	if !endpoint.IsValid() {
		return nil
	}
	endpoint = endpoint.Unmap()

	for _, value := range candidate.IPs {
		address, err := netip.ParseAddr(value)
		if err != nil {
			continue
		}
		if address.Unmap() == endpoint {
			return nil
		}
	}

	return fmt.Errorf("%w: %s is not advertised by %s", ErrEndpointIPMismatch,
		endpoint, candidate.Hostname)
}
