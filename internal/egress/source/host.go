package source

import (
	"errors"
	"net"
	"net/netip"
	"slices"
)

// HostIPs returns the underlay host IPs captured before the tunnel starts.
// When automatic capture is disabled, the configured IP is the only entry.
func HostIPs(auto bool, configured netip.Addr) (hostIPs []netip.Addr, err error) {
	if !auto {
		if !configured.IsValid() {
			return nil, errors.New("host IP is not configured")
		}
		return []netip.Addr{configured.Unmap()}, nil
	}

	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}

	hostIPs = make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		prefix, parseErr := netip.ParsePrefix(address.String())
		if parseErr != nil {
			continue
		}
		ip := prefix.Addr().Unmap()
		if !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		if slices.Contains(hostIPs, ip) {
			continue
		}
		hostIPs = append(hostIPs, ip)
	}
	return hostIPs, nil
}
