package consensus

import (
	"net/netip"

	"github.com/qdm12/gluetun/internal/egress"
)

// Options are the fixed rules applied to every observation.
type Options struct {
	Quorum        int
	MinSources    int
	AllowSingle   bool
	Family        int
	HostIPs       []netip.Addr
	ForbiddenIPs  []netip.Addr
	AllowTestNets bool
}

// RejectionReason returns the hard rejection for an address, if any.
func RejectionReason(ip netip.Addr, options Options) egress.Reason {
	if !ip.IsValid() {
		return egress.ReasonMalformed
	}
	ip = ip.Unmap()

	switch {
	case ip.IsUnspecified():
		return egress.ReasonUnspecified
	case ip.IsLoopback():
		return egress.ReasonLoopback
	case ip.IsLinkLocalUnicast():
		return egress.ReasonLinkLocal
	case ip.IsMulticast():
		return egress.ReasonMulticast
	case isCGNAT(ip):
		return egress.ReasonCGNAT
	case ip.IsPrivate():
		return egress.ReasonPrivate
	case options.Family == 4 && !ip.Is4():
		return egress.ReasonWrongFamily
	case options.Family == 6 && !ip.Is6():
		return egress.ReasonWrongFamily
	case contains(options.HostIPs, ip):
		return egress.ReasonHostIP
	case contains(options.ForbiddenIPs, ip):
		return egress.ReasonForbiddenIP
	case !options.AllowTestNets && isDocumentation(ip):
		return egress.ReasonDocumenting
	}
	return ""
}

func isCGNAT(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	bytes := ip.As4()
	return bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127
}

func isDocumentation(ip netip.Addr) bool {
	return netip.MustParsePrefix("192.0.2.0/24").Contains(ip) ||
		netip.MustParsePrefix("198.51.100.0/24").Contains(ip) ||
		netip.MustParsePrefix("203.0.113.0/24").Contains(ip) ||
		netip.MustParsePrefix("2001:db8::/32").Contains(ip)
}

func contains(addresses []netip.Addr, ip netip.Addr) bool {
	for _, address := range addresses {
		if address.Unmap() == ip {
			return true
		}
	}
	return false
}
