package jobs

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/egress"
)

// check validates the request constraints against the target endpoint and its
// expected egress IP before any tunnel is touched.
func (c SwitchConstraints) check(target Target, expected netip.Addr) error {
	addresses := []netip.Addr{
		target.EndpointIP,
		expected,
	}
	for _, address := range addresses {
		if !address.IsValid() {
			continue
		}
		if slices.Contains(c.ExcludeIPs, address) ||
			slices.Contains(c.ForbiddenIPs, address) {
			return fmt.Errorf("%w: endpoint IP %s", ErrTargetExcluded, address)
		}
		for _, prefix := range c.ExcludeSubnets {
			if prefix.Contains(address) {
				return fmt.Errorf("%w: endpoint subnet %s",
					ErrTargetExcluded, prefix)
			}
		}
	}
	return nil
}

// checkSwitchGates applies the post-switch gates in their documented order:
// verification, exclusions, expected egress IP, then same IP/subnet.
func checkSwitchGates(request SwitchRequest,
	before state.TunnelSnapshot, verification egress.Verification,
) error {
	if !verification.Verified || !verification.IP.IsValid() {
		return ErrEgressUnverified
	}

	err := request.Constraints.checkVerified(verification.IP)
	if err != nil {
		return err
	}

	expected := request.Target.ExpectedEgressIP
	if expected.IsValid() && verification.IP != expected {
		return fmt.Errorf("%w: observed %s, expected %s",
			ErrEgressMismatch, verification.IP, expected)
	}

	if before.Egress == nil || !before.Egress.Verified ||
		!before.Egress.IP.IsValid() {
		return nil
	}
	if request.Constraints.RequireNewIP &&
		before.Egress.IP == verification.IP {
		return fmt.Errorf("%w: %s", ErrSameIP, verification.IP)
	}
	if request.Constraints.RequireNewSubnet &&
		egressSubnet(before.Egress.IP) == egressSubnet(verification.IP) {
		return fmt.Errorf("%w: %s", ErrSameSubnet,
			egressSubnet(verification.IP))
	}
	return nil
}

// checkVerified validates the observed egress IP against the exclusions.
func (c SwitchConstraints) checkVerified(address netip.Addr) error {
	if slices.Contains(c.ForbiddenIPs, address) ||
		slices.Contains(c.ExcludeIPs, address) {
		return fmt.Errorf("%w: egress IP %s", ErrTargetExcluded, address)
	}
	for _, prefix := range c.ExcludeSubnets {
		if prefix.Contains(address) {
			return fmt.Errorf("%w: egress subnet %s",
				ErrTargetExcluded, prefix)
		}
	}
	return nil
}

func isNoop(request SwitchRequest, before state.TunnelSnapshot,
	result PreflightResult,
) bool {
	if request.Constraints.RequireNewIP ||
		request.Constraints.RequireNewSubnet {
		return false
	}
	if !strings.EqualFold(before.ServerHostname, result.Hostname) {
		return false
	}
	if before.EndpointIP.IsValid() &&
		before.EndpointIP != result.EndpointIP {
		return false
	}
	expected := request.Target.ExpectedEgressIP
	if expected.IsValid() && before.Egress != nil &&
		before.Egress.Verified && before.Egress.IP != expected {
		return false
	}
	return true
}

// egressSubnet approximates the egress subnet of an address for the
// require_new_subnet gate: /24 for IPv4 and /48 for IPv6.
func egressSubnet(address netip.Addr) netip.Prefix {
	address = address.Unmap()
	bits := 24
	if address.Is6() {
		bits = 48
	}
	prefix, err := address.Prefix(bits)
	if err != nil {
		return netip.Prefix{}
	}
	return prefix
}
