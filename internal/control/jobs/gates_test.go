package jobs

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/egress"
)

func mustAddr(t *testing.T, value string) netip.Addr {
	t.Helper()
	return netip.MustParseAddr(value)
}

func mustPrefix(t *testing.T, value string) netip.Prefix {
	t.Helper()
	return netip.MustParsePrefix(value)
}

func snapshotWithEgress(ip string) state.TunnelSnapshot {
	return state.TunnelSnapshot{
		ServerHostname: "old.example.com",
		EndpointIP:     netip.MustParseAddr("203.0.113.10"),
		Egress:         &egress.Verification{Verified: true, IP: netip.MustParseAddr(ip)},
	}
}

func Test_Constraints_Check(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		constraints SwitchConstraints
		target      Target
		expected    netip.Addr
		wantErr     error
	}{
		"valid": {
			target: Target{EndpointIP: mustAddr(t, "203.0.113.10")},
		},
		"invalid addresses skipped": {
			constraints: SwitchConstraints{
				ExcludeIPs: []netip.Addr{mustAddr(t, "203.0.113.11")},
			},
		},
		"endpoint IP excluded": {
			constraints: SwitchConstraints{
				ExcludeIPs: []netip.Addr{mustAddr(t, "203.0.113.10")},
			},
			target:  Target{EndpointIP: mustAddr(t, "203.0.113.10")},
			wantErr: ErrTargetExcluded,
		},
		"endpoint IP forbidden": {
			constraints: SwitchConstraints{
				ForbiddenIPs: []netip.Addr{mustAddr(t, "203.0.113.10")},
			},
			target:  Target{EndpointIP: mustAddr(t, "203.0.113.10")},
			wantErr: ErrTargetExcluded,
		},
		"expected egress excluded": {
			constraints: SwitchConstraints{
				ExcludeIPs: []netip.Addr{mustAddr(t, "198.51.100.9")},
			},
			expected: mustAddr(t, "198.51.100.9"),
			wantErr:  ErrTargetExcluded,
		},
		"expected egress forbidden": {
			constraints: SwitchConstraints{
				ForbiddenIPs: []netip.Addr{mustAddr(t, "198.51.100.9")},
			},
			expected: mustAddr(t, "198.51.100.9"),
			wantErr:  ErrTargetExcluded,
		},
		"endpoint subnet excluded": {
			constraints: SwitchConstraints{
				ExcludeSubnets: []netip.Prefix{mustPrefix(t, "203.0.113.0/24")},
			},
			target:  Target{EndpointIP: mustAddr(t, "203.0.113.10")},
			wantErr: ErrTargetExcluded,
		},
		"expected egress subnet excluded": {
			constraints: SwitchConstraints{
				ExcludeSubnets: []netip.Prefix{mustPrefix(t, "198.51.100.0/24")},
			},
			expected: mustAddr(t, "198.51.100.9"),
			wantErr:  ErrTargetExcluded,
		},
		"other subnet allowed": {
			constraints: SwitchConstraints{
				ExcludeSubnets: []netip.Prefix{mustPrefix(t, "198.51.100.0/24")},
			},
			target:   Target{EndpointIP: mustAddr(t, "203.0.113.10")},
			expected: mustAddr(t, "192.0.2.5"),
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.constraints.check(testCase.target, testCase.expected)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("error = %v, want %v", err, testCase.wantErr)
			}
		})
	}
}

func Test_CheckSwitchGates(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		constraints   SwitchConstraints
		before        state.TunnelSnapshot
		verification  egress.Verification
		expectedSet   bool
		expectedValue string
		wantErr       error
	}{
		"unverified": {
			verification: egress.Verification{},
			wantErr:      ErrEgressUnverified,
		},
		"invalid IP": {
			verification: egress.Verification{Verified: true},
			wantErr:      ErrEgressUnverified,
		},
		"verified without before egress": {
			verification: verifiedIP("198.51.100.8"),
		},
		"before egress unverified": {
			before: state.TunnelSnapshot{
				Egress: &egress.Verification{IP: mustAddr(t, "198.51.100.8")},
			},
			verification: verifiedIP("198.51.100.8"),
		},
		"excluded egress IP": {
			constraints: SwitchConstraints{
				ExcludeIPs: []netip.Addr{mustAddr(t, "198.51.100.8")},
			},
			verification: verifiedIP("198.51.100.8"),
			wantErr:      ErrTargetExcluded,
		},
		"forbidden egress IP": {
			constraints: SwitchConstraints{
				ForbiddenIPs: []netip.Addr{mustAddr(t, "198.51.100.8")},
			},
			verification: verifiedIP("198.51.100.8"),
			wantErr:      ErrTargetExcluded,
		},
		"excluded egress subnet": {
			constraints: SwitchConstraints{
				ExcludeSubnets: []netip.Prefix{mustPrefix(t, "198.51.100.0/24")},
			},
			verification: verifiedIP("198.51.100.8"),
			wantErr:      ErrTargetExcluded,
		},
		"egress mismatch": {
			before:        snapshotWithEgress("203.0.113.1"),
			verification:  verifiedIP("198.51.100.8"),
			expectedSet:   true,
			wantErr:       ErrEgressMismatch,
			expectedValue: "198.51.100.9",
		},
		"egress match": {
			before:        snapshotWithEgress("203.0.113.1"),
			verification:  verifiedIP("198.51.100.8"),
			expectedSet:   true,
			expectedValue: "198.51.100.8",
		},
		"same IP rejected": {
			constraints:  SwitchConstraints{RequireNewIP: true},
			before:       snapshotWithEgress("198.51.100.8"),
			verification: verifiedIP("198.51.100.8"),
			wantErr:      ErrSameIP,
		},
		"same IP allowed without requirement": {
			before:       snapshotWithEgress("198.51.100.8"),
			verification: verifiedIP("198.51.100.8"),
		},
		"same subnet rejected": {
			constraints:  SwitchConstraints{RequireNewSubnet: true},
			before:       snapshotWithEgress("198.51.100.7"),
			verification: verifiedIP("198.51.100.8"),
			wantErr:      ErrSameSubnet,
		},
		"different subnet accepted": {
			constraints:  SwitchConstraints{RequireNewSubnet: true},
			before:       snapshotWithEgress("198.51.100.7"),
			verification: verifiedIP("203.0.113.8"),
		},
		"same IPv6 /48 rejected": {
			constraints:  SwitchConstraints{RequireNewSubnet: true},
			before:       snapshotWithEgress("2001:db8:1::1"),
			verification: verifiedIP("2001:db8:1::2"),
			wantErr:      ErrSameSubnet,
		},
		"different IPv6 /48 accepted": {
			constraints:  SwitchConstraints{RequireNewSubnet: true},
			before:       snapshotWithEgress("2001:db8:1::1"),
			verification: verifiedIP("2001:db8:2::1"),
		},
		"new IP and subnet run both gates": {
			constraints:  SwitchConstraints{RequireNewIP: true, RequireNewSubnet: true},
			before:       snapshotWithEgress("198.51.100.7"),
			verification: verifiedIP("198.51.100.7"),
			wantErr:      ErrSameIP,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := SwitchRequest{Constraints: testCase.constraints}
			if testCase.expectedSet {
				request.Target.ExpectedEgressIP = mustAddr(t,
					testCase.expectedValue)
			}
			err := checkSwitchGates(request, testCase.before,
				testCase.verification)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("error = %v, want %v", err, testCase.wantErr)
			}
		})
	}
}

func Test_EgressSubnet(t *testing.T) {
	t.Parallel()

	assertPrefix := func(address, expected string) {
		t.Helper()
		got := egressSubnet(mustAddr(t, address))
		if got.String() != expected {
			t.Errorf("egressSubnet(%s) = %s, want %s", address, got,
				expected)
		}
	}
	assertPrefix("198.51.100.8", "198.51.100.0/24")
	assertPrefix("2001:db8:1::1", "2001:db8:1::/48")
}

func Test_IsNoop(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		constraints SwitchConstraints
		before      state.TunnelSnapshot
		result      PreflightResult
		expectedIP  netip.Addr
		want        bool
	}{
		"same target": {
			before: state.TunnelSnapshot{
				ServerHostname: "old.example.com",
				EndpointIP:     mustAddr(t, "203.0.113.10"),
			},
			result: PreflightResult{
				Hostname:   "old.example.com",
				EndpointIP: mustAddr(t, "203.0.113.10"),
			},
			want: true,
		},
		"case insensitive hostname": {
			before: state.TunnelSnapshot{
				ServerHostname: "Old.Example.com",
				EndpointIP:     mustAddr(t, "203.0.113.10"),
			},
			result: PreflightResult{
				Hostname:   "old.example.com",
				EndpointIP: mustAddr(t, "203.0.113.10"),
			},
			want: true,
		},
		"different hostname": {
			before: state.TunnelSnapshot{
				ServerHostname: "old.example.com",
				EndpointIP:     mustAddr(t, "203.0.113.10"),
			},
			result: PreflightResult{
				Hostname:   "new.example.com",
				EndpointIP: mustAddr(t, "203.0.113.10"),
			},
		},
		"different endpoint": {
			before: state.TunnelSnapshot{
				ServerHostname: "old.example.com",
				EndpointIP:     mustAddr(t, "203.0.113.10"),
			},
			result: PreflightResult{
				Hostname:   "old.example.com",
				EndpointIP: mustAddr(t, "203.0.113.11"),
			},
		},
		"require new IP disables noop": {
			constraints: SwitchConstraints{RequireNewIP: true},
			before: state.TunnelSnapshot{
				ServerHostname: "old.example.com",
				EndpointIP:     mustAddr(t, "203.0.113.10"),
			},
			result: PreflightResult{
				Hostname:   "old.example.com",
				EndpointIP: mustAddr(t, "203.0.113.10"),
			},
		},
		"require new subnet disables noop": {
			constraints: SwitchConstraints{RequireNewSubnet: true},
			before: state.TunnelSnapshot{
				ServerHostname: "old.example.com",
				EndpointIP:     mustAddr(t, "203.0.113.10"),
			},
			result: PreflightResult{
				Hostname:   "old.example.com",
				EndpointIP: mustAddr(t, "203.0.113.10"),
			},
		},
		"unverified before egress keeps noop": {
			before: state.TunnelSnapshot{
				ServerHostname: "old.example.com",
				EndpointIP:     mustAddr(t, "203.0.113.10"),
			},
			result: PreflightResult{
				Hostname:   "old.example.com",
				EndpointIP: mustAddr(t, "203.0.113.10"),
			},
			expectedIP: mustAddr(t, "198.51.100.8"),
			want:       true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := SwitchRequest{
				Constraints: testCase.constraints,
				Target:      SwitchTarget{ExpectedEgressIP: testCase.expectedIP},
			}
			got := isNoop(request, testCase.before, testCase.result)
			if got != testCase.want {
				t.Fatalf("isNoop = %t, want %t", got, testCase.want)
			}
		})
	}
}
