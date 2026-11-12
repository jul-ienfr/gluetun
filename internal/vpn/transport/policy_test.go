package transport

import (
	"errors"
	"testing"
	"time"
)

func TestDefaultPolicyNormalize(t *testing.T) {
	t.Parallel()

	policy, warnings, err := DefaultPolicy().Normalize()
	if err != nil {
		t.Fatalf("normalizing default policy: %v", err)
	}
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	expected := []Transport{WireGuard, OpenVPNUDP, OpenVPNTCP}
	if len(policy.Ladder) != len(expected) {
		t.Fatalf("ladder length: expected %d, got %d", len(expected), len(policy.Ladder))
	}
	for i := range expected {
		if policy.Ladder[i] != expected[i] {
			t.Fatalf("ladder[%d]: expected %q, got %q", i, expected[i], policy.Ladder[i])
		}
	}
	if policy.AttemptTimeout[OpenVPNTCP] != 45*time.Second {
		t.Fatalf("TCP timeout: got %s", policy.AttemptTimeout[OpenVPNTCP])
	}
	if policy.AttemptTimeout[WireGuard] != 30*time.Second {
		t.Fatalf("WireGuard timeout: got %s", policy.AttemptTimeout[WireGuard])
	}
}

func TestPolicyNormalizeRejectsInvalid(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		policy Policy
	}{
		"empty ladder":       {policy: Policy{}},
		"unknown transport":  {policy: Policy{Ladder: []Transport{"gre"}}},
		"negative jitter":    {policy: Policy{Ladder: DefaultLadder, Jitter: -0.1}},
		"jitter above one":   {policy: Policy{Ladder: DefaultLadder, Jitter: 1.1}},
		"backoff max below":  {policy: Policy{Ladder: DefaultLadder, BackoffBase: 10 * time.Second, BackoffMax: time.Second}},
		"cooldown max below": {policy: Policy{Ladder: DefaultLadder, BreakerCooldown: 10 * time.Second, BreakerCooldownMax: time.Second}},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, _, err := testCase.policy.Normalize()
			if !errors.Is(err, ErrInvalidPolicy) {
				t.Fatalf("expected ErrInvalidPolicy, got %v", err)
			}
		})
	}
}

func TestPolicyNormalizeDuplicate(t *testing.T) {
	t.Parallel()

	policy := DefaultPolicy()
	policy.Ladder = []Transport{WireGuard, OpenVPNUDP, WireGuard}

	normalized, warnings, err := policy.Normalize()
	if err != nil {
		t.Fatalf("normalizing policy: %v", err)
	}
	if len(warnings) != 1 {
		t.Fatalf("expected one warning, got %v", warnings)
	}
	if len(normalized.Ladder) != 2 ||
		normalized.Ladder[0] != WireGuard ||
		normalized.Ladder[1] != OpenVPNUDP {
		t.Fatalf("unexpected normalized ladder: %v", normalized.Ladder)
	}
}

func TestParseLadder(t *testing.T) {
	t.Parallel()

	ladder, err := ParseLadder(" wireguard, openvpn-udp ,openvpn-tcp ")
	if err != nil {
		t.Fatalf("parsing ladder: %v", err)
	}
	if len(ladder) != 3 || ladder[0] != WireGuard ||
		ladder[1] != OpenVPNUDP || ladder[2] != OpenVPNTCP {
		t.Fatalf("unexpected ladder: %v", ladder)
	}

	_, err = ParseLadder("wireguard,gre")
	if !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("expected ErrInvalidPolicy, got %v", err)
	}

	_, err = ParseLadder(" , ")
	if !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("expected ErrInvalidPolicy, got %v", err)
	}
}

func TestTransportProperties(t *testing.T) {
	t.Parallel()

	if WireGuard.VPNType() != VPNWireGuard {
		t.Fatalf("wireguard VPN type: %q", WireGuard.VPNType())
	}
	if OpenVPNUDP.VPNType() != VPNOpenVPN || OpenVPNTCP.VPNType() != VPNOpenVPN {
		t.Fatalf("openvpn VPN type mismatch")
	}
	if OpenVPNTCP.Network() != "tcp" || OpenVPNUDP.Network() != "udp" {
		t.Fatalf("network mismatch")
	}
	if WireGuard.DefaultPort() != 51820 || OpenVPNTCP.DefaultPort() != 1194 {
		t.Fatalf("default port mismatch")
	}
	if Transport("gre").Valid() {
		t.Fatalf("unknown transport reported valid")
	}
}
