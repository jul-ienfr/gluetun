package jobs

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/egress"
)

type recordingProber struct {
	failing    map[Transport]bool
	transports []Transport
}

func (p *recordingProber) Probe(_ context.Context, transport Transport,
	_ string,
) error {
	p.transports = append(p.transports, transport)
	if p.failing[transport] {
		return errors.New("probe failed")
	}
	return nil
}

func newPolicyExecutor(t *testing.T, vpn string, prober *recordingProber,
) *Executor {
	t.Helper()

	snapshotter := &fakeSnapshotter{
		snapshot: func(string) state.TunnelSnapshot { return executorSnapshot() },
	}
	preflight := NewPreflight(PreflightSettings{
		Catalog: switchCatalog{servers: map[string]Server{
			"new.example.com": switchServer("new.example.com"),
		}},
		Resolver:    switchResolver{addresses: []netip.Addr{netip.MustParseAddr("203.0.113.10")}},
		Prober:      prober,
		Credentials: Credentials{OpenVPN: true, WireGuard: true},
		Timeout:     5 * time.Second,
	})
	return NewExecutor(ExecutorSettings{
		StationID:   "station-1",
		Provider:    "nordvpn",
		VPN:         vpn,
		Tunnel:      &fakeTunnel{},
		Snapshotter: snapshotter,
		Verifier:    &fakeVerifier{results: []egress.Verification{verifiedIP("198.51.100.8")}},
		Preflight:   preflight,
		Now:         testTime,
	})
}

func Test_Inspect_TransportPolicy(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		vpn         string
		policy      []Transport
		failing     map[Transport]bool
		wantProbes  []Transport
		wantPlan    Transport
		wantWrapped error
	}{
		"auto defaults to ladder": {
			wantProbes: []Transport{TransportWireGuard},
			wantPlan:   TransportWireGuard,
		},
		"explicit VPN restricts ladder": {
			vpn:        VPNWireGuard,
			wantProbes: []Transport{TransportWireGuard},
			wantPlan:   TransportWireGuard,
		},
		"single transport": {
			policy:     []Transport{TransportOpenVPNUDP},
			wantProbes: []Transport{TransportOpenVPNUDP},
			wantPlan:   TransportOpenVPNUDP,
		},
		"ordered fallback": {
			policy:     []Transport{TransportOpenVPNTCP, TransportWireGuard},
			failing:    map[Transport]bool{TransportOpenVPNTCP: true},
			wantProbes: []Transport{TransportOpenVPNTCP, TransportWireGuard},
			wantPlan:   TransportWireGuard,
		},
		"duplicates are removed": {
			policy: []Transport{
				TransportOpenVPNTCP, TransportOpenVPNTCP, TransportWireGuard,
			},
			failing:    map[Transport]bool{TransportOpenVPNTCP: true},
			wantProbes: []Transport{TransportOpenVPNTCP, TransportWireGuard},
			wantPlan:   TransportWireGuard,
		},
		"unknown transport": {
			policy:      []Transport{"quic"},
			wantWrapped: ErrInvalidTarget,
		},
		"policy mismatches explicit VPN": {
			vpn:         VPNWireGuard,
			policy:      []Transport{TransportOpenVPNTCP},
			wantWrapped: ErrInvalidTarget,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			prober := &recordingProber{failing: testCase.failing}
			executor := newPolicyExecutor(t, testCase.vpn, prober)
			request := testSwitchRequest()
			request.Options.TransportPolicy = testCase.policy

			inspection, err := executor.Inspect(t.Context(), request)
			if testCase.wantWrapped != nil {
				if !errors.Is(err, testCase.wantWrapped) {
					t.Fatalf("error = %v, want %v", err,
						testCase.wantWrapped)
				}
				return
			}
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			if len(prober.transports) != len(testCase.wantProbes) {
				t.Fatalf("probes = %v, want %v", prober.transports,
					testCase.wantProbes)
			}
			for index, transport := range testCase.wantProbes {
				if prober.transports[index] != transport {
					t.Errorf("probe[%d] = %q, want %q", index,
						prober.transports[index], transport)
				}
			}
			if inspection.Plan.Transport != testCase.wantPlan {
				t.Errorf("plan transport = %q, want %q",
					inspection.Plan.Transport, testCase.wantPlan)
			}
			if inspection.Plan.Target.Hostname != "new.example.com" {
				t.Errorf("policy changed the server to %q",
					inspection.Plan.Target.Hostname)
			}
		})
	}
}

func Test_Manager_SubmitRotation_InvalidTransportPolicy(t *testing.T) {
	t.Parallel()

	executor := newPolicyExecutor(t, "", &recordingProber{})
	manager := NewManager(ManagerSettings{Executor: executor, Now: testTime})

	request := testRotationRequest("a.example.com")
	request.Options.TransportPolicy = []Transport{"quic"}

	_, err := manager.SubmitRotation(t.Context(), request)
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("error = %v, want ErrInvalidTarget", err)
	}
}
