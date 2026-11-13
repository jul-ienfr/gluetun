package jobs

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/verify"
)

type switchCatalog struct {
	servers map[string]Server
}

func (f switchCatalog) Lookup(_ context.Context, hostname string) (Server, bool, error) {
	server, found := f.servers[hostname]
	return server, found, nil
}

type switchResolver struct {
	addresses []netip.Addr
	err       error
}

func (f switchResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return f.addresses, f.err
}

type switchProber struct {
	failing map[Transport]bool
}

func (f switchProber) Probe(_ context.Context, transport Transport, _ string) error {
	if f.failing[transport] {
		return errors.New("probe failed")
	}
	return nil
}

type fakeSnapshotter struct {
	snapshot func(trigger string) state.TunnelSnapshot
	err      error
	calls    int
}

func (f *fakeSnapshotter) Capture(_ context.Context, trigger string) (state.TunnelSnapshot, error) {
	f.calls++
	if f.err != nil {
		return state.TunnelSnapshot{}, f.err
	}
	return f.snapshot(trigger), nil
}

type fakeTunnel struct {
	applied  []state.TunnelSnapshot
	applyErr error
	awaitErr error
	notify   chan struct{}
	release  <-chan struct{}
}

func (f *fakeTunnel) ApplySnapshot(_ context.Context, snapshot state.TunnelSnapshot) error {
	if f.notify != nil {
		select {
		case f.notify <- struct{}{}:
		default:
		}
	}
	if f.release != nil {
		<-f.release
	}
	f.applied = append(f.applied, snapshot)
	return f.applyErr
}

func (f *fakeTunnel) AwaitSnapshot(_ context.Context, _ state.TunnelSnapshot) error {
	return f.awaitErr
}

type fakeVerifier struct {
	results []egress.Verification
	errs    []error
	calls   int
}

func (f *fakeVerifier) Verify(_ context.Context, _ verify.Request) (egress.Verification, error) {
	index := f.calls
	f.calls++
	if index < len(f.errs) && f.errs[index] != nil {
		return egress.Verification{}, f.errs[index]
	}
	if index < len(f.results) {
		return f.results[index], nil
	}
	return egress.Verification{}, errors.New("no verification scripted")
}

func executorSnapshot() state.TunnelSnapshot {
	verified := egress.Verification{
		Verified: true,
		IP:       netip.MustParseAddr("198.51.100.7"),
	}
	return state.TunnelSnapshot{
		SchemaVersion: state.SchemaVersion,
		StationID:     "station-1",
		TakenAt:       testTime(),
		Trigger:       "switch",
		Settings: state.TunnelSettings{
			Provider:  "nordvpn",
			VPN:       "wireguard",
			Hostnames: []string{"old.example.com"},
		},
		ServerHostname: "old.example.com",
		EndpointIP:     netip.MustParseAddr("203.0.113.10"),
		Transport:      "wireguard",
		Egress:         &verified,
	}
}

func switchServer(hostname string) Server {
	return Server{
		Hostname:  hostname,
		IPs:       []netip.Addr{netip.MustParseAddr("203.0.113.10")},
		Protocols: []string{"wireguard", "openvpn"},
	}
}

func newTestExecutor(t *testing.T, tunnel *fakeTunnel,
	verifier *fakeVerifier, prober switchProber,
) (*Executor, *fakeSnapshotter) {
	t.Helper()

	snapshotter := &fakeSnapshotter{
		snapshot: func(string) state.TunnelSnapshot { return executorSnapshot() },
	}
	preflight := NewPreflight(PreflightSettings{
		Catalog: switchCatalog{servers: map[string]Server{
			"old.example.com": switchServer("old.example.com"),
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
		Tunnel:      tunnel,
		Snapshotter: snapshotter,
		Verifier:    verifier,
		Preflight:   preflight,
		Now:         testTime,
	}), snapshotter
}

func testSwitchRequest() SwitchRequest {
	return SwitchRequest{
		Kind:   KindSwitch,
		Target: SwitchTarget{Hostname: "new.example.com"},
		Constraints: SwitchConstraints{
			RequireNewIP: true,
		},
		Options: SwitchOptions{Timeout: 5 * time.Second},
	}
}

func newTestMachine(t *testing.T, kind Kind) *Machine {
	t.Helper()
	return NewMachine(Job{
		ID:        "job-1",
		Kind:      kind,
		StationID: "station-1",
		CreatedAt: testTime(),
	}, testTime)
}

func verifiedIP(value string) egress.Verification {
	return egress.Verification{
		Verified: true,
		IP:       netip.MustParseAddr(value),
	}
}

func Test_Executor_Switch_Committed(t *testing.T) {
	t.Parallel()

	tunnel := &fakeTunnel{}
	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.8"),
	}}
	executor, snapshotter := newTestExecutor(t, tunnel, verifier,
		switchProber{})
	request := testSwitchRequest()

	inspection, err := executor.Inspect(t.Context(), request)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if inspection.Noop {
		t.Fatal("inspection reported a noop")
	}
	if inspection.Plan.Transport != TransportWireGuard {
		t.Errorf("transport = %q, want wireguard", inspection.Plan.Transport)
	}

	machine := newTestMachine(t, KindSwitch)
	result, err := executor.Execute(t.Context(), machine, request, inspection)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Job.State != StateCommitted {
		t.Fatalf("state = %q, want committed", result.Job.State)
	}
	if result.Job.Verification == nil ||
		result.Job.Verification.IP != netip.MustParseAddr("198.51.100.8") {
		t.Errorf("verification = %+v", result.Job.Verification)
	}
	if len(tunnel.applied) != 1 {
		t.Fatalf("apply calls = %d, want 1", len(tunnel.applied))
	}
	if tunnel.applied[0].ServerHostname != "new.example.com" {
		t.Errorf("applied hostname = %q", tunnel.applied[0].ServerHostname)
	}
	if result.Job.SnapshotAfter == nil {
		t.Error("snapshot after is missing")
	}
	if snapshotter.calls < 2 {
		t.Errorf("snapshot calls = %d, want at least 2", snapshotter.calls)
	}
	if len(result.Job.Attempts) != 1 ||
		result.Job.Attempts[0].Result != "committed" {
		t.Errorf("attempts = %+v", result.Job.Attempts)
	}
}

func Test_Executor_Switch_Gates(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		request       func() SwitchRequest
		verifications []egress.Verification
		wantState     State
		wantError     error
	}{
		"egress mismatch": {
			request: func() SwitchRequest {
				request := testSwitchRequest()
				request.Target.ExpectedEgressIP = netip.MustParseAddr("198.51.100.9")
				return request
			},
			verifications: []egress.Verification{
				verifiedIP("198.51.100.8"),
				verifiedIP("198.51.100.7"),
			},
			wantState: StateRolledBack,
			wantError: ErrEgressMismatch,
		},
		"same ip": {
			request: testSwitchRequest,
			verifications: []egress.Verification{
				verifiedIP("198.51.100.7"),
				verifiedIP("198.51.100.7"),
			},
			wantState: StateRolledBack,
			wantError: ErrSameIP,
		},
		"unverified egress": {
			request: testSwitchRequest,
			verifications: []egress.Verification{
				{Verified: false},
				{Verified: false},
				{Verified: false},
				verifiedIP("198.51.100.7"),
			},
			wantState: StateRolledBack,
			wantError: ErrEgressUnverified,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tunnel := &fakeTunnel{}
			verifier := &fakeVerifier{results: testCase.verifications}
			executor, _ := newTestExecutor(t, tunnel, verifier,
				switchProber{})
			request := testCase.request()

			inspection, err := executor.Inspect(t.Context(), request)
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			machine := newTestMachine(t, KindSwitch)
			_, err = executor.Execute(t.Context(), machine, request,
				inspection)
			if !errors.Is(err, testCase.wantError) {
				t.Fatalf("error = %v, want %v", err, testCase.wantError)
			}
			if machine.Job().State != testCase.wantState {
				t.Errorf("state = %q, want %q", machine.Job().State,
					testCase.wantState)
			}
			if len(tunnel.applied) != 2 {
				t.Errorf("apply calls = %d, want 2 (switch then rollback)",
					len(tunnel.applied))
			}
		})
	}
}

func Test_Executor_Inspect_Errors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		request   func() SwitchRequest
		prober    switchProber
		wantError error
	}{
		"unknown target": {
			request: func() SwitchRequest {
				request := testSwitchRequest()
				request.Target.Hostname = "missing.example.com"
				return request
			},
			wantError: ErrUnknownTarget,
		},
		"excluded endpoint": {
			request: func() SwitchRequest {
				request := testSwitchRequest()
				request.Target.EndpointIP = netip.MustParseAddr("203.0.113.10")
				request.Constraints.ForbiddenIPs = []netip.Addr{
					netip.MustParseAddr("203.0.113.10"),
				}
				return request
			},
			wantError: ErrTargetExcluded,
		},
		"all transports unreachable": {
			request: testSwitchRequest,
			prober: switchProber{failing: map[Transport]bool{
				TransportWireGuard:  true,
				TransportOpenVPNUDP: true,
				TransportOpenVPNTCP: true,
			}},
			wantError: ErrEndpointUnreachable,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			executor, _ := newTestExecutor(t, &fakeTunnel{},
				&fakeVerifier{}, testCase.prober)
			_, err := executor.Inspect(t.Context(), testCase.request())
			if !errors.Is(err, testCase.wantError) {
				t.Fatalf("error = %v, want %v", err, testCase.wantError)
			}
		})
	}
}

func Test_Executor_Inspect_TransportFallback(t *testing.T) {
	t.Parallel()

	executor, _ := newTestExecutor(t, &fakeTunnel{}, &fakeVerifier{},
		switchProber{failing: map[Transport]bool{TransportWireGuard: true}})

	inspection, err := executor.Inspect(t.Context(), testSwitchRequest())
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if inspection.Plan.Transport != TransportOpenVPNUDP {
		t.Errorf("transport = %q, want openvpn-udp",
			inspection.Plan.Transport)
	}
	if len(inspection.Plan.Warnings) == 0 {
		t.Error("warnings are empty")
	}
}

func Test_Executor_transportLadder_FollowsExplicitVPN(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		executor *Executor
		policy   []Transport
		expected []Transport
	}{
		"non explicit uses the full ladder": {
			executor: &Executor{vpn: VPNOpenVPN, vpnExplicit: false},
			expected: []Transport{
				TransportWireGuard, TransportOpenVPNUDP, TransportOpenVPNTCP,
			},
		},
		"explicit openvpn stays on openvpn": {
			executor: &Executor{vpn: VPNOpenVPN, vpnExplicit: true},
			expected: []Transport{TransportOpenVPNUDP, TransportOpenVPNTCP},
		},
		"non explicit accepts a wireguard policy": {
			executor: &Executor{vpn: VPNOpenVPN, vpnExplicit: false},
			policy:   []Transport{TransportWireGuard},
			expected: []Transport{TransportWireGuard},
		},
		"explicit openvpn rejects a wireguard policy": {
			executor: &Executor{vpn: VPNOpenVPN, vpnExplicit: true},
			policy:   []Transport{TransportWireGuard},
			expected: nil,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ladder, err := testCase.executor.transportLadder(testCase.policy)
			if testCase.expected == nil {
				if err == nil {
					t.Fatal("expected an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("transport ladder: %v", err)
			}
			if !slices.Equal(testCase.expected, ladder) {
				t.Fatalf("ladder = %v, want %v", ladder, testCase.expected)
			}
		})
	}
}

func Test_Executor_Inspect_Noop(t *testing.T) {
	t.Parallel()

	executor, _ := newTestExecutor(t, &fakeTunnel{}, &fakeVerifier{},
		switchProber{})
	request := SwitchRequest{
		Kind: KindSwitch,
		Target: SwitchTarget{
			Hostname:   "old.example.com",
			EndpointIP: netip.MustParseAddr("203.0.113.10"),
		},
		Options: SwitchOptions{Timeout: 5 * time.Second},
	}

	inspection, err := executor.Inspect(t.Context(), request)
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if !inspection.Noop {
		t.Error("inspection did not report a noop")
	}
	if inspection.WouldCutTunnel {
		t.Error("noop would cut the tunnel")
	}
}

func Test_Executor_ExecuteRollback(t *testing.T) {
	t.Parallel()

	tunnel := &fakeTunnel{}
	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.7"),
	}}
	executor, _ := newTestExecutor(t, tunnel, verifier, switchProber{})
	snapshot := executorSnapshot()
	machine := NewMachine(Job{
		ID:             "job-rollback",
		Kind:           KindRollback,
		StationID:      "station-1",
		CreatedAt:      testTime(),
		SnapshotBefore: &snapshot,
	}, testTime)

	result, err := executor.ExecuteRollback(t.Context(), machine)
	if err != nil {
		t.Fatalf("execute rollback: %v", err)
	}
	if result.Job.State != StateRolledBack {
		t.Fatalf("state = %q, want rolled_back", result.Job.State)
	}
	if len(tunnel.applied) != 1 {
		t.Errorf("apply calls = %d, want 1", len(tunnel.applied))
	}
}

func Test_Executor_ExecuteRollback_NoSnapshot(t *testing.T) {
	t.Parallel()

	executor, _ := newTestExecutor(t, &fakeTunnel{}, &fakeVerifier{},
		switchProber{})
	machine := newTestMachine(t, KindRollback)

	result, err := executor.ExecuteRollback(t.Context(), machine)
	if !errors.Is(err, ErrNoSnapshot) {
		t.Fatalf("error = %v, want %v", err, ErrNoSnapshot)
	}
	if result.Job.State != StateRejected {
		t.Errorf("state = %q, want rejected", result.Job.State)
	}
}

func Test_Executor_ExecuteRollback_UnprovenBaseline(t *testing.T) {
	t.Parallel()

	tunnel := &fakeTunnel{}
	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.7"),
	}}
	executor, _ := newTestExecutor(t, tunnel, verifier, switchProber{})
	snapshot := executorSnapshot()
	snapshot.Egress = nil
	machine := NewMachine(Job{
		ID:             "job-rollback",
		Kind:           KindRollback,
		StationID:      "station-1",
		CreatedAt:      testTime(),
		SnapshotBefore: &snapshot,
	}, testTime)

	result, err := executor.ExecuteRollback(t.Context(), machine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Job.State != StateRolledBack {
		t.Errorf("state = %q, want rolled_back", result.Job.State)
	}
	if len(tunnel.applied) != 1 {
		t.Errorf("apply calls = %d, want 1", len(tunnel.applied))
	}
}
