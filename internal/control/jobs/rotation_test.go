package jobs

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/control/catalog"
	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/egress"
)

type fakeCatalogSource struct {
	pages   []catalog.Page
	queries []catalog.Query
}

func (f *fakeCatalogSource) Query(query catalog.Query) (catalog.Page, error) {
	f.queries = append(f.queries, query)
	if len(f.pages) == 0 {
		return catalog.Page{}, nil
	}
	page := f.pages[0]
	f.pages = f.pages[1:]
	return page, nil
}

func rotationCandidates(hostnames ...string) []RotationTarget {
	candidates := make([]RotationTarget, len(hostnames))
	for index, hostname := range hostnames {
		candidates[index] = RotationTarget{Hostname: hostname}
	}
	return candidates
}

func Test_ResolveRotationCandidates_PreservesOrder(t *testing.T) {
	t.Parallel()

	candidates, err := resolveRotationCandidates(RotationRequest{
		Candidates: rotationCandidates("c.example.com", "a.example.com",
			"b.example.com", "a.example.com"),
	}, nil)
	if err != nil {
		t.Fatalf("resolving candidates: %v", err)
	}
	expected := []string{"c.example.com", "a.example.com", "b.example.com"}
	if len(candidates) != len(expected) {
		t.Fatalf("candidates = %d, want %d", len(candidates), len(expected))
	}
	for index, hostname := range expected {
		if candidates[index].Hostname != hostname {
			t.Errorf("candidate[%d] = %q, want %q", index,
				candidates[index].Hostname, hostname)
		}
	}
}

func Test_ResolveRotationCandidates_ExcludesAndClamps(t *testing.T) {
	t.Parallel()

	excluded := netip.MustParseAddr("198.51.100.9")
	candidates, err := resolveRotationCandidates(RotationRequest{
		Candidates: []RotationTarget{
			{Hostname: "a.example.com", EndpointIP: excluded},
			{Hostname: "b.example.com"},
			{Hostname: "c.example.com"},
		},
		Constraints: RotationConstraints{
			ExcludeHostnames: []string{"c.example.com"},
			ExcludeIPs:       []netip.Addr{excluded},
			MaxCandidates:    2,
		},
	}, nil)
	if err != nil {
		t.Fatalf("resolving candidates: %v", err)
	}
	if len(candidates) != 1 || candidates[0].Hostname != "b.example.com" {
		t.Fatalf("candidates = %+v", candidates)
	}
}

func Test_ResolveRotationCandidates_RequiresOneSource(t *testing.T) {
	t.Parallel()

	_, err := resolveRotationCandidates(RotationRequest{}, nil)
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("error = %v, want ErrInvalidTarget", err)
	}

	_, err = resolveRotationCandidates(RotationRequest{
		Candidates: rotationCandidates("a.example.com"),
		Policy:     &RotationPolicy{},
	}, nil)
	if !errors.Is(err, ErrInvalidTarget) {
		t.Fatalf("error = %v, want ErrInvalidTarget", err)
	}
}

func Test_ResolveRotationCandidates_FromPolicy(t *testing.T) {
	t.Parallel()

	source := &fakeCatalogSource{pages: []catalog.Page{{
		Items: []catalog.ServerCandidate{
			{Hostname: "a.example.com"},
			{Hostname: "b.example.com"},
		},
	}}}
	candidates, err := resolveRotationCandidates(RotationRequest{
		Policy: &RotationPolicy{Countries: []string{"Netherlands"}},
	}, source)
	if err != nil {
		t.Fatalf("resolving candidates: %v", err)
	}
	if len(candidates) != 2 ||
		candidates[0].Hostname != "a.example.com" ||
		candidates[1].Hostname != "b.example.com" {
		t.Fatalf("candidates = %+v", candidates)
	}
	if len(source.queries) != 1 ||
		!slicesEqual(source.queries[0].Countries, []string{"Netherlands"}) {
		t.Fatalf("queries = %+v", source.queries)
	}
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func newRotationExecutor(t *testing.T, tunnel *fakeTunnel,
	verifier *fakeVerifier, servers map[string]Server,
) *Executor {
	t.Helper()

	snapshotter := &fakeSnapshotter{
		snapshot: func(string) state.TunnelSnapshot { return executorSnapshot() },
	}
	preflight := NewPreflight(PreflightSettings{
		Catalog:     switchCatalog{servers: servers},
		Resolver:    switchResolver{addresses: []netip.Addr{netip.MustParseAddr("203.0.113.10")}},
		Prober:      switchProber{},
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
	})
}

func testRotationRequest(hostnames ...string) RotationRequest {
	return RotationRequest{
		Candidates: rotationCandidates(hostnames...),
		Constraints: RotationConstraints{
			RequireNewIP: true,
		},
		Options: SwitchOptions{Timeout: 5 * time.Second},
	}
}

func Test_Executor_RotationFallsThroughCandidates(t *testing.T) {
	t.Parallel()

	tunnel := &fakeTunnel{}
	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.7"),
		verifiedIP("198.51.100.8"),
	}}
	executor := newRotationExecutor(t, tunnel, verifier, map[string]Server{
		"b.example.com": switchServer("b.example.com"),
		"c.example.com": switchServer("c.example.com"),
	})
	request := testRotationRequest("a.example.com", "b.example.com",
		"c.example.com")
	request.Candidates[1].ExpectedEgressIP = netip.MustParseAddr("203.0.113.99")

	machine := newTestMachine(t, KindRotate)
	result, err := executor.ExecuteRotation(t.Context(), machine, request)
	if err != nil {
		t.Fatalf("execute rotation: %v", err)
	}
	if result.Job.State != StateCommitted {
		t.Fatalf("state = %q, want committed", result.Job.State)
	}
	if result.Job.Target.Hostname != "c.example.com" {
		t.Errorf("target = %q, want c.example.com", result.Job.Target.Hostname)
	}
	if len(result.Job.Attempts) != 3 {
		t.Fatalf("attempts = %d, want 3", len(result.Job.Attempts))
	}
	if result.Job.Attempts[0].Reason != "preflight_failed" {
		t.Errorf("attempt 0 reason = %q", result.Job.Attempts[0].Reason)
	}
	if result.Job.Attempts[1].Reason != "egress_mismatch" {
		t.Errorf("attempt 1 reason = %q", result.Job.Attempts[1].Reason)
	}
	if result.Job.Attempts[2].Result != "committed" {
		t.Errorf("attempt 2 result = %q", result.Job.Attempts[2].Result)
	}
	// b applied, restored, c applied.
	if len(tunnel.applied) != 3 {
		t.Fatalf("apply calls = %d, want 3", len(tunnel.applied))
	}
	if tunnel.applied[1].ServerHostname != "old.example.com" {
		t.Errorf("second apply = %q, want old.example.com",
			tunnel.applied[1].ServerHostname)
	}
}

func Test_Executor_RotationExhaustedPreservesStation(t *testing.T) {
	t.Parallel()

	tunnel := &fakeTunnel{}
	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.7"),
		verifiedIP("198.51.100.7"),
		verifiedIP("198.51.100.7"),
	}}
	executor := newRotationExecutor(t, tunnel, verifier, map[string]Server{
		"a.example.com": switchServer("a.example.com"),
		"b.example.com": switchServer("b.example.com"),
		"c.example.com": switchServer("c.example.com"),
	})
	request := testRotationRequest("a.example.com", "b.example.com",
		"c.example.com")

	machine := newTestMachine(t, KindRotate)
	result, err := executor.ExecuteRotation(t.Context(), machine, request)
	if !errors.Is(err, ErrExhausted) {
		t.Fatalf("error = %v, want ErrExhausted", err)
	}
	if result.Job.State != StateExhausted {
		t.Fatalf("state = %q, want exhausted", result.Job.State)
	}
	if result.Job.StationPreserved == nil || !*result.Job.StationPreserved {
		t.Errorf("station_preserved = %v", result.Job.StationPreserved)
	}
	if result.Job.GlobalStateWritten == nil ||
		*result.Job.GlobalStateWritten {
		t.Errorf("global_state_written = %v", result.Job.GlobalStateWritten)
	}
	if len(result.Job.Attempts) != 3 {
		t.Fatalf("attempts = %d, want 3", len(result.Job.Attempts))
	}
	for index, attempt := range result.Job.Attempts {
		if attempt.Reason != "same_ip" {
			t.Errorf("attempt %d reason = %q, want same_ip", index,
				attempt.Reason)
		}
	}
	// Each failed candidate is restored before the next one.
	if len(tunnel.applied) != 6 {
		t.Fatalf("apply calls = %d, want 6", len(tunnel.applied))
	}
}

func Test_Manager_SubmitRotation(t *testing.T) {
	t.Parallel()

	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.7"),
		verifiedIP("198.51.100.8"),
	}}
	tunnel := &fakeTunnel{}
	executor := newRotationExecutor(t, tunnel, verifier, map[string]Server{
		"a.example.com": switchServer("a.example.com"),
		"b.example.com": switchServer("b.example.com"),
	})
	manager := NewManager(ManagerSettings{
		Executor: executor,
		Now:      testTime,
	})

	request := testRotationRequest("a.example.com", "b.example.com")
	request.RequestHash = "rotate-hash"
	request.IdempotencyKey = "rotate-1"
	submission, err := manager.SubmitRotation(t.Context(), request)
	if err != nil {
		t.Fatalf("submit rotation: %v", err)
	}
	if submission.Job.Kind != KindRotate {
		t.Errorf("kind = %q, want rotate", submission.Job.Kind)
	}
	if len(submission.Job.Candidates) != 2 ||
		submission.Job.Candidates[0] != "a.example.com" {
		t.Errorf("candidates = %+v", submission.Job.Candidates)
	}

	job := waitJob(t, manager, submission.Job.ID)
	if job.State != StateCommitted {
		t.Fatalf("state = %q, want committed", job.State)
	}
	if job.Target.Hostname != "b.example.com" {
		t.Errorf("target = %q, want b.example.com", job.Target.Hostname)
	}

	replayed, err := manager.SubmitRotation(t.Context(), request)
	if err != nil {
		t.Fatalf("replay rotation: %v", err)
	}
	if !replayed.Replayed || replayed.Job.ID != submission.Job.ID {
		t.Errorf("replay = %+v", replayed)
	}
}

func Test_Machine_RotationTransitions(t *testing.T) {
	t.Parallel()

	machine := newTestMachine(t, KindRotate)
	transitions := []State{
		StateValidating, StatePreflight, StatePreflight, StateDraining,
		StateApplying, StateRollingBack, StatePreflight, StateDraining,
		StateApplying, StateAwaitingTunnel, StateVerifyingEgress,
		StateRollingBack, StatePreflight,
	}
	for _, next := range transitions {
		err := machine.Transition(next)
		if err != nil {
			t.Fatalf("transition to %q: %v", next, err)
		}
	}
}
