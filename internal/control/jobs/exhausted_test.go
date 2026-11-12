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

func newCooldownExecutor(t *testing.T, tunnel *fakeTunnel,
	verifier *fakeVerifier, cooldown CooldownSource,
	servers map[string]Server,
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
		Cooldown:    cooldown,
		Now:         testTime,
	})
}

func Test_Rotation_CooldownSkipsHostname(t *testing.T) {
	t.Parallel()

	cooldown := catalog.NewCooldown(catalog.CooldownOptions{
		Base: time.Minute,
		Max:  time.Hour,
	})
	tunnel := &fakeTunnel{}
	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.8"),
		verifiedIP("198.51.100.9"),
	}}
	executor := newCooldownExecutor(t, tunnel, verifier, cooldown,
		map[string]Server{
			"b.example.com": switchServer("b.example.com"),
			"c.example.com": switchServer("c.example.com"),
		})

	first := testRotationRequest("a.example.com", "b.example.com")
	machine := newTestMachine(t, KindRotate)
	result, err := executor.ExecuteRotation(t.Context(), machine, first)
	if err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	if result.Job.State != StateCommitted {
		t.Fatalf("first state = %q", result.Job.State)
	}
	if _, cooling := cooldown.Until("a.example.com"); !cooling {
		t.Fatal("a.example.com should be cooling down after its failure")
	}

	second := testRotationRequest("a.example.com", "c.example.com")
	machine = newTestMachine(t, KindRotate)
	result, err = executor.ExecuteRotation(t.Context(), machine, second)
	if err != nil {
		t.Fatalf("second rotation: %v", err)
	}
	if result.Job.State != StateCommitted {
		t.Fatalf("second state = %q", result.Job.State)
	}
	if result.Job.Target.Hostname != "c.example.com" {
		t.Fatalf("target = %q, want c.example.com",
			result.Job.Target.Hostname)
	}
	attempts := result.Job.Attempts
	if len(attempts) != 2 {
		t.Fatalf("attempts = %d, want 2", len(attempts))
	}
	if attempts[0].Reason != "cooldown" || attempts[0].Result != "skipped" {
		t.Errorf("first attempt = %+v, want a cooldown skip", attempts[0])
	}
	if attempts[1].Result != "committed" {
		t.Errorf("second attempt = %+v, want committed", attempts[1])
	}
}

func Test_Rotation_CooldownExhaustedPreservesStation(t *testing.T) {
	t.Parallel()

	cooldown := catalog.NewCooldown(catalog.CooldownOptions{
		Base: time.Minute,
		Max:  time.Hour,
	})
	cooldown.RecordFailure("a.example.com", testTime())
	tunnel := &fakeTunnel{}
	verifier := &fakeVerifier{}
	executor := newCooldownExecutor(t, tunnel, verifier, cooldown,
		map[string]Server{"a.example.com": switchServer("a.example.com")})

	request := testRotationRequest("a.example.com")
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
	if len(result.Job.Attempts) != 1 ||
		result.Job.Attempts[0].Reason != "cooldown" {
		t.Errorf("attempts = %+v, want one cooldown skip",
			result.Job.Attempts)
	}
	if len(tunnel.applied) != 0 {
		t.Errorf("tunnel applied %d times, want 0", len(tunnel.applied))
	}
}

func Test_Rotation_SuccessClearsCooldown(t *testing.T) {
	t.Parallel()

	cooldown := catalog.NewCooldown(catalog.CooldownOptions{})
	cooldown.RecordFailure("b.example.com", testTime())
	cooldown.RecordSuccess("b.example.com")

	tunnel := &fakeTunnel{}
	verifier := &fakeVerifier{results: []egress.Verification{
		verifiedIP("198.51.100.8"),
	}}
	executor := newCooldownExecutor(t, tunnel, verifier, cooldown,
		map[string]Server{"b.example.com": switchServer("b.example.com")})

	request := testRotationRequest("b.example.com")
	machine := newTestMachine(t, KindRotate)
	result, err := executor.ExecuteRotation(t.Context(), machine, request)
	if err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if result.Job.State != StateCommitted {
		t.Fatalf("state = %q, want committed", result.Job.State)
	}
	if _, cooling := cooldown.Until("b.example.com"); cooling {
		t.Fatal("a committed hostname should not be cooling down")
	}
}
