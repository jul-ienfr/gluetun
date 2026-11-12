package transport

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestWatchdogCheck(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	watchdog := NewWatchdog(WatchdogSettings{
		StaleAfter: 10 * time.Second,
		Now:        func() time.Time { return now },
	})
	healthy := Health{
		InterfaceUp:  true,
		HandshakeAt:  now.Add(-time.Second),
		Status:       "running",
		DNSReachable: true,
	}

	testCases := map[string]struct {
		mutate   func(health *Health)
		expected Problem
	}{
		"healthy": {
			mutate:   func(*Health) {},
			expected: ProblemNone,
		},
		"interface down": {
			mutate:   func(health *Health) { health.InterfaceUp = false },
			expected: ProblemInterfaceDown,
		},
		"status not running": {
			mutate:   func(health *Health) { health.Status = "crashed" },
			expected: ProblemStatusNotRunning,
		},
		"handshake stale": {
			mutate:   func(health *Health) { health.HandshakeAt = now.Add(-time.Minute) },
			expected: ProblemHandshakeStale,
		},
		"handshake zero": {
			mutate:   func(health *Health) { health.HandshakeAt = time.Time{} },
			expected: ProblemHandshakeStale,
		},
		"dns unreachable": {
			mutate:   func(health *Health) { health.DNSReachable = false },
			expected: ProblemDNSUnreachable,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			health := healthy
			testCase.mutate(&health)
			problem, unhealthy := watchdog.Check(health)
			if problem != testCase.expected {
				t.Fatalf("expected %q, got %q", testCase.expected, problem)
			}
			if testCase.expected == ProblemNone && unhealthy {
				t.Fatal("healthy state reported unhealthy")
			}
			if testCase.expected != ProblemNone && !unhealthy {
				t.Fatal("unhealthy state reported healthy")
			}
		})
	}
}

type fakeReconnector struct {
	mutex sync.Mutex
	calls int
	err   error
}

func (r *fakeReconnector) Reconnect(ctx context.Context, transport Transport, target Target) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.calls++
	return r.err
}

func (r *fakeReconnector) count() int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.calls
}

func TestWatchdogHandleEscalates(t *testing.T) {
	t.Parallel()

	watchdog := NewWatchdog(WatchdogSettings{MaxReconnects: 2})
	reconnector := &fakeReconnector{}

	for i := 0; i < 2; i++ {
		reconnected, err := watchdog.Handle(context.Background(),
			ProblemInterfaceDown, reconnector, WireGuard, Target{Hostname: "server"})
		if err != nil {
			t.Fatalf("reconnect %d: %v", i, err)
		}
		if !reconnected {
			t.Fatalf("reconnect %d not attempted", i)
		}
	}

	_, err := watchdog.Handle(context.Background(), ProblemInterfaceDown,
		reconnector, WireGuard, Target{Hostname: "server"})
	if !errors.Is(err, ErrRepairNeeded) {
		t.Fatalf("expected ErrRepairNeeded, got %v", err)
	}
	if reconnector.count() != 2 {
		t.Fatalf("reconnections: expected 2, got %d", reconnector.count())
	}

	watchdog.Reset()
	reconnected, err := watchdog.Handle(context.Background(),
		ProblemInterfaceDown, reconnector, WireGuard, Target{Hostname: "server"})
	if err != nil || !reconnected {
		t.Fatalf("after reset: reconnected=%v err=%v", reconnected, err)
	}
	if reconnector.count() != 3 {
		t.Fatalf("reconnections after reset: %d", reconnector.count())
	}
}

type staticProbe struct {
	health Health
}

func (p staticProbe) Health(ctx context.Context, transport Transport, target Target) (Health, error) {
	return p.health, nil
}

func TestWatchdogRunExhaustsBudget(t *testing.T) {
	t.Parallel()

	watchdog := NewWatchdog(WatchdogSettings{
		Interval:      time.Millisecond,
		MaxReconnects: 3,
	})
	probe := staticProbe{health: Health{InterfaceUp: false}}
	reconnector := &fakeReconnector{}

	err := watchdog.Run(context.Background(), probe, reconnector,
		OpenVPNTCP, Target{Hostname: "server"})
	if !errors.Is(err, ErrRepairNeeded) {
		t.Fatalf("expected ErrRepairNeeded, got %v", err)
	}
	if reconnector.count() != 3 {
		t.Fatalf("reconnections: expected 3, got %d", reconnector.count())
	}
}

func TestWatchdogRunStopsOnContext(t *testing.T) {
	t.Parallel()

	watchdog := NewWatchdog(WatchdogSettings{Interval: time.Millisecond})
	probe := staticProbe{health: Health{
		InterfaceUp:  true,
		HandshakeAt:  time.Now(),
		Status:       "running",
		DNSReachable: true,
	}}
	reconnector := &fakeReconnector{}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- watchdog.Run(ctx, probe, reconnector, WireGuard,
			Target{Hostname: "server"})
	}()
	time.Sleep(5 * time.Millisecond)
	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if reconnector.count() != 0 {
		t.Fatalf("unexpected reconnections: %d", reconnector.count())
	}
}
