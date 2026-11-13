package jobs

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/verify"
)

type fakeRollbackTunnel struct {
	applyErr error
	awaitErr error
	applied  []state.TunnelSnapshot
	awaited  []state.TunnelSnapshot
	calls    []string
}

func (f *fakeRollbackTunnel) ApplySnapshot(ctx context.Context,
	snapshot state.TunnelSnapshot,
) error {
	contextErr := ctx.Err()
	if contextErr != nil {
		return contextErr
	}
	f.applied = append(f.applied, snapshot)
	f.calls = append(f.calls, "apply")
	return f.applyErr
}

func (f *fakeRollbackTunnel) AwaitSnapshot(ctx context.Context,
	snapshot state.TunnelSnapshot,
) error {
	contextErr := ctx.Err()
	if contextErr != nil {
		return contextErr
	}
	f.awaited = append(f.awaited, snapshot)
	f.calls = append(f.calls, "await")
	return f.awaitErr
}

type fakeEgressVerifier struct {
	verification egress.Verification
	err          error
	requests     []verify.Request
	calls        []string
}

func (f *fakeEgressVerifier) Verify(ctx context.Context,
	request verify.Request,
) (verification egress.Verification, err error) {
	contextErr := ctx.Err()
	if contextErr != nil {
		return egress.Verification{}, contextErr
	}
	f.requests = append(f.requests, request)
	f.calls = append(f.calls, "verify")
	return f.verification, f.err
}

func testRollbackSnapshot() state.TunnelSnapshot {
	provenAt := testTime()
	return state.TunnelSnapshot{
		SchemaVersion:  state.SchemaVersion,
		StationID:      "station-1",
		TakenAt:        testTime(),
		Trigger:        "switch",
		Settings:       state.TunnelSettings{Provider: "mullvad", VPN: "wireguard"},
		ServerHostname: "ch-1.example.com",
		EndpointIP:     netip.MustParseAddr("203.0.113.10"),
		Transport:      "wireguard",
		VPNStatus:      "running",
		Egress: &egress.Verification{
			Verified: true,
			IP:       netip.MustParseAddr("198.51.100.7"),
		},
		ProvenAt: &provenAt,
	}
}

func rollbackSnapshotPtr() *state.TunnelSnapshot {
	snapshot := testRollbackSnapshot()
	return &snapshot
}

func Test_Rollback_Run(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		state           State
		snapshot        *state.TunnelSnapshot
		applyErr        error
		awaitErr        error
		verification    egress.Verification
		verifyErr       error
		expectedErr     error
		expectedState   State
		expectedEvent   string
		expectedCalls   []string
		expectedProven  bool
		expectedApplied bool
	}{
		"success from applying": {
			state:           StateApplying,
			snapshot:        rollbackSnapshotPtr(),
			verification:    *testRollbackSnapshot().Egress,
			expectedState:   StateRolledBack,
			expectedEvent:   EventRolledBack,
			expectedCalls:   []string{"apply", "await", "verify"},
			expectedProven:  true,
			expectedApplied: true,
		},
		"success from awaiting tunnel": {
			state:           StateAwaitingTunnel,
			snapshot:        rollbackSnapshotPtr(),
			verification:    *testRollbackSnapshot().Egress,
			expectedState:   StateRolledBack,
			expectedEvent:   EventRolledBack,
			expectedCalls:   []string{"apply", "await", "verify"},
			expectedProven:  true,
			expectedApplied: true,
		},
		"success from verifying egress": {
			state:           StateVerifyingEgress,
			snapshot:        rollbackSnapshotPtr(),
			verification:    *testRollbackSnapshot().Egress,
			expectedState:   StateRolledBack,
			expectedEvent:   EventRolledBack,
			expectedCalls:   []string{"apply", "await", "verify"},
			expectedProven:  true,
			expectedApplied: true,
		},
		"success from rolling back": {
			state:           StateRollingBack,
			snapshot:        rollbackSnapshotPtr(),
			verification:    *testRollbackSnapshot().Egress,
			expectedState:   StateRolledBack,
			expectedEvent:   EventRolledBack,
			expectedCalls:   []string{"apply", "await", "verify"},
			expectedProven:  true,
			expectedApplied: true,
		},
		"apply failure": {
			state:           StateApplying,
			snapshot:        rollbackSnapshotPtr(),
			applyErr:        errors.New("settings rejected"),
			expectedErr:     ErrRollbackApply,
			expectedState:   StateFailedDegraded,
			expectedEvent:   EventFailedDegraded,
			expectedCalls:   []string{"apply"},
			expectedProven:  false,
			expectedApplied: false,
		},
		"await failure": {
			state:           StateApplying,
			snapshot:        rollbackSnapshotPtr(),
			awaitErr:        errors.New("handshake timeout"),
			expectedErr:     ErrRollbackAwait,
			expectedState:   StateFailedDegraded,
			expectedEvent:   EventFailedDegraded,
			expectedCalls:   []string{"apply", "await"},
			expectedProven:  false,
			expectedApplied: true,
		},
		"verification failure": {
			state:           StateApplying,
			snapshot:        rollbackSnapshotPtr(),
			verifyErr:       errors.New("no source"),
			expectedErr:     ErrRollbackVerify,
			expectedState:   StateFailedDegraded,
			expectedEvent:   EventFailedDegraded,
			expectedCalls:   []string{"apply", "await", "verify"},
			expectedProven:  false,
			expectedApplied: true,
		},
		"fresh egress not verified": {
			state:           StateApplying,
			snapshot:        rollbackSnapshotPtr(),
			verification:    egress.Verification{Verified: false},
			expectedErr:     ErrRollbackUnproven,
			expectedState:   StateFailedDegraded,
			expectedEvent:   EventFailedDegraded,
			expectedCalls:   []string{"apply", "await", "verify", "verify", "verify"},
			expectedProven:  false,
			expectedApplied: true,
		},
		"fresh egress mismatch": {
			state:    StateApplying,
			snapshot: rollbackSnapshotPtr(),
			verification: egress.Verification{
				Verified: true,
				IP:       netip.MustParseAddr("198.51.100.99"),
			},
			expectedErr:     ErrRollbackMismatch,
			expectedState:   StateFailedDegraded,
			expectedEvent:   EventFailedDegraded,
			expectedCalls:   []string{"apply", "await", "verify"},
			expectedProven:  false,
			expectedApplied: true,
		},
		"snapshot without egress": {
			state: StateApplying,
			snapshot: func() *state.TunnelSnapshot {
				snapshot := testRollbackSnapshot()
				snapshot.Egress = nil
				return &snapshot
			}(),
			verification:    *testRollbackSnapshot().Egress,
			expectedState:   StateRolledBack,
			expectedEvent:   EventRolledBack,
			expectedCalls:   []string{"apply", "await", "verify"},
			expectedProven:  true,
			expectedApplied: true,
		},
		"snapshot egress never verified": {
			state: StateApplying,
			snapshot: func() *state.TunnelSnapshot {
				snapshot := testRollbackSnapshot()
				snapshot.Egress = &egress.Verification{Verified: false}
				return &snapshot
			}(),
			verification:    *testRollbackSnapshot().Egress,
			expectedState:   StateRolledBack,
			expectedEvent:   EventRolledBack,
			expectedCalls:   []string{"apply", "await", "verify"},
			expectedProven:  true,
			expectedApplied: true,
		},
		"snapshot egress IP missing": {
			state: StateApplying,
			snapshot: func() *state.TunnelSnapshot {
				snapshot := testRollbackSnapshot()
				snapshot.Egress = &egress.Verification{Verified: true}
				return &snapshot
			}(),
			verification:    *testRollbackSnapshot().Egress,
			expectedState:   StateRolledBack,
			expectedEvent:   EventRolledBack,
			expectedCalls:   []string{"apply", "await", "verify"},
			expectedProven:  true,
			expectedApplied: true,
		},
		"no snapshot": {
			state:           StateApplying,
			snapshot:        nil,
			expectedErr:     ErrNoSnapshot,
			expectedState:   StateApplying,
			expectedEvent:   "",
			expectedCalls:   []string{},
			expectedProven:  false,
			expectedApplied: false,
		},
		"invalid starting state": {
			state:           StateQueued,
			snapshot:        rollbackSnapshotPtr(),
			expectedErr:     ErrInvalidTransition,
			expectedState:   StateQueued,
			expectedEvent:   "",
			expectedCalls:   []string{},
			expectedProven:  false,
			expectedApplied: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tunnel := &fakeRollbackTunnel{
				applyErr: testCase.applyErr,
				awaitErr: testCase.awaitErr,
			}
			verifier := &fakeEgressVerifier{
				verification: testCase.verification,
				err:          testCase.verifyErr,
			}
			rollback := NewRollback(RollbackSettings{
				Tunnel:   tunnel,
				Verifier: verifier,
			})

			job := testJob()
			job.State = testCase.state
			job.SnapshotBefore = testCase.snapshot
			machine := NewMachine(job, testClock(testTime()))

			result, err := rollback.Run(context.Background(), machine)

			assertRollbackRun(t, testCase.expectedErr, testCase.expectedState,
				testCase.expectedEvent, testCase.expectedCalls,
				testCase.expectedProven, testCase.expectedApplied,
				testCase.verification, err, result, machine, tunnel, verifier)
		})
	}
}

func assertRollbackRun(t *testing.T, expectedErr error, expectedState State,
	expectedEvent string, expectedCalls []string, expectedProven,
	expectedApplied bool, verification egress.Verification, err error,
	result RollbackResult, machine *Machine, tunnel *fakeRollbackTunnel,
	verifier *fakeEgressVerifier,
) {
	t.Helper()

	if expectedErr != nil {
		if !errors.Is(err, expectedErr) {
			t.Fatalf("error = %v, want %v", err, expectedErr)
		}
	} else if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if machine.Job().State != expectedState {
		t.Errorf("state = %s, want %s", machine.Job().State, expectedState)
	}
	if result.Event != expectedEvent {
		t.Errorf("event = %q, want %q", result.Event, expectedEvent)
	}
	if result.Proven != expectedProven {
		t.Errorf("proven = %t, want %t", result.Proven, expectedProven)
	}
	if result.Applied != expectedApplied {
		t.Errorf("applied = %t, want %t", result.Applied, expectedApplied)
	}

	calls := append([]string{}, tunnel.calls...)
	calls = append(calls, verifier.calls...)
	if !slices.Equal(calls, expectedCalls) {
		t.Fatalf("calls = %v, want %v", calls, expectedCalls)
	}

	if !expectedProven {
		return
	}
	if machine.Job().Verification == nil {
		t.Fatalf("verification was not recorded")
	}
	if machine.Job().Verification.IP != verification.IP {
		t.Errorf("verification IP = %s, want %s",
			machine.Job().Verification.IP, verification.IP)
	}
	if len(verifier.requests) != 1 || !verifier.requests[0].Fresh {
		t.Errorf("verification was not fresh: %v", verifier.requests)
	}
}

func Test_Rollback_Run_AppliesSnapshot(t *testing.T) {
	t.Parallel()

	snapshot := testRollbackSnapshot()
	tunnel := &fakeRollbackTunnel{}
	verifier := &fakeEgressVerifier{verification: *snapshot.Egress}
	rollback := NewRollback(RollbackSettings{
		Tunnel:   tunnel,
		Verifier: verifier,
	})

	job := testJob()
	job.State = StateApplying
	job.SnapshotBefore = &snapshot
	machine := NewMachine(job, testClock(testTime()))

	_, err := rollback.Run(context.Background(), machine)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tunnel.applied) != 1 {
		t.Fatalf("applied %d snapshots, want 1", len(tunnel.applied))
	}
	if tunnel.applied[0].ServerHostname != snapshot.ServerHostname {
		t.Errorf("applied hostname %q, want %q",
			tunnel.applied[0].ServerHostname, snapshot.ServerHostname)
	}
	if len(tunnel.awaited) != 1 ||
		tunnel.awaited[0].ServerHostname != snapshot.ServerHostname {
		t.Errorf("awaited snapshot does not match the applied one")
	}
}

func Test_Rollback_Run_CanceledContext(t *testing.T) {
	t.Parallel()

	snapshot := testRollbackSnapshot()
	tunnel := &fakeRollbackTunnel{}
	verifier := &fakeEgressVerifier{verification: *snapshot.Egress}
	rollback := NewRollback(RollbackSettings{
		Tunnel:   tunnel,
		Verifier: verifier,
	})

	job := testJob()
	job.State = StateApplying
	job.SnapshotBefore = &snapshot
	machine := NewMachine(job, testClock(testTime()))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, _ = rollback.Run(ctx, machine)

	if machine.Job().State != StateFailedDegraded {
		t.Errorf("state = %s, want %s",
			machine.Job().State, StateFailedDegraded)
	}
}

func Test_NewRollback_Panics(t *testing.T) {
	t.Parallel()

	testCases := map[string]RollbackSettings{
		"nil tunnel": {
			Verifier: &fakeEgressVerifier{},
		},
		"nil verifier": {
			Tunnel: &fakeRollbackTunnel{},
		},
	}

	for name, settings := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Errorf("expected a panic")
				}
			}()
			NewRollback(settings)
		})
	}
}
