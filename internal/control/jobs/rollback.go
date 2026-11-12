package jobs

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/verify"
)

// Rollback events.
const (
	EventRolledBack     = "job.rolled_back"
	EventFailedDegraded = "job.failed_degraded"
)

// Rollback errors.
var (
	ErrNoSnapshot       = errors.New("no snapshot to roll back to")
	ErrRollbackApply    = errors.New("rollback apply failed")
	ErrRollbackAwait    = errors.New("rollback tunnel await failed")
	ErrRollbackVerify   = errors.New("rollback egress verification failed")
	ErrRollbackUnproven = errors.New("rollback egress unproven")
	ErrRollbackMismatch = errors.New("rollback egress mismatch")
)

const (
	defaultRollbackApplyTimeout  = 30 * time.Second
	defaultRollbackAwaitTimeout  = 30 * time.Second
	defaultRollbackVerifyTimeout = 30 * time.Second
)

// Tunnel is the VPN control surface used by switch and rollback jobs.
type Tunnel interface {
	ApplySnapshot(ctx context.Context, snapshot state.TunnelSnapshot) error
	AwaitSnapshot(ctx context.Context, snapshot state.TunnelSnapshot) error
}

// EgressVerifier runs a fresh egress verification.
type EgressVerifier interface {
	Verify(ctx context.Context, request verify.Request) (
		verification egress.Verification, err error)
}

// RollbackSettings configure the rollback transaction.
type RollbackSettings struct {
	Tunnel        Tunnel
	Verifier      EgressVerifier
	ApplyTimeout  time.Duration
	AwaitTimeout  time.Duration
	VerifyTimeout time.Duration
}

// Rollback re-applies the previous snapshot and re-proves its egress IP.
type Rollback struct {
	tunnel        Tunnel
	verifier      EgressVerifier
	applyTimeout  time.Duration
	awaitTimeout  time.Duration
	verifyTimeout time.Duration
}

// NewRollback creates a rollback transaction.
func NewRollback(settings RollbackSettings) *Rollback {
	if settings.Tunnel == nil {
		panic("rollback tunnel is nil")
	}
	if settings.Verifier == nil {
		panic("rollback verifier is nil")
	}

	applyTimeout := settings.ApplyTimeout
	if applyTimeout <= 0 {
		applyTimeout = defaultRollbackApplyTimeout
	}
	awaitTimeout := settings.AwaitTimeout
	if awaitTimeout <= 0 {
		awaitTimeout = defaultRollbackAwaitTimeout
	}
	verifyTimeout := settings.VerifyTimeout
	if verifyTimeout <= 0 {
		verifyTimeout = defaultRollbackVerifyTimeout
	}

	return &Rollback{
		tunnel:        settings.Tunnel,
		verifier:      settings.Verifier,
		applyTimeout:  applyTimeout,
		awaitTimeout:  awaitTimeout,
		verifyTimeout: verifyTimeout,
	}
}

// RollbackResult is the outcome of one rollback attempt.
type RollbackResult struct {
	Snapshot     state.TunnelSnapshot
	Verification egress.Verification
	Applied      bool
	Proven       bool
	Event        string
}

// Run re-applies the snapshot taken before the job, waits for the tunnel,
// verifies the old egress IP once, and drives the machine to rolled_back or
// failed_degraded. It never retries.
func (r *Rollback) Run(ctx context.Context, machine *Machine) (
	result RollbackResult, err error,
) {
	job := machine.Job()
	if job.SnapshotBefore == nil {
		return RollbackResult{}, fmt.Errorf("%w: job %q", ErrNoSnapshot, job.ID)
	}
	snapshot := *job.SnapshotBefore
	result.Snapshot = snapshot

	err = enterRollback(machine)
	if err != nil {
		return RollbackResult{}, err
	}

	err = verifyExpectedEgress(snapshot)
	if err != nil {
		return r.degrade(machine, result, err)
	}

	applyCtx, cancel := context.WithTimeout(ctx, r.applyTimeout)
	err = r.tunnel.ApplySnapshot(applyCtx, snapshot)
	cancel()
	if err != nil {
		return r.degrade(machine, result,
			fmt.Errorf("%w: %w", ErrRollbackApply, err))
	}
	result.Applied = true

	awaitCtx, cancel := context.WithTimeout(ctx, r.awaitTimeout)
	err = r.tunnel.AwaitSnapshot(awaitCtx, snapshot)
	cancel()
	if err != nil {
		return r.degrade(machine, result,
			fmt.Errorf("%w: %w", ErrRollbackAwait, err))
	}

	verifyCtx, cancel := context.WithTimeout(ctx, r.verifyTimeout)
	verification, err := r.verifier.Verify(verifyCtx,
		verify.Request{Fresh: true})
	cancel()
	if err != nil {
		return r.degrade(machine, result,
			fmt.Errorf("%w: %w", ErrRollbackVerify, err))
	}
	result.Verification = verification

	err = compareEgress(snapshot, verification)
	if err != nil {
		return r.degrade(machine, result, err)
	}

	result.Proven = true
	result.Event = EventRolledBack
	machine.SetVerification(verification)

	err = machine.Transition(StateRolledBack)
	if err != nil {
		return result, err
	}
	return result, nil
}

func enterRollback(machine *Machine) error {
	switch machine.Job().State {
	case StateRollingBack:
		return nil
	case StateApplying, StateAwaitingTunnel, StateVerifyingEgress:
		return machine.Transition(StateRollingBack)
	case StateQueued, StateValidating, StatePreflight, StateDraining,
		StateCommitted, StateRejected, StateRolledBack, StateFailedDegraded,
		StateExhausted, StateCanceled, StateInterrupted:
		return fmt.Errorf("%w: cannot roll back from %s", ErrInvalidTransition,
			machine.Job().State)
	}
	return fmt.Errorf("%w: cannot roll back from %s", ErrInvalidTransition,
		machine.Job().State)
}

func verifyExpectedEgress(snapshot state.TunnelSnapshot) error {
	if snapshot.Egress == nil {
		return fmt.Errorf("%w: snapshot has no egress verification",
			ErrRollbackUnproven)
	}
	if !snapshot.Egress.Verified {
		return fmt.Errorf("%w: snapshot egress was never verified",
			ErrRollbackUnproven)
	}
	if !snapshot.Egress.IP.IsValid() {
		return fmt.Errorf("%w: snapshot egress IP is missing",
			ErrRollbackUnproven)
	}
	return nil
}

func compareEgress(snapshot state.TunnelSnapshot,
	verification egress.Verification,
) error {
	if !verification.Verified {
		return fmt.Errorf("%w: fresh egress is not verified",
			ErrRollbackUnproven)
	}
	expected := snapshot.Egress.IP
	if verification.IP != expected {
		return fmt.Errorf("%w: observed %s, expected %s",
			ErrRollbackMismatch, verification.IP, expected)
	}
	return nil
}

func (r *Rollback) degrade(machine *Machine, result RollbackResult,
	cause error,
) (RollbackResult, error) {
	result.Proven = false
	result.Event = EventFailedDegraded

	err := machine.Transition(StateFailedDegraded)
	if err != nil {
		return result, errors.Join(cause, err)
	}
	return result, cause
}
