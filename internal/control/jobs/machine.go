package jobs

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/egress"
)

// Job machine errors.
var (
	ErrInvalidTransition = errors.New("invalid job transition")
	ErrJobInvariant      = errors.New("job invariant violated")
	ErrJobTerminal       = errors.New("job is terminal")
)

// Machine advances one job through the contract state machine. Its methods are
// safe for concurrent use so an administrator can read or cancel a running job.
type Machine struct {
	mutex          sync.Mutex
	job            Job
	now            func() time.Time
	phaseStartedAt time.Time
}

// NewMachine creates a job state machine.
func NewMachine(job Job, now func() time.Time) *Machine {
	if job.State == "" {
		job.State = StateQueued
	}
	if now == nil {
		now = time.Now
	}

	phaseStartedAt := job.UpdatedAt
	if phaseStartedAt.IsZero() {
		phaseStartedAt = job.CreatedAt
	}
	if phaseStartedAt.IsZero() {
		phaseStartedAt = now().UTC()
	}

	return &Machine{
		job:            job,
		now:            now,
		phaseStartedAt: phaseStartedAt,
	}
}

// Job returns a copy of the current job.
func (m *Machine) Job() Job {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.job
}

// Transition moves the job to the next state and updates its timings.
func (m *Machine) Transition(to State) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	return m.transitionLocked(to)
}

func (m *Machine) transitionLocked(to State) error {
	previous := m.job.State
	if !canTransition(previous, to) {
		return fmt.Errorf("%w: %s -> %s", ErrInvalidTransition, previous, to)
	}

	err := m.checkInvariants(to)
	if err != nil {
		return err
	}

	now := m.now().UTC()
	m.job.Timings.add(previous, now.Sub(m.phaseStartedAt))
	if previous == StateQueued {
		startedAt := now
		m.job.StartedAt = &startedAt
	}

	m.job.State = to
	m.job.UpdatedAt = now
	m.phaseStartedAt = now

	if IsTerminal(to) {
		finishedAt := now
		m.job.FinishedAt = &finishedAt
	}
	return nil
}

// SetVerification records the egress proof used by the committed and rolled
// back states.
func (m *Machine) SetVerification(verification egress.Verification) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.job.Verification = &verification
	m.job.UpdatedAt = m.now().UTC()
}

// SetTarget records the normalized target proven by the preflight.
func (m *Machine) SetTarget(target Target) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.job.Target = target
	m.job.UpdatedAt = m.now().UTC()
}

// SetSnapshotBefore records the tunnel state captured before any change.
func (m *Machine) SetSnapshotBefore(snapshot state.TunnelSnapshot) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.job.SnapshotBefore = &snapshot
	m.job.UpdatedAt = m.now().UTC()
}

// SetSnapshotAfter records the tunnel state captured after a commit.
func (m *Machine) SetSnapshotAfter(snapshot state.TunnelSnapshot) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.job.SnapshotAfter = &snapshot
	m.job.UpdatedAt = m.now().UTC()
}

// AddAttempt appends one candidate attempt.
func (m *Machine) AddAttempt(attempt Attempt) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.job.Attempts = append(m.job.Attempts, attempt)
	m.job.UpdatedAt = m.now().UTC()
}

// SetError records the failure that ended the job.
func (m *Machine) SetError(message string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.job.Error = message
	m.job.UpdatedAt = m.now().UTC()
}

// SetStationPreserved records whether the station snapshot was restored.
func (m *Machine) SetStationPreserved(preserved bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.job.StationPreserved = &preserved
	m.job.UpdatedAt = m.now().UTC()
}

// SetGlobalStateWritten records whether the job wrote the global state.
func (m *Machine) SetGlobalStateWritten(written bool) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.job.GlobalStateWritten = &written
	m.job.UpdatedAt = m.now().UTC()
}

// Cancel cancels the job immediately when the tunnel has not changed yet. In
// applying, awaiting_tunnel, verifying_egress and rolling_back, it only sets
// cancel_requested: the rollback keeps running.
func (m *Machine) Cancel() (canceled bool, err error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	switch m.job.State {
	case StateQueued, StateValidating, StatePreflight, StateDraining:
		err = m.transitionLocked(StateCanceled)
		if err != nil {
			return false, err
		}
		return true, nil
	case StateApplying, StateAwaitingTunnel, StateVerifyingEgress,
		StateRollingBack:
		m.job.CancelRequested = true
		m.job.UpdatedAt = m.now().UTC()
		return false, nil
	case StateCommitted, StateRejected, StateRolledBack, StateFailedDegraded,
		StateExhausted, StateCanceled, StateInterrupted:
		return false, fmt.Errorf("%w: job is %s", ErrJobTerminal, m.job.State)
	}
	return false, fmt.Errorf("%w: unknown state %q", ErrInvalidTransition,
		m.job.State)
}

// Interrupt turns an active job into interrupted after a restart.
func Interrupt(job Job, now time.Time) Job {
	if !IsActive(job.State) {
		return job
	}
	at := now.UTC()
	job.State = StateInterrupted
	job.UpdatedAt = at
	job.FinishedAt = &at
	job.CancelRequested = false
	return job
}

func (m *Machine) checkInvariants(to State) error {
	switch to {
	case StateCommitted:
		if m.job.Verification == nil || !m.job.Verification.Verified {
			return fmt.Errorf(
				"%w: committed requires a verified egress", ErrJobInvariant)
		}
	case StateRolledBack:
		if m.job.Verification == nil || !m.job.Verification.Verified {
			return fmt.Errorf(
				"%w: rolled back requires a re-verified egress", ErrJobInvariant)
		}
	case StateQueued, StateValidating, StatePreflight, StateDraining,
		StateApplying, StateAwaitingTunnel, StateVerifyingEgress,
		StateRollingBack, StateRejected, StateFailedDegraded, StateExhausted,
		StateCanceled, StateInterrupted:
		return nil
	}
	return nil
}

func canTransition(from, to State) bool {
	switch from {
	case StateQueued:
		return to == StateValidating || to == StateCanceled
	case StateValidating:
		return to == StatePreflight || to == StateRejected ||
			to == StateExhausted || to == StateCanceled
	case StatePreflight:
		return to == StateDraining || to == StatePreflight ||
			to == StateRejected || to == StateExhausted || to == StateCanceled
	case StateDraining:
		return to == StateApplying || to == StateCanceled
	case StateApplying:
		return to == StateAwaitingTunnel || to == StateRollingBack
	case StateAwaitingTunnel:
		return to == StateVerifyingEgress || to == StateRollingBack ||
			to == StateCanceled
	case StateVerifyingEgress:
		return to == StateCommitted || to == StateRollingBack ||
			to == StateCanceled
	case StateRollingBack:
		return to == StateRolledBack || to == StateFailedDegraded ||
			to == StatePreflight || to == StateCanceled
	case StateCommitted, StateRejected, StateRolledBack, StateFailedDegraded,
		StateExhausted, StateCanceled, StateInterrupted:
		return false
	}
	return false
}

func (t *Timings) add(state State, duration time.Duration) {
	if duration < 0 {
		duration = 0
	}
	milliseconds := duration.Milliseconds()
	switch state {
	case StateValidating:
		t.Validating += milliseconds
	case StatePreflight:
		t.Preflight += milliseconds
	case StateDraining:
		t.Draining += milliseconds
	case StateApplying:
		t.Applying += milliseconds
	case StateAwaitingTunnel:
		t.AwaitingTunnel += milliseconds
	case StateVerifyingEgress:
		t.VerifyingEgress += milliseconds
	case StateRollingBack:
		t.RollingBack += milliseconds
	case StateQueued, StateCommitted, StateRejected, StateRolledBack,
		StateFailedDegraded, StateExhausted, StateCanceled, StateInterrupted:
		return
	}
}
