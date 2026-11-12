package jobs

import (
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testTime() time.Time {
	return time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
}

func testJob() Job {
	return Job{
		ID:        "job_test",
		Kind:      KindSwitch,
		State:     StateQueued,
		StationID: "station-1",
		CreatedAt: testTime(),
		UpdatedAt: testTime(),
		Target:    testTarget(),
	}
}

func testClock(start time.Time) func() time.Time {
	current := start
	return func() time.Time {
		current = current.Add(time.Millisecond)
		return current
	}
}

func Test_MachineTransition(t *testing.T) {
	t.Parallel()

	machine := NewMachine(testJob(), testClock(testTime()))
	require.Equal(t, StateQueued, machine.Job().State)

	err := machine.Transition(StateValidating)
	require.NoError(t, err)
	assert.NotNil(t, machine.Job().StartedAt)
	assert.Equal(t, testTime().Add(time.Millisecond), *machine.Job().StartedAt)

	path := []State{
		StatePreflight,
		StateDraining,
		StateApplying,
		StateAwaitingTunnel,
		StateVerifyingEgress,
	}
	for _, next := range path {
		err = machine.Transition(next)
		require.NoError(t, err, "transition to %s", next)
	}

	machine.job.Verification = &egress.Verification{Verified: true}
	err = machine.Transition(StateCommitted)
	require.NoError(t, err)

	job := machine.Job()
	assert.Equal(t, StateCommitted, job.State)
	assert.NotNil(t, job.FinishedAt)
	assert.Equal(t, testTime().Add(7*time.Millisecond), *job.FinishedAt)
	expectedTimings := Timings{
		Validating:      1,
		Preflight:       1,
		Draining:        1,
		Applying:        1,
		AwaitingTunnel:  1,
		VerifyingEgress: 1,
	}
	assert.Equal(t, expectedTimings, job.Timings)
}

func Test_MachineInvalidTransitions(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		from State
		to   State
	}{
		"queued to committed": {
			from: StateQueued,
			to:   StateCommitted,
		},
		"validating to applying": {
			from: StateValidating,
			to:   StateApplying,
		},
		"preflight to applying": {
			from: StatePreflight,
			to:   StateApplying,
		},
		"applying to canceled": {
			from: StateApplying,
			to:   StateCanceled,
		},
		"committed to validating": {
			from: StateCommitted,
			to:   StateValidating,
		},
		"rolling back to applying": {
			from: StateRollingBack,
			to:   StateApplying,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			job := testJob()
			job.State = testCase.from
			machine := NewMachine(job, testClock(testTime()))

			err := machine.Transition(testCase.to)
			assert.ErrorIs(t, err, ErrInvalidTransition)
			assert.Equal(t, job, machine.Job())
		})
	}
}

func Test_MachineInvariants(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		from         State
		to           State
		verification *egress.Verification
		expectedErr  error
	}{
		"committed without verification": {
			from:        StateVerifyingEgress,
			to:          StateCommitted,
			expectedErr: ErrJobInvariant,
		},
		"committed with unverified egress": {
			from:         StateVerifyingEgress,
			to:           StateCommitted,
			verification: &egress.Verification{Verified: false},
			expectedErr:  ErrJobInvariant,
		},
		"committed with verified egress": {
			from:         StateVerifyingEgress,
			to:           StateCommitted,
			verification: &egress.Verification{Verified: true},
		},
		"rolled back without verification": {
			from:        StateRollingBack,
			to:          StateRolledBack,
			expectedErr: ErrJobInvariant,
		},
		"rolled back with verified egress": {
			from:         StateRollingBack,
			to:           StateRolledBack,
			verification: &egress.Verification{Verified: true},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			job := testJob()
			job.State = testCase.from
			job.Verification = testCase.verification
			machine := NewMachine(job, testClock(testTime()))

			err := machine.Transition(testCase.to)
			if testCase.expectedErr != nil {
				assert.ErrorIs(t, err, testCase.expectedErr)
				assert.Equal(t, job, machine.Job())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.to, machine.Job().State)
		})
	}
}

func Test_MachineCancel(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		state                   State
		expectedCanceled        bool
		expectedState           State
		expectedCancelRequested bool
		expectedErr             error
	}{
		"queued": {
			state:            StateQueued,
			expectedCanceled: true,
			expectedState:    StateCanceled,
		},
		"validating": {
			state:            StateValidating,
			expectedCanceled: true,
			expectedState:    StateCanceled,
		},
		"preflight": {
			state:            StatePreflight,
			expectedCanceled: true,
			expectedState:    StateCanceled,
		},
		"draining": {
			state:            StateDraining,
			expectedCanceled: true,
			expectedState:    StateCanceled,
		},
		"applying": {
			state:                   StateApplying,
			expectedState:           StateApplying,
			expectedCancelRequested: true,
		},
		"awaiting tunnel": {
			state:                   StateAwaitingTunnel,
			expectedState:           StateAwaitingTunnel,
			expectedCancelRequested: true,
		},
		"verifying egress": {
			state:                   StateVerifyingEgress,
			expectedState:           StateVerifyingEgress,
			expectedCancelRequested: true,
		},
		"rolling back": {
			state:                   StateRollingBack,
			expectedState:           StateRollingBack,
			expectedCancelRequested: true,
		},
		"committed": {
			state:         StateCommitted,
			expectedErr:   ErrJobTerminal,
			expectedState: StateCommitted,
		},
		"canceled": {
			state:         StateCanceled,
			expectedErr:   ErrJobTerminal,
			expectedState: StateCanceled,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			job := testJob()
			job.State = testCase.state
			machine := NewMachine(job, testClock(testTime()))

			canceled, err := machine.Cancel()
			if testCase.expectedErr != nil {
				assert.ErrorIs(t, err, testCase.expectedErr)
				assert.False(t, canceled)
				assert.Equal(t, testCase.expectedState, machine.Job().State)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, testCase.expectedCanceled, canceled)
			assert.Equal(t, testCase.expectedState, machine.Job().State)
			assert.Equal(t, testCase.expectedCancelRequested,
				machine.Job().CancelRequested)
		})
	}
}

func Test_Interrupt(t *testing.T) {
	t.Parallel()

	at := testTime().Add(time.Minute)
	interrupted := Interrupt(Job{
		State:     StateApplying,
		UpdatedAt: testTime(),
	}, at)
	assert.Equal(t, StateInterrupted, interrupted.State)
	assert.Equal(t, at, interrupted.UpdatedAt)
	require.NotNil(t, interrupted.FinishedAt)
	assert.Equal(t, at, *interrupted.FinishedAt)
	assert.False(t, interrupted.CancelRequested)

	terminal := Job{State: StateCommitted, UpdatedAt: testTime()}
	assert.Equal(t, terminal, Interrupt(terminal, at))
}

func Test_JobStatePredicates(t *testing.T) {
	t.Parallel()

	testCases := map[State]struct {
		active   bool
		terminal bool
	}{
		StateQueued:          {active: true},
		StateValidating:      {active: true},
		StatePreflight:       {active: true},
		StateDraining:        {active: true},
		StateApplying:        {active: true},
		StateAwaitingTunnel:  {active: true},
		StateVerifyingEgress: {active: true},
		StateRollingBack:     {active: true},
		StateCommitted:       {terminal: true},
		StateRejected:        {terminal: true},
		StateRolledBack:      {terminal: true},
		StateFailedDegraded:  {terminal: true},
		StateExhausted:       {terminal: true},
		StateCanceled:        {terminal: true},
		StateInterrupted:     {terminal: true},
	}

	for state, testCase := range testCases {
		t.Run(string(state), func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.active, IsActive(state))
			assert.Equal(t, testCase.terminal, IsTerminal(state))
		})
	}

	assert.False(t, IsActive("unknown"))
	assert.False(t, IsTerminal("unknown"))
}
