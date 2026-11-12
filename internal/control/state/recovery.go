package state

import (
	"errors"
	"fmt"
)

// Recovery decisions, journaled on every startup reconciliation.
const (
	ActionAbsent    = "state.absent"
	ActionRecovered = "state.recovered"
	ActionDrift     = "state.drift"
	ActionMerged    = "state.merged"
	ActionInvalid   = "state.invalid"
)

// Decision is the outcome of reconciling the persisted state with the
// environment settings at startup.
type Decision struct {
	Action  string
	State   DesiredState
	Message string
}

// Recover reconciles the persisted state with the environment settings using
// one of the state, env or merge modes. An invalid persisted state never
// overwrites its file: the environment settings are used for this run and the
// decision is journaled as state.invalid.
func (s *Store) Recover(stationID string, environment TunnelSettings, mode string,
) (decision Decision, err error) {
	switch mode {
	case ModeState, ModeEnv, ModeMerge:
	default:
		return Decision{}, fmt.Errorf("%w: unknown recovery mode %q",
			ErrInvalidState, mode)
	}

	loaded, found, loadErr := s.Load()
	switch {
	case errors.Is(loadErr, ErrInvalidState),
		errors.Is(loadErr, ErrChecksumMismatch):
		state, buildErr := s.build(stationID, mode, environment)
		if buildErr != nil {
			return Decision{}, buildErr
		}
		decision = Decision{
			Action:  ActionInvalid,
			State:   state,
			Message: loadErr.Error(),
		}
		return decision, s.record(decision, false)
	case loadErr != nil:
		return Decision{}, loadErr
	case !found:
		decision, err = s.persist(stationID, mode, environment,
			ActionAbsent, "")
		if err != nil {
			return Decision{}, err
		}
		return decision, s.record(decision, true)
	case loaded.StationID != stationID:
		message := fmt.Sprintf("persisted state belongs to station %q",
			loaded.StationID)
		decision, err = s.persist(stationID, mode, environment,
			ActionDrift, message)
		if err != nil {
			return Decision{}, err
		}
		return decision, s.record(decision, true)
	}

	decision, err = s.reconcile(stationID, mode, environment, loaded)
	if err != nil {
		return Decision{}, err
	}
	return decision, s.record(decision, true)
}

func (s *Store) reconcile(stationID, mode string, environment TunnelSettings,
	loaded DesiredState,
) (decision Decision, err error) {
	switch mode {
	case ModeState:
		message := ""
		if !loaded.Desired.Equal(environment) {
			message = "persisted state overrides the environment"
		}
		return Decision{Action: ActionRecovered, State: loaded, Message: message}, nil
	case ModeEnv:
		if loaded.Desired.Equal(environment) {
			return Decision{Action: ActionRecovered, State: loaded}, nil
		}
		return s.persist(stationID, mode, environment, ActionDrift,
			"environment overrides the persisted state")
	case ModeMerge:
		merged := loaded.Desired.mergedWith(environment)
		if merged.Equal(loaded.Desired) {
			return Decision{Action: ActionRecovered, State: loaded}, nil
		}
		return s.persist(stationID, mode, merged, ActionMerged,
			"merged the persisted state with the environment")
	}
	return Decision{}, fmt.Errorf("%w: unknown recovery mode %q",
		ErrInvalidState, mode)
}

func (s *Store) build(stationID, mode string, desired TunnelSettings,
) (DesiredState, error) {
	state, err := NewDesiredState(stationID, mode, desired, s.clock())
	if err != nil {
		return DesiredState{}, fmt.Errorf("building desired state: %w", err)
	}
	return state, nil
}

func (s *Store) persist(stationID, mode string, desired TunnelSettings,
	action, message string,
) (decision Decision, err error) {
	state, err := s.build(stationID, mode, desired)
	if err != nil {
		return Decision{}, err
	}
	err = s.Save(state)
	if err != nil {
		return Decision{}, err
	}
	return Decision{Action: action, State: state, Message: message}, nil
}

func (s *Store) record(decision Decision, persisted bool) error {
	entry := JournalEntry{
		At:      decision.State.UpdatedAt,
		Action:  decision.Action,
		Message: decision.Message,
	}
	if persisted {
		entry.Checksum = decision.State.Checksum
	}
	err := s.journal.Append(entry)
	if err != nil {
		return fmt.Errorf("journaling recovery decision: %w", err)
	}
	return nil
}
