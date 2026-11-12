package jobs

import (
	"net/netip"
	"time"

	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/egress"
)

// Kind is the kind of a switch job.
type Kind string

// Job kinds.
const (
	KindSwitch   Kind = "switch"
	KindRotate   Kind = "rotate"
	KindRollback Kind = "rollback"
	KindRecover  Kind = "recover"
)

// State is one state of the job state machine.
type State string

// Job states.
const (
	StateQueued          State = "queued"
	StateValidating      State = "validating"
	StatePreflight       State = "preflight"
	StateDraining        State = "draining"
	StateApplying        State = "applying"
	StateAwaitingTunnel  State = "awaiting_tunnel"
	StateVerifyingEgress State = "verifying_egress"
	StateRollingBack     State = "rolling_back"
	StateCommitted       State = "committed"
	StateRejected        State = "rejected"
	StateRolledBack      State = "rolled_back"
	StateFailedDegraded  State = "failed_degraded"
	StateExhausted       State = "exhausted"
	StateCanceled        State = "cancelled" //nolint:misspell // contract value
	StateInterrupted     State = "interrupted"
)

// Attempt is one candidate attempt recorded in a job.
type Attempt struct {
	Hostname   string     `json:"hostname"`
	Phase      State      `json:"phase,omitempty"`
	StartedAt  time.Time  `json:"started_at,omitzero"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Result     string     `json:"result,omitempty"`
	Reason     string     `json:"reason,omitempty"`
	ObservedIP netip.Addr `json:"observed_ip,omitempty"`
	ExpectedIP netip.Addr `json:"expected_ip,omitempty"`
}

// Timings accumulates the milliseconds spent in each phase.
type Timings struct {
	Validating      int64 `json:"validating"`
	Preflight       int64 `json:"preflight"`
	Draining        int64 `json:"draining"`
	Applying        int64 `json:"applying"`
	AwaitingTunnel  int64 `json:"awaiting_tunnel"`
	VerifyingEgress int64 `json:"verifying_egress"`
	RollingBack     int64 `json:"rolling_back,omitempty"`
}

// Job is the transaction unit persisted across restarts.
type Job struct {
	ID              string                `json:"id"`
	Kind            Kind                  `json:"kind"`
	State           State                 `json:"state"`
	StationID       string                `json:"station_id"`
	CreatedAt       time.Time             `json:"created_at"`
	StartedAt       *time.Time            `json:"started_at,omitempty"`
	UpdatedAt       time.Time             `json:"updated_at"`
	FinishedAt      *time.Time            `json:"finished_at,omitempty"`
	Target          Target                `json:"target"`
	Candidates      []string              `json:"candidates,omitempty"`
	Attempts        []Attempt             `json:"attempts,omitempty"`
	SnapshotBefore  *state.TunnelSnapshot `json:"snapshot_before,omitempty"`
	SnapshotAfter   *state.TunnelSnapshot `json:"snapshot_after,omitempty"`
	Verification    *egress.Verification  `json:"verification,omitempty"`
	Timings         Timings               `json:"timings_ms"`
	Error           string                `json:"error,omitempty"`
	IdempotencyKey  string                `json:"idempotency_key,omitempty"`
	RequestedBy     string                `json:"requested_by,omitempty"`
	CancelRequested bool                  `json:"cancel_requested,omitempty"`
	// StationPreserved reports whether the pre-rotation tunnel was restored.
	StationPreserved *bool `json:"station_preserved,omitempty"`
	// GlobalStateWritten reports whether the job wrote the global desired
	// state. Rotation never does.
	GlobalStateWritten *bool `json:"global_state_written,omitempty"`
}

// IsActive reports whether a state still has work to do.
func IsActive(state State) bool {
	switch state {
	case StateQueued, StateValidating, StatePreflight, StateDraining,
		StateApplying, StateAwaitingTunnel, StateVerifyingEgress,
		StateRollingBack:
		return true
	case StateCommitted, StateRejected, StateRolledBack,
		StateFailedDegraded, StateExhausted, StateCanceled, StateInterrupted:
		return false
	}
	return false
}

// IsTerminal reports whether a state is final.
func IsTerminal(state State) bool {
	switch state {
	case StateCommitted, StateRejected, StateRolledBack,
		StateFailedDegraded, StateExhausted, StateCanceled, StateInterrupted:
		return true
	case StateQueued, StateValidating, StatePreflight, StateDraining,
		StateApplying, StateAwaitingTunnel, StateVerifyingEgress,
		StateRollingBack:
		return false
	}
	return false
}
