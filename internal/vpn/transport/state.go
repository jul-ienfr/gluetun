package transport

import (
	"net/netip"
	"time"
)

type AttemptResult string

const (
	AttemptSuccess AttemptResult = "success"
	AttemptFailed  AttemptResult = "failed"
	AttemptSkipped AttemptResult = "skipped"
)

type Phase string

const (
	PhaseIdle           Phase = "idle"
	PhasePreflight      Phase = "preflight"
	PhaseApplying       Phase = "applying"
	PhaseAwaitingTunnel Phase = "awaiting_tunnel"
	PhaseVerifying      Phase = "verifying"
	PhaseCommitted      Phase = "committed"
	PhaseCooldown       Phase = "cooldown"
)

type Attempt struct {
	ID        string        `json:"id,omitempty"`
	Transport Transport     `json:"transport"`
	Server    string        `json:"server,omitempty"`
	Started   time.Time     `json:"started"`
	Ended     time.Time     `json:"ended"`
	Result    AttemptResult `json:"result"`
	Reason    Reason        `json:"reason,omitempty"`
	Latency   time.Duration `json:"latency"`
	NextRetry time.Time     `json:"next_retry,omitempty"`
}

type State struct {
	Active    *Transport            `json:"active_transport,omitempty"`
	Phase     Phase                 `json:"phase"`
	Cycle     int                   `json:"cycle"`
	Breakers  map[Transport]Breaker `json:"breakers"`
	Attempts  []Attempt             `json:"attempts"`
	NextAt    *time.Time            `json:"next_attempt_at,omitempty"`
	UpdatedAt time.Time             `json:"updated_at"`
}

func (s State) Clone() State {
	cloned := State{
		Phase:     s.Phase,
		Cycle:     s.Cycle,
		UpdatedAt: s.UpdatedAt,
		Breakers:  make(map[Transport]Breaker, len(s.Breakers)),
		Attempts:  append([]Attempt(nil), s.Attempts...),
	}
	if s.Active != nil {
		active := *s.Active
		cloned.Active = &active
	}
	if s.NextAt != nil {
		next := *s.NextAt
		cloned.NextAt = &next
	}
	for transport, breaker := range s.Breakers {
		cloned.Breakers[transport] = breaker
	}
	return cloned
}

type Result struct {
	Transport Transport  `json:"transport"`
	Cycle     int        `json:"cycle"`
	Attempts  []Attempt  `json:"attempts"`
	EgressIP  netip.Addr `json:"egress_ip,omitempty"`
}
