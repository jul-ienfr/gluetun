package ladder

// State is the health state of a DNS tier or endpoint.
type State string

// DNS health states.
const (
	StateUp       State = "up"
	StateDegraded State = "degraded"
	StateDown     State = "down"
	StateStandby  State = "standby"
)

// Valid reports whether the state is a known DNS health state.
func (s State) Valid() bool {
	switch s {
	case StateUp, StateDegraded, StateDown, StateStandby:
		return true
	}
	return false
}

// Serving reports whether the state can answer DNS queries.
func (s State) Serving() bool {
	return s == StateUp || s == StateDegraded
}
