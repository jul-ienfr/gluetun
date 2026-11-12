// Package ladder models the multi-tier DNS resolver ladder.
package ladder

import "time"

// TierType is the transport of one DNS tier.
type TierType string

// DNS tier types.
const (
	TierDoT   TierType = "dot"
	TierDoH   TierType = "doh"
	TierPlain TierType = "plain"
)

// Valid reports whether the tier type is supported.
func (t TierType) Valid() bool {
	switch t {
	case TierDoT, TierDoH, TierPlain:
		return true
	}
	return false
}

// Tier is one stage of the DNS ladder.
type Tier struct {
	Type          TierType   `json:"type"`
	State         State      `json:"state"`
	Listener      string     `json:"listener,omitempty"`
	Successes     uint64     `json:"successes"`
	Failures      uint64     `json:"failures"`
	LatencyEWMAMS int64      `json:"latency_ewma_ms"`
	CooldownUntil *time.Time `json:"cooldown_until"`
	LastError     *string    `json:"last_error"`
	Endpoints     []Endpoint `json:"endpoints"`
}

// NewTier creates a tier in standby with the endpoints given.
func NewTier(tierType TierType, listener string, endpoints []Endpoint) Tier {
	if endpoints == nil {
		endpoints = []Endpoint{}
	}
	return Tier{
		Type:      tierType,
		State:     StateStandby,
		Listener:  listener,
		Endpoints: endpoints,
	}
}

// Available reports whether the tier can currently serve requests.
func (t *Tier) Available(now time.Time) bool {
	if t.State != StateUp {
		return false
	}
	return t.CooldownUntil == nil || !now.Before(*t.CooldownUntil)
}

// AddEndpoint appends one endpoint to the tier.
func (t *Tier) AddEndpoint(endpoint Endpoint) {
	t.Endpoints = append(t.Endpoints, endpoint)
}

// AvailableEndpoints counts the endpoints that can serve requests now.
func (t *Tier) AvailableEndpoints(now time.Time) (count int) {
	for index := range t.Endpoints {
		if t.Endpoints[index].Available(now) {
			count++
		}
	}
	return count
}
