package ladder

import (
	"math"
	"time"
)

const defaultEWMAAlpha = 0.2

// Endpoint is one resolver address of a DNS tier.
type Endpoint struct {
	Address       string     `json:"address"`
	Provider      string     `json:"provider,omitempty"`
	TLSName       string     `json:"-"`
	URL           string     `json:"-"`
	State         State      `json:"state"`
	Successes     uint64     `json:"successes"`
	Failures      uint64     `json:"failures"`
	LatencyEWMAMS int64      `json:"latency_ewma_ms"`
	CooldownUntil *time.Time `json:"cooldown_until"`
	LastError     *string    `json:"last_error"`

	consecutiveFailures  int
	consecutiveSuccesses int
}

// NewEndpoint creates a usable endpoint.
func NewEndpoint(address, provider string) Endpoint {
	return Endpoint{
		Address:  address,
		Provider: provider,
		State:    StateUp,
	}
}

// Available reports whether the endpoint can be tried now.
func (e *Endpoint) Available(now time.Time) bool {
	if !e.State.Serving() {
		return false
	}
	return e.CooldownUntil == nil || !now.Before(*e.CooldownUntil)
}

// EWMA computes the exponentially weighted moving average of two latencies,
// in milliseconds. A non-positive previous value adopts the sample.
func EWMA(previous int64, sample time.Duration, alpha float64) int64 {
	if alpha <= 0 || alpha > 1 {
		alpha = defaultEWMAAlpha
	}
	sampleMS := sample.Milliseconds()
	if sampleMS < 0 {
		sampleMS = 0
	}
	if previous <= 0 {
		return sampleMS
	}
	value := alpha*float64(sampleMS) + (1-alpha)*float64(previous)
	return int64(math.Round(value))
}

func (e *Endpoint) applyLatency(latency time.Duration, alpha float64) {
	e.LatencyEWMAMS = EWMA(e.LatencyEWMAMS, latency, alpha)
}
