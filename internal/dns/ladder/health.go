package ladder

import (
	"time"
)

const (
	defaultFailuresToDown     = 3
	defaultSuccessesToRecover = 2
	defaultBaseCooldown       = 5 * time.Second
	defaultMaxCooldown        = 5 * time.Minute
	maxBackoffExponent        = 20
)

// HealthSettings configure the DNS health state machine.
type HealthSettings struct {
	FailuresToDown     int
	SuccessesToRecover int
	BaseCooldown       time.Duration
	MaxCooldown        time.Duration
	EWMAAlpha          float64
	Now                func() time.Time
}

// Health applies success and failure observations to tiers and endpoints.
type Health struct {
	settings HealthSettings
}

// NewHealth creates a DNS health state machine with safe defaults.
func NewHealth(settings HealthSettings) *Health {
	if settings.FailuresToDown <= 0 {
		settings.FailuresToDown = defaultFailuresToDown
	}
	if settings.SuccessesToRecover <= 0 {
		settings.SuccessesToRecover = defaultSuccessesToRecover
	}
	if settings.BaseCooldown <= 0 {
		settings.BaseCooldown = defaultBaseCooldown
	}
	if settings.MaxCooldown <= 0 {
		settings.MaxCooldown = defaultMaxCooldown
	}
	if settings.MaxCooldown < settings.BaseCooldown {
		settings.MaxCooldown = settings.BaseCooldown
	}
	if settings.EWMAAlpha <= 0 || settings.EWMAAlpha > 1 {
		settings.EWMAAlpha = defaultEWMAAlpha
	}
	if settings.Now == nil {
		settings.Now = time.Now
	}
	return &Health{settings: settings}
}

// Success records a successful request or probe on one endpoint. It reports
// whether the tier state changed.
func (h *Health) Success(tier *Tier, endpointIndex int,
	latency time.Duration,
) bool {
	if tier == nil || endpointIndex < 0 || endpointIndex >= len(tier.Endpoints) {
		return false
	}
	previous := tier.State
	now := h.settings.Now().UTC()
	endpoint := &tier.Endpoints[endpointIndex]

	endpoint.Successes++
	endpoint.consecutiveSuccesses++
	endpoint.consecutiveFailures = 0
	endpoint.applyLatency(latency, h.settings.EWMAAlpha)
	endpoint.LastError = nil
	endpoint.CooldownUntil = nil
	switch {
	case endpoint.State == StateDown:
		if endpoint.consecutiveSuccesses >= h.settings.SuccessesToRecover {
			endpoint.State = StateUp
		}
	case endpoint.State != StateUp:
		endpoint.State = StateUp
	}

	tier.Successes++
	tier.LatencyEWMAMS = EWMA(tier.LatencyEWMAMS, latency,
		h.settings.EWMAAlpha)
	tier.LastError = nil
	tier.CooldownUntil = nil

	h.refresh(tier, now)
	return previous != tier.State
}

// Failure records a failed request or probe on one endpoint. It reports whether
// the tier state changed.
func (h *Health) Failure(tier *Tier, endpointIndex int, cause error) bool {
	if tier == nil || endpointIndex < 0 || endpointIndex >= len(tier.Endpoints) {
		return false
	}
	previous := tier.State
	now := h.settings.Now().UTC()
	endpoint := &tier.Endpoints[endpointIndex]

	endpoint.Failures++
	endpoint.consecutiveFailures++
	endpoint.consecutiveSuccesses = 0
	message := ""
	if cause != nil {
		message = cause.Error()
	}
	endpoint.LastError = &message
	tier.Failures++
	tier.LastError = &message

	if endpoint.consecutiveFailures >= h.settings.FailuresToDown {
		endpoint.State = StateDown
		cooldown := now.Add(h.backoff(endpoint.consecutiveFailures))
		endpoint.CooldownUntil = &cooldown
	} else {
		endpoint.State = StateDegraded
		endpoint.CooldownUntil = nil
	}

	h.refresh(tier, now)
	return previous != tier.State
}

// Refresh recomputes the tier state from its endpoints. Expired endpoint
// cooldowns become degraded so the endpoint can be probed again.
func (h *Health) Refresh(tier *Tier) {
	if tier == nil {
		return
	}
	h.refresh(tier, h.settings.Now().UTC())
}

func (h *Health) refresh(tier *Tier, now time.Time) {
	if len(tier.Endpoints) == 0 {
		return
	}

	up := 0
	degraded := 0
	down := 0
	var earliestCooldown *time.Time

	for index := range tier.Endpoints {
		endpoint := &tier.Endpoints[index]
		if endpoint.State == StateDown && endpoint.CooldownUntil != nil &&
			!now.Before(*endpoint.CooldownUntil) {
			endpoint.State = StateDegraded
		}
		switch endpoint.State {
		case StateUp:
			up++
		case StateDegraded, StateStandby:
			degraded++
		case StateDown:
			down++
			if endpoint.CooldownUntil != nil &&
				(earliestCooldown == nil ||
					endpoint.CooldownUntil.Before(*earliestCooldown)) {
				cooldown := *endpoint.CooldownUntil
				earliestCooldown = &cooldown
			}
		}
	}

	switch {
	case up > 0:
		tier.State = StateUp
		tier.CooldownUntil = nil
	case degraded > 0:
		tier.State = StateDegraded
		tier.CooldownUntil = nil
	case down > 0:
		tier.State = StateDown
		if earliestCooldown != nil {
			tier.CooldownUntil = earliestCooldown
		} else {
			cooldown := now.Add(h.settings.BaseCooldown)
			tier.CooldownUntil = &cooldown
		}
	}
}

func (h *Health) backoff(failures int) time.Duration {
	exponent := failures - h.settings.FailuresToDown
	if exponent < 0 {
		exponent = 0
	}
	if exponent > maxBackoffExponent {
		exponent = maxBackoffExponent
	}
	cooldown := h.settings.BaseCooldown * time.Duration(1<<exponent)
	if cooldown > h.settings.MaxCooldown || cooldown <= 0 {
		return h.settings.MaxCooldown
	}
	return cooldown
}
