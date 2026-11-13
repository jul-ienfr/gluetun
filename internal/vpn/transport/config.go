package transport

import (
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
)

// Enabled reports whether the runtime transport ladder is enabled by the
// operator settings.
func Enabled(settings settings.TransportLadder) bool {
	return settings.Enabled == nil || *settings.Enabled
}

// PolicyFromSettings converts the operator settings into a normalized policy.
// Duplicate transports are removed and returned as warnings.
func PolicyFromSettings(settings settings.TransportLadder,
) (policy Policy, warnings []string, err error) {
	ladder, err := ParseLadder(strings.Join(settings.Ladder, ","))
	if err != nil {
		return Policy{}, nil, err
	}

	policy = DefaultPolicy()
	policy.Ladder = ladder
	policy.AttemptTimeout = map[Transport]time.Duration{
		WireGuard:  settings.AttemptTimeout,
		OpenVPNUDP: settings.AttemptTimeout,
		OpenVPNTCP: settings.AttemptTimeoutTCP,
	}
	policy.MaxAttempts = settings.MaxAttempts
	policy.BreakerThreshold = settings.BreakerThreshold
	policy.BreakerCooldown = settings.BreakerCooldown
	policy.BreakerCooldownMax = settings.BreakerCooldownMax
	policy.BackoffBase = settings.BackoffBase
	policy.BackoffMax = settings.BackoffMax
	policy.MaxCycles = settings.MaxCycles
	policy.Jitter = settings.Jitter

	return policy.Normalize()
}
