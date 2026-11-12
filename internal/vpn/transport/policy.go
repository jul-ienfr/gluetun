package transport

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Transport string

const (
	WireGuard  Transport = "wireguard"
	OpenVPNUDP Transport = "openvpn-udp"
	OpenVPNTCP Transport = "openvpn-tcp"
)

const (
	VPNOpenVPN   = "openvpn"
	VPNWireGuard = "wireguard"
)

var ErrInvalidPolicy = errors.New("invalid transport policy")

var DefaultLadder = []Transport{WireGuard, OpenVPNUDP, OpenVPNTCP}

const (
	defaultAttemptTimeout   = 30 * time.Second
	defaultAttemptTCP       = 45 * time.Second
	defaultMaxAttempts      = 2
	defaultBreakerThreshold = 3
	defaultBreakerCooldown  = 120 * time.Second
	defaultBreakerMax       = 900 * time.Second
	defaultBackoffBase      = 30 * time.Second
	defaultBackoffMax       = 300 * time.Second
	defaultMaxCycles        = 3
	defaultJitter           = 0.2
)

type Policy struct {
	Ladder             []Transport
	AttemptTimeout     map[Transport]time.Duration
	MaxAttempts        int
	BreakerThreshold   int
	BreakerCooldown    time.Duration
	BreakerCooldownMax time.Duration
	BackoffBase        time.Duration
	BackoffMax         time.Duration
	MaxCycles          int
	Jitter             float64
}

func DefaultPolicy() Policy {
	return Policy{
		Ladder:             append([]Transport(nil), DefaultLadder...),
		AttemptTimeout:     DefaultAttemptTimeouts(),
		MaxAttempts:        defaultMaxAttempts,
		BreakerThreshold:   defaultBreakerThreshold,
		BreakerCooldown:    defaultBreakerCooldown,
		BreakerCooldownMax: defaultBreakerMax,
		BackoffBase:        defaultBackoffBase,
		BackoffMax:         defaultBackoffMax,
		MaxCycles:          defaultMaxCycles,
		Jitter:             defaultJitter,
	}
}

func DefaultAttemptTimeouts() map[Transport]time.Duration {
	return map[Transport]time.Duration{
		WireGuard:  defaultAttemptTimeout,
		OpenVPNUDP: defaultAttemptTimeout,
		OpenVPNTCP: defaultAttemptTCP,
	}
}

func (t Transport) Valid() bool {
	switch t {
	case WireGuard, OpenVPNUDP, OpenVPNTCP:
		return true
	}
	return false
}

func (t Transport) VPNType() string {
	switch t {
	case WireGuard:
		return VPNWireGuard
	case OpenVPNUDP, OpenVPNTCP:
		return VPNOpenVPN
	}
	return ""
}

func (t Transport) Network() string {
	if t == OpenVPNTCP {
		return "tcp"
	}
	return "udp"
}

func (t Transport) DefaultPort() uint16 {
	switch t {
	case WireGuard:
		return 51820
	case OpenVPNUDP, OpenVPNTCP:
		return 1194
	}
	return 0
}

func ParseLadder(value string) (ladder []Transport, err error) {
	parts := strings.Split(value, ",")
	ladder = make([]Transport, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(strings.ToLower(part))
		if part == "" {
			continue
		}
		transport := Transport(part)
		if !transport.Valid() {
			return nil, fmt.Errorf("%w: unknown transport %q",
				ErrInvalidPolicy, part)
		}
		ladder = append(ladder, transport)
	}
	if len(ladder) == 0 {
		return nil, fmt.Errorf("%w: ladder is empty", ErrInvalidPolicy)
	}
	return ladder, nil
}

func (p Policy) Normalize() (normalized Policy, warnings []string, err error) {
	normalized = p
	if len(normalized.Ladder) == 0 {
		return Policy{}, nil, fmt.Errorf("%w: ladder is empty", ErrInvalidPolicy)
	}

	seen := make(map[Transport]struct{}, len(normalized.Ladder))
	ladder := make([]Transport, 0, len(normalized.Ladder))
	for _, transport := range normalized.Ladder {
		if !transport.Valid() {
			return Policy{}, nil, fmt.Errorf("%w: unknown transport %q",
				ErrInvalidPolicy, transport)
		}
		if _, ok := seen[transport]; ok {
			warnings = append(warnings,
				fmt.Sprintf("ignoring duplicate transport %q", transport))
			continue
		}
		seen[transport] = struct{}{}
		ladder = append(ladder, transport)
	}
	if len(ladder) == 0 {
		return Policy{}, nil, fmt.Errorf("%w: ladder is empty", ErrInvalidPolicy)
	}
	normalized.Ladder = ladder

	timeouts := make(map[Transport]time.Duration, len(ladder))
	defaults := DefaultAttemptTimeouts()
	for _, transport := range ladder {
		timeout := normalized.AttemptTimeout[transport]
		if timeout <= 0 {
			timeout = defaults[transport]
		}
		timeouts[transport] = timeout
	}
	normalized.AttemptTimeout = timeouts

	if normalized.MaxAttempts <= 0 {
		normalized.MaxAttempts = defaultMaxAttempts
	}
	if normalized.BreakerThreshold <= 0 {
		normalized.BreakerThreshold = defaultBreakerThreshold
	}
	if normalized.BreakerCooldown <= 0 {
		normalized.BreakerCooldown = defaultBreakerCooldown
	}
	if normalized.BreakerCooldownMax <= 0 {
		normalized.BreakerCooldownMax = defaultBreakerMax
	}
	if normalized.BreakerCooldownMax < normalized.BreakerCooldown {
		return Policy{}, nil, fmt.Errorf(
			"%w: breaker cooldown max %s is below cooldown %s",
			ErrInvalidPolicy, normalized.BreakerCooldownMax,
			normalized.BreakerCooldown)
	}
	if normalized.BackoffBase <= 0 {
		normalized.BackoffBase = defaultBackoffBase
	}
	if normalized.BackoffMax <= 0 {
		normalized.BackoffMax = defaultBackoffMax
	}
	if normalized.BackoffMax < normalized.BackoffBase {
		return Policy{}, nil, fmt.Errorf(
			"%w: backoff max %s is below base %s",
			ErrInvalidPolicy, normalized.BackoffMax, normalized.BackoffBase)
	}
	if normalized.MaxCycles <= 0 {
		normalized.MaxCycles = defaultMaxCycles
	}
	switch {
	case normalized.Jitter < 0:
		return Policy{}, nil, fmt.Errorf("%w: jitter %s is negative",
			ErrInvalidPolicy, strconv.FormatFloat(normalized.Jitter, 'f', -1, 64))
	case normalized.Jitter == 0:
		normalized.Jitter = defaultJitter
	case normalized.Jitter > 1:
		return Policy{}, nil, fmt.Errorf("%w: jitter %s is above 1",
			ErrInvalidPolicy, strconv.FormatFloat(normalized.Jitter, 'f', -1, 64))
	}

	return normalized, warnings, nil
}

func (p Policy) Validate() error {
	_, _, err := p.Normalize()
	return err
}

func (p Policy) String() string {
	values := make([]string, len(p.Ladder))
	for i, transport := range p.Ladder {
		values[i] = string(transport)
	}
	return strings.Join(values, ",")
}
