package settings

import (
	"fmt"
	"strings"
	"time"

	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/validate"
	"github.com/qdm12/gotree"
)

// DefaultTransportLadder is the ordered transport ladder used when the user
// does not provide one.
var DefaultTransportLadder = []string{ //nolint:gochecknoglobals
	"wireguard", "openvpn-udp", "openvpn-tcp",
}

const (
	defaultTransportAttemptTimeout    = 30 * time.Second
	defaultTransportAttemptTimeoutTCP = 45 * time.Second
	defaultTransportMaxAttempts       = 2
	defaultTransportBreakerThreshold  = 3
	defaultTransportBreakerCooldown   = 120 * time.Second
	defaultTransportBreakerMax        = 900 * time.Second
	defaultTransportBackoffBase       = 30 * time.Second
	defaultTransportBackoffMax        = 300 * time.Second
	defaultTransportMaxCycles         = 3
	defaultTransportJitter            = 0.2
	defaultTransportLocalReconnects   = 3
)

// TransportLadder contains the transport ladder settings.
type TransportLadder struct {
	// Enabled activates the runtime transport ladder.
	// It defaults to true.
	Enabled *bool
	// Ladder is the ordered list of transports to try.
	// It defaults to [wireguard openvpn-udp openvpn-tcp].
	Ladder []string
	// AttemptTimeout is the budget of one WireGuard or OpenVPN UDP attempt.
	// It defaults to 30s.
	AttemptTimeout time.Duration
	// AttemptTimeoutTCP is the budget of one OpenVPN TCP attempt.
	// It defaults to 45s.
	AttemptTimeoutTCP time.Duration
	// MaxAttempts is the number of attempts per transport in a cycle.
	// It defaults to 2.
	MaxAttempts int
	// BreakerThreshold is the number of consecutive failures opening a breaker.
	// It defaults to 3.
	BreakerThreshold int
	// BreakerCooldown is the initial cooldown of an open breaker.
	// It defaults to 120s.
	BreakerCooldown time.Duration
	// BreakerCooldownMax is the cooldown backoff ceiling of a breaker.
	// It defaults to 900s.
	BreakerCooldownMax time.Duration
	// BackoffBase is the backoff after an exhausted cycle.
	// It defaults to 30s.
	BackoffBase time.Duration
	// BackoffMax is the backoff ceiling of an exhausted cycle.
	// It defaults to 300s.
	BackoffMax time.Duration
	// MaxCycles is the number of complete cycles before asking for repair.
	// It defaults to 3.
	MaxCycles int
	// Jitter is the fraction of jitter applied to backoffs.
	// It defaults to 0.2.
	Jitter float64
	// LocalReconnectMax is the number of same-server reconnects before
	// escalating to the next transport.
	// It defaults to 3.
	LocalReconnectMax int
}

func (t TransportLadder) enabled() bool {
	return t.Enabled == nil || *t.Enabled
}

func (t TransportLadder) validate() (err error) {
	if !t.enabled() {
		return nil
	}

	if len(t.Ladder) == 0 {
		return fmt.Errorf("ladder is empty")
	}

	validTransports := []string{"wireguard", "openvpn-udp", "openvpn-tcp"}
	for i, transport := range t.Ladder {
		err = validate.IsOneOf(transport, validTransports...)
		if err != nil {
			return fmt.Errorf("transport %d: %w", i+1, err)
		}
	}

	switch {
	case t.AttemptTimeout <= 0:
		return fmt.Errorf("attempt timeout must be positive: %s", t.AttemptTimeout)
	case t.AttemptTimeoutTCP <= 0:
		return fmt.Errorf("TCP attempt timeout must be positive: %s", t.AttemptTimeoutTCP)
	case t.MaxAttempts < 1:
		return fmt.Errorf("maximum attempts must be at least 1: %d", t.MaxAttempts)
	case t.BreakerThreshold < 1:
		return fmt.Errorf("breaker threshold must be at least 1: %d", t.BreakerThreshold)
	case t.BreakerCooldown < 0:
		return fmt.Errorf("breaker cooldown must not be negative: %s", t.BreakerCooldown)
	case t.BreakerCooldownMax < t.BreakerCooldown:
		return fmt.Errorf("breaker cooldown maximum %s is less than cooldown %s",
			t.BreakerCooldownMax, t.BreakerCooldown)
	case t.BackoffBase < 0:
		return fmt.Errorf("backoff base must not be negative: %s", t.BackoffBase)
	case t.BackoffMax < t.BackoffBase:
		return fmt.Errorf("backoff maximum %s is less than base %s",
			t.BackoffMax, t.BackoffBase)
	case t.MaxCycles < 1:
		return fmt.Errorf("maximum cycles must be at least 1: %d", t.MaxCycles)
	case t.Jitter < 0:
		return fmt.Errorf("jitter must not be negative: %v", t.Jitter)
	case t.Jitter > 1:
		return fmt.Errorf("jitter must not be above 1: %v", t.Jitter)
	case t.LocalReconnectMax < 1:
		return fmt.Errorf("local reconnect maximum must be at least 1: %d",
			t.LocalReconnectMax)
	}

	return nil
}

func (t TransportLadder) copy() (copied TransportLadder) {
	return TransportLadder{
		Enabled:            gosettings.CopyPointer(t.Enabled),
		Ladder:             gosettings.CopySlice(t.Ladder),
		AttemptTimeout:     t.AttemptTimeout,
		AttemptTimeoutTCP:  t.AttemptTimeoutTCP,
		MaxAttempts:        t.MaxAttempts,
		BreakerThreshold:   t.BreakerThreshold,
		BreakerCooldown:    t.BreakerCooldown,
		BreakerCooldownMax: t.BreakerCooldownMax,
		BackoffBase:        t.BackoffBase,
		BackoffMax:         t.BackoffMax,
		MaxCycles:          t.MaxCycles,
		Jitter:             t.Jitter,
		LocalReconnectMax:  t.LocalReconnectMax,
	}
}

func (t *TransportLadder) overrideWith(other TransportLadder) {
	t.Enabled = gosettings.OverrideWithPointer(t.Enabled, other.Enabled)
	t.Ladder = gosettings.OverrideWithSlice(t.Ladder, other.Ladder)
	t.AttemptTimeout = gosettings.OverrideWithComparable(t.AttemptTimeout, other.AttemptTimeout)
	t.AttemptTimeoutTCP = gosettings.OverrideWithComparable(t.AttemptTimeoutTCP, other.AttemptTimeoutTCP)
	t.MaxAttempts = gosettings.OverrideWithComparable(t.MaxAttempts, other.MaxAttempts)
	t.BreakerThreshold = gosettings.OverrideWithComparable(t.BreakerThreshold, other.BreakerThreshold)
	t.BreakerCooldown = gosettings.OverrideWithComparable(t.BreakerCooldown, other.BreakerCooldown)
	t.BreakerCooldownMax = gosettings.OverrideWithComparable(t.BreakerCooldownMax, other.BreakerCooldownMax)
	t.BackoffBase = gosettings.OverrideWithComparable(t.BackoffBase, other.BackoffBase)
	t.BackoffMax = gosettings.OverrideWithComparable(t.BackoffMax, other.BackoffMax)
	t.MaxCycles = gosettings.OverrideWithComparable(t.MaxCycles, other.MaxCycles)
	t.Jitter = gosettings.OverrideWithComparable(t.Jitter, other.Jitter)
	t.LocalReconnectMax = gosettings.OverrideWithComparable(t.LocalReconnectMax, other.LocalReconnectMax)
}

func (t *TransportLadder) setDefaults() {
	t.Enabled = gosettings.DefaultPointer(t.Enabled, true)
	t.Ladder = gosettings.DefaultSlice(t.Ladder, DefaultTransportLadder)
	t.AttemptTimeout = gosettings.DefaultComparable(t.AttemptTimeout,
		defaultTransportAttemptTimeout)
	t.AttemptTimeoutTCP = gosettings.DefaultComparable(t.AttemptTimeoutTCP,
		defaultTransportAttemptTimeoutTCP)
	t.MaxAttempts = gosettings.DefaultComparable(t.MaxAttempts,
		defaultTransportMaxAttempts)
	t.BreakerThreshold = gosettings.DefaultComparable(t.BreakerThreshold,
		defaultTransportBreakerThreshold)
	t.BreakerCooldown = gosettings.DefaultComparable(t.BreakerCooldown,
		defaultTransportBreakerCooldown)
	t.BreakerCooldownMax = gosettings.DefaultComparable(t.BreakerCooldownMax,
		defaultTransportBreakerMax)
	t.BackoffBase = gosettings.DefaultComparable(t.BackoffBase,
		defaultTransportBackoffBase)
	t.BackoffMax = gosettings.DefaultComparable(t.BackoffMax,
		defaultTransportBackoffMax)
	t.MaxCycles = gosettings.DefaultComparable(t.MaxCycles,
		defaultTransportMaxCycles)
	t.Jitter = gosettings.DefaultComparable(t.Jitter,
		defaultTransportJitter)
	t.LocalReconnectMax = gosettings.DefaultComparable(t.LocalReconnectMax,
		defaultTransportLocalReconnects)
}

func (t TransportLadder) String() string {
	return t.toLinesNode().String()
}

func (t TransportLadder) toLinesNode() (node *gotree.Node) {
	node = gotree.New("Transport ladder settings:")
	node.Appendf("Enabled: %s", gosettings.BoolToYesNo(t.Enabled))
	node.Appendf("Ladder: %s", strings.Join(t.Ladder, ", "))
	node.Appendf("Attempt timeout: %s", t.AttemptTimeout)
	node.Appendf("TCP attempt timeout: %s", t.AttemptTimeoutTCP)
	node.Appendf("Maximum attempts: %d", t.MaxAttempts)
	node.Appendf("Breaker threshold: %d", t.BreakerThreshold)
	node.Appendf("Breaker cooldown: %s", t.BreakerCooldown)
	node.Appendf("Breaker cooldown maximum: %s", t.BreakerCooldownMax)
	node.Appendf("Backoff base: %s", t.BackoffBase)
	node.Appendf("Backoff maximum: %s", t.BackoffMax)
	node.Appendf("Maximum cycles: %d", t.MaxCycles)
	node.Appendf("Jitter: %v", t.Jitter)
	node.Appendf("Local reconnect maximum: %d", t.LocalReconnectMax)
	return node
}

func (t *TransportLadder) read(r *reader.Reader) (err error) {
	t.Enabled, err = r.BoolPtr("TRANSPORT_ENABLED")
	if err != nil {
		return err
	}

	t.Ladder = r.CSV("TRANSPORT_LADDER")

	attemptTimeoutS, err := r.UintPtr("TRANSPORT_ATTEMPT_TIMEOUT_S")
	if err != nil {
		return err
	}
	if attemptTimeoutS != nil {
		t.AttemptTimeout = time.Duration(*attemptTimeoutS) * time.Second //nolint:gosec
	}

	tcpTimeoutS, err := r.UintPtr("TRANSPORT_ATTEMPT_TIMEOUT_TCP_S")
	if err != nil {
		return err
	}
	switch {
	case tcpTimeoutS != nil:
		t.AttemptTimeoutTCP = time.Duration(*tcpTimeoutS) * time.Second //nolint:gosec
	case attemptTimeoutS != nil:
		t.AttemptTimeoutTCP = time.Duration(*attemptTimeoutS) * time.Second //nolint:gosec
	}

	maxAttempts, err := r.UintPtr("TRANSPORT_MAX_ATTEMPTS")
	if err != nil {
		return err
	}
	if maxAttempts != nil {
		t.MaxAttempts = int(*maxAttempts) //nolint:gosec
	}

	breakerThreshold, err := r.UintPtr("TRANSPORT_BREAKER_THRESHOLD")
	if err != nil {
		return err
	}
	if breakerThreshold != nil {
		t.BreakerThreshold = int(*breakerThreshold) //nolint:gosec
	}

	breakerCooldownS, err := r.UintPtr("TRANSPORT_BREAKER_COOLDOWN_S")
	if err != nil {
		return err
	}
	if breakerCooldownS != nil {
		t.BreakerCooldown = time.Duration(*breakerCooldownS) * time.Second //nolint:gosec
	}

	breakerCooldownMaxS, err := r.UintPtr("TRANSPORT_BREAKER_COOLDOWN_MAX_S")
	if err != nil {
		return err
	}
	if breakerCooldownMaxS != nil {
		t.BreakerCooldownMax = time.Duration(*breakerCooldownMaxS) * time.Second //nolint:gosec
	}

	backoffBaseS, err := r.UintPtr("TRANSPORT_BACKOFF_BASE_S")
	if err != nil {
		return err
	}
	if backoffBaseS != nil {
		t.BackoffBase = time.Duration(*backoffBaseS) * time.Second //nolint:gosec
	}

	backoffMaxS, err := r.UintPtr("TRANSPORT_BACKOFF_MAX_S")
	if err != nil {
		return err
	}
	if backoffMaxS != nil {
		t.BackoffMax = time.Duration(*backoffMaxS) * time.Second //nolint:gosec
	}

	maxCycles, err := r.UintPtr("TRANSPORT_MAX_CYCLES")
	if err != nil {
		return err
	}
	if maxCycles != nil {
		t.MaxCycles = int(*maxCycles) //nolint:gosec
	}

	jitter, err := r.Float64Ptr("TRANSPORT_JITTER")
	if err != nil {
		return err
	}
	if jitter != nil {
		t.Jitter = *jitter
	}

	localReconnects, err := r.UintPtr("TRANSPORT_LOCAL_RECONNECT_MAX")
	if err != nil {
		return err
	}
	if localReconnects != nil {
		t.LocalReconnectMax = int(*localReconnects) //nolint:gosec
	}

	return nil
}
