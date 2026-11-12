package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var ErrRepairNeeded = errors.New("tunnel repair needed")

type Problem string

const (
	ProblemNone             Problem = ""
	ProblemInterfaceDown    Problem = "interface_down"
	ProblemHandshakeStale   Problem = "handshake_stale"
	ProblemStatusNotRunning Problem = "status_not_running"
	ProblemDNSUnreachable   Problem = "dns_unreachable"
)

type Health struct {
	InterfaceUp  bool
	HandshakeAt  time.Time
	Status       string
	DNSReachable bool
}

type HealthProbe interface {
	Health(ctx context.Context, transport Transport, target Target) (Health, error)
}

type Reconnector interface {
	Reconnect(ctx context.Context, transport Transport, target Target) error
}

type WatchdogSettings struct {
	Interval      time.Duration
	StaleAfter    time.Duration
	MaxReconnects int
	Now           func() time.Time
}

type Watchdog struct {
	interval      time.Duration
	staleAfter    time.Duration
	maxReconnects int
	now           func() time.Time

	mutex      sync.Mutex
	reconnects int
}

func NewWatchdog(settings WatchdogSettings) *Watchdog {
	interval := settings.Interval
	if interval <= 0 {
		interval = time.Second
	}
	staleAfter := settings.StaleAfter
	if staleAfter <= 0 {
		staleAfter = 30 * time.Second
	}
	maxReconnects := settings.MaxReconnects
	if maxReconnects <= 0 {
		maxReconnects = 3
	}
	now := settings.Now
	if now == nil {
		now = time.Now
	}
	return &Watchdog{
		interval:      interval,
		staleAfter:    staleAfter,
		maxReconnects: maxReconnects,
		now:           now,
	}
}

func (w *Watchdog) Check(health Health) (problem Problem, unhealthy bool) {
	switch {
	case !health.InterfaceUp:
		return ProblemInterfaceDown, true
	case health.Status != "running":
		return ProblemStatusNotRunning, true
	case health.HandshakeAt.IsZero() ||
		w.now().Sub(health.HandshakeAt) > w.staleAfter:
		return ProblemHandshakeStale, true
	case !health.DNSReachable:
		return ProblemDNSUnreachable, true
	default:
		return ProblemNone, false
	}
}

func (w *Watchdog) Handle(ctx context.Context, problem Problem,
	reconnector Reconnector, transport Transport, target Target,
) (reconnected bool, err error) {
	if problem == ProblemNone {
		w.Reset()
		return false, nil
	}

	w.mutex.Lock()
	if w.reconnects >= w.maxReconnects {
		reconnects := w.reconnects
		w.mutex.Unlock()
		return false, fmt.Errorf("%w: %d local reconnects for %s",
			ErrRepairNeeded, reconnects, transport)
	}
	w.reconnects++
	w.mutex.Unlock()

	err = reconnector.Reconnect(ctx, transport, target)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (w *Watchdog) Reconnects() int {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	return w.reconnects
}

func (w *Watchdog) Reset() {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.reconnects = 0
}

func (w *Watchdog) Run(ctx context.Context, probe HealthProbe,
	reconnector Reconnector, transport Transport, target Target,
) error {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			health, err := probe.Health(ctx, transport, target)
			if err != nil {
				continue
			}
			problem, unhealthy := w.Check(health)
			if !unhealthy {
				w.Reset()
				continue
			}
			_, err = w.Handle(ctx, problem, reconnector, transport, target)
			if errors.Is(err, ErrRepairNeeded) {
				return err
			}
		}
	}
}
