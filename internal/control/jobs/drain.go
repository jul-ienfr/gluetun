package jobs

import (
	"context"
	"errors"
	"time"
)

// EventDrainTimeout is emitted when the drain deadline is reached while
// proxy connections are still active.
const EventDrainTimeout = "drain.timeout"

// ErrDrainTimeout is returned when active connections outlive the drain.
var ErrDrainTimeout = errors.New("drain timeout")

// Drain waits for active proxy connections to close, bounded by a timeout.
type Drain struct {
	active   func() int
	timeout  time.Duration
	interval time.Duration
	now      func() time.Time
	sleep    func(ctx context.Context, duration time.Duration) error
}

// NewDrain creates a bounded drain. The active counter must return quickly and
// must not block.
func NewDrain(active func() int, timeout time.Duration) *Drain {
	if active == nil {
		panic("drain active counter is nil")
	}
	if timeout <= 0 {
		panic("drain timeout must be positive")
	}

	const (
		intervalDivisor = 20
		maxInterval     = 100 * time.Millisecond
	)
	interval := timeout / intervalDivisor
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	if interval > maxInterval {
		interval = maxInterval
	}

	return &Drain{
		active:   active,
		timeout:  timeout,
		interval: interval,
		now:      time.Now,
		sleep:    sleepContext,
	}
}

// Wait polls the active counter until it reports zero. It returns
// ErrDrainTimeout at the deadline, the context error when the job is
// canceled, or nil when every connection has closed.
func (d *Drain) Wait(ctx context.Context) error {
	if ctx == nil {
		panic("drain context is nil")
	}
	err := ctx.Err()
	if err != nil {
		return err
	}

	deadline := d.now().Add(d.timeout)
	for {
		if d.active() <= 0 {
			return nil
		}

		remaining := deadline.Sub(d.now())
		if remaining <= 0 {
			return ErrDrainTimeout
		}

		wait := d.interval
		if wait > remaining {
			wait = remaining
		}
		err = d.sleep(ctx, wait)
		if err != nil {
			return err
		}
	}
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
