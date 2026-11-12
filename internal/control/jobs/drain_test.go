package jobs

import (
	"context"
	"errors"
	"testing"
	"time"
)

type drainClock struct {
	now    time.Time
	sleeps []time.Duration
	err    error
}

func (c *drainClock) Now() time.Time {
	return c.now
}

func (c *drainClock) Sleep(_ context.Context, duration time.Duration) error {
	if c.err != nil {
		return c.err
	}
	c.sleeps = append(c.sleeps, duration)
	c.now = c.now.Add(duration)
	return nil
}

func newTestDrain(active func() int, timeout, interval time.Duration) (
	drain *Drain, clock *drainClock,
) {
	drain = NewDrain(active, timeout)
	clock = &drainClock{now: time.Date(2026, time.November, 12, 12, 0, 0, 0, time.UTC)}
	drain.now = clock.Now
	drain.sleep = clock.Sleep
	drain.interval = interval
	return drain, clock
}

func Test_Drain_NoConnections(t *testing.T) {
	t.Parallel()

	drain, clock := newTestDrain(func() int { return 0 }, time.Second,
		10*time.Millisecond)

	err := drain.Wait(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(clock.sleeps) != 0 {
		t.Errorf("waited %v without active connections", clock.sleeps)
	}
}

func Test_Drain_ConnectionsClose(t *testing.T) {
	t.Parallel()

	counts := []int{3, 2, 1, 0}
	calls := 0
	active := func() int {
		value := counts[calls]
		calls++
		return value
	}

	drain, clock := newTestDrain(active, time.Second, 10*time.Millisecond)

	err := drain.Wait(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != len(counts) {
		t.Errorf("active called %d times, want %d", calls, len(counts))
	}
	if len(clock.sleeps) != len(counts)-1 {
		t.Errorf("slept %d times, want %d", len(clock.sleeps), len(counts)-1)
	}
}

func Test_Drain_TimeoutIsBounded(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		timeout  time.Duration
		interval time.Duration
	}{
		"interval divides timeout": {
			timeout:  100 * time.Millisecond,
			interval: 10 * time.Millisecond,
		},
		"interval does not divide timeout": {
			timeout:  100 * time.Millisecond,
			interval: 30 * time.Millisecond,
		},
		"interval larger than timeout": {
			timeout:  10 * time.Millisecond,
			interval: time.Second,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			drain, clock := newTestDrain(func() int { return 4 },
				testCase.timeout, testCase.interval)

			err := drain.Wait(context.Background())
			if !errors.Is(err, ErrDrainTimeout) {
				t.Fatalf("error = %v, want %v", err, ErrDrainTimeout)
			}

			var waited time.Duration
			for _, sleep := range clock.sleeps {
				waited += sleep
			}
			if waited > testCase.timeout {
				t.Errorf("waited %v, above timeout %v", waited, testCase.timeout)
			}
			if waited != testCase.timeout {
				t.Errorf("waited %v, want the full timeout %v",
					waited, testCase.timeout)
			}
		})
	}
}

func Test_Drain_CanceledBeforeWait(t *testing.T) {
	t.Parallel()

	calls := 0
	active := func() int {
		calls++
		return 1
	}
	drain, clock := newTestDrain(active, time.Second, 10*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := drain.Wait(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want %v", err, context.Canceled)
	}
	if calls != 0 {
		t.Errorf("active called %d times after cancellation", calls)
	}
	if len(clock.sleeps) != 0 {
		t.Errorf("slept after cancellation: %v", clock.sleeps)
	}
}

func Test_Drain_CanceledWhileWaiting(t *testing.T) {
	t.Parallel()

	drain, clock := newTestDrain(func() int { return 2 }, time.Second,
		10*time.Millisecond)
	clock.err = context.Canceled

	err := drain.Wait(context.Background())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want %v", err, context.Canceled)
	}
}

func Test_NewDrain_Validation(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		active  func() int
		timeout time.Duration
	}{
		"nil active counter": {
			active:  nil,
			timeout: time.Second,
		},
		"zero timeout": {
			active:  func() int { return 0 },
			timeout: 0,
		},
		"negative timeout": {
			active:  func() int { return 0 },
			timeout: -time.Second,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			defer func() {
				if recover() == nil {
					t.Errorf("expected a panic")
				}
			}()
			NewDrain(testCase.active, testCase.timeout)
		})
	}
}
