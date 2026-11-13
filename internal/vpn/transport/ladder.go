package transport

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"sync"
	"time"
)

var (
	ErrAlreadyRunning = errors.New("transport ladder is already running")
	ErrExhausted      = errors.New("transport ladder exhausted")
)

const (
	EventAttempt        = "transport.attempt"
	EventConnected      = "transport.connected"
	EventFailed         = "transport.failed"
	EventBreakerOpen    = "transport.breaker_open"
	EventBreakerReset   = "transport.breaker_reset"
	EventCycleExhausted = "transport.cycle_exhausted"
	EventRepairNeeded   = "tunnel.repair_needed"
)

const (
	maxAttemptHistory = 64
	teardownTimeout   = 10 * time.Second
)

type Event struct {
	Type      string
	Transport Transport
	Server    string
	Attempt   int
	Result    AttemptResult
	Reason    Reason
	LatencyMS int64
	Cycle     int
	Ladder    []Transport
	Reasons   []Reason
	EgressIP  netip.Addr
	Failures  int
	RetryAt   time.Time
	Cycles    int
}

type EventSink func(event Event)

type Runner interface {
	Preflight(ctx context.Context, transport Transport, target Target) error
	Teardown(ctx context.Context) error
	Apply(ctx context.Context, transport Transport, target Target) error
	AwaitTunnel(ctx context.Context, transport Transport, target Target) error
	VerifyEgress(ctx context.Context) (egressIP netip.Addr, err error)
}

type Ladder struct {
	policy   Policy
	runner   Runner
	now      func() time.Time
	sleep    func(ctx context.Context, duration time.Duration) error
	events   EventSink
	metrics  *Metrics
	warnings []string

	runMu  sync.Mutex
	mutex  sync.Mutex
	state  State
	nextID int
}

type Option func(*Ladder)

func WithClock(now func() time.Time) Option {
	return func(ladder *Ladder) {
		if now != nil {
			ladder.now = now
		}
	}
}

func WithSleep(sleep func(ctx context.Context, duration time.Duration) error) Option {
	return func(ladder *Ladder) {
		if sleep != nil {
			ladder.sleep = sleep
		}
	}
}

func WithEventSink(sink EventSink) Option {
	return func(ladder *Ladder) {
		ladder.events = sink
	}
}

func WithMetrics(metrics *Metrics) Option {
	return func(ladder *Ladder) {
		ladder.metrics = metrics
	}
}

func NewLadder(policy Policy, runner Runner, options ...Option) (*Ladder, error) {
	if runner == nil {
		return nil, errors.New("transport runner is nil")
	}
	normalized, warnings, err := policy.Normalize()
	if err != nil {
		return nil, err
	}

	ladder := &Ladder{
		policy:   normalized,
		runner:   runner,
		now:      time.Now,
		sleep:    sleepContext,
		warnings: warnings,
		state: State{
			Phase:    PhaseIdle,
			Breakers: make(map[Transport]Breaker, len(normalized.Ladder)),
		},
	}
	for _, transport := range normalized.Ladder {
		ladder.state.Breakers[transport] = NewBreaker()
	}
	for _, option := range options {
		option(ladder)
	}
	return ladder, nil
}

func (l *Ladder) Policy() Policy {
	return l.policy
}

func (l *Ladder) Warnings() []string {
	return append([]string(nil), l.warnings...)
}

// SetEventSink replaces the event sink. It is safe to call while the ladder is
// running so the control plane can attach its bus after startup.
func (l *Ladder) SetEventSink(sink EventSink) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.events = sink
}

// ReportFailure records a failure for a committed transport, for example when
// the watchdog had to repair the tunnel. It lets the next run skip the
// transport once its breaker opens.
func (l *Ladder) ReportFailure(transport Transport, reason Reason) {
	now := l.now()
	l.mutex.Lock()
	breaker, ok := l.state.Breakers[transport]
	if !ok {
		l.mutex.Unlock()
		return
	}
	opened := breaker.Failure(now, l.policy.BreakerThreshold,
		l.policy.BreakerCooldown, l.policy.BreakerCooldownMax)
	l.state.Breakers[transport] = breaker
	l.state.UpdatedAt = now
	l.mutex.Unlock()

	if l.metrics != nil {
		l.metrics.ObserveAttempt(transport, AttemptFailed, reason, 0)
		l.metrics.SetBreaker(transport, breaker.State)
	}

	l.emit(Event{
		Type:      EventFailed,
		Transport: transport,
		Result:    AttemptFailed,
		Reason:    reason,
	})
	if opened {
		l.emit(Event{
			Type:      EventBreakerOpen,
			Transport: transport,
			Failures:  breaker.Failures,
			RetryAt:   breaker.RetryAt,
		})
	}
}

func (l *Ladder) Snapshot() State {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return l.state.Clone()
}

func (l *Ladder) Reset(transport *Transport) error {
	if transport != nil && !transport.Valid() {
		return fmt.Errorf("%w: unknown transport %q",
			ErrInvalidPolicy, *transport)
	}

	l.mutex.Lock()
	now := l.now()
	if transport == nil {
		for name := range l.state.Breakers {
			breaker := l.state.Breakers[name]
			breaker.Reset()
			l.state.Breakers[name] = breaker
		}
		l.state.UpdatedAt = now
		l.mutex.Unlock()
		l.emit(Event{Type: EventBreakerReset})
		return nil
	}
	breaker, ok := l.state.Breakers[*transport]
	if !ok {
		l.mutex.Unlock()
		return fmt.Errorf("%w: transport %q is not in the ladder",
			ErrInvalidPolicy, *transport)
	}
	breaker.Reset()
	l.state.Breakers[*transport] = breaker
	l.state.UpdatedAt = now
	l.mutex.Unlock()
	l.emit(Event{Type: EventBreakerReset, Transport: *transport})
	return nil
}

func (l *Ladder) Run(ctx context.Context, target Target) (result Result, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if target.Hostname == "" {
		return Result{}, NewFailure(ReasonConfigInvalid,
			errors.New("target hostname is empty"))
	}
	if !l.runMu.TryLock() {
		return Result{}, ErrAlreadyRunning
	}
	defer l.runMu.Unlock()

	l.begin()
	attempts := make([]Attempt, 0, len(l.policy.Ladder))
	var lastReasons []Reason

	for cycle := 1; cycle <= l.policy.MaxCycles; cycle++ {
		l.setCycle(cycle)

		for _, transport := range l.policy.Ladder {
			if ctx.Err() != nil {
				return Result{Cycle: cycle, Attempts: attempts}, ctx.Err()
			}

			now := l.now()
			breaker := l.breaker(transport)
			allowed, halfOpen := breaker.Allow(now)
			l.setBreaker(transport, breaker)
			if l.metrics != nil {
				l.metrics.SetBreaker(transport, breaker.State)
			}
			if halfOpen {
				l.emit(Event{
					Type:      EventBreakerOpen,
					Transport: transport,
					Server:    target.Hostname,
					Failures:  breaker.Failures,
					RetryAt:   now,
				})
			}
			if !allowed {
				skipped := Attempt{
					ID:        l.attemptID(cycle, transport, 0),
					Transport: transport,
					Server:    target.Hostname,
					Started:   now,
					Ended:     now,
					Result:    AttemptSkipped,
					Reason:    ReasonBreakerOpen,
					NextRetry: breaker.RetryAt,
				}
				attempts = l.appendAttempt(attempts, skipped)
				if l.metrics != nil {
					l.metrics.ObserveAttempt(transport, AttemptSkipped,
						ReasonBreakerOpen, 0)
				}
				l.emit(Event{
					Type:      EventAttempt,
					Transport: transport,
					Server:    target.Hostname,
					Result:    AttemptSkipped,
					Reason:    ReasonBreakerOpen,
					Cycle:     cycle,
					RetryAt:   breaker.RetryAt,
				})
				lastReasons = append(lastReasons, ReasonBreakerOpen)
				continue
			}

			transportDone := false
			for attemptNumber := 1; attemptNumber <= l.policy.MaxAttempts; attemptNumber++ {
				if ctx.Err() != nil {
					return Result{Cycle: cycle, Attempts: attempts}, ctx.Err()
				}

				started := l.now()
				attemptCtx, cancel := context.WithTimeout(ctx,
					l.policy.AttemptTimeout[transport])
				egressIP, applied, attemptErr := l.attempt(attemptCtx, transport, target)
				cancel()
				ended := l.now()

				attempt := Attempt{
					ID:        l.attemptID(cycle, transport, attemptNumber),
					Transport: transport,
					Server:    target.Hostname,
					Started:   started,
					Ended:     ended,
					Latency:   ended.Sub(started),
				}

				if attemptErr == nil {
					attempt.Result = AttemptSuccess
					attempts = l.appendAttempt(attempts, attempt)
					breaker = l.breaker(transport)
					breaker.Success()
					l.setBreaker(transport, breaker)
					l.setCommitted(transport, cycle)
					if l.metrics != nil {
						l.metrics.ObserveAttempt(transport, AttemptSuccess,
							ReasonNone, ended.Sub(started))
						l.metrics.SetActive(transport)
						l.metrics.SetBreaker(transport, BreakerClosed)
						l.metrics.ObserveCycle("committed")
					}
					l.emit(Event{
						Type:      EventAttempt,
						Transport: transport,
						Server:    target.Hostname,
						Attempt:   attemptNumber,
						Result:    AttemptSuccess,
						Cycle:     cycle,
						EgressIP:  egressIP,
					})
					l.emit(Event{
						Type:      EventConnected,
						Transport: transport,
						Server:    target.Hostname,
						Attempt:   attemptNumber,
						Result:    AttemptSuccess,
						Cycle:     cycle,
						LatencyMS: ended.Sub(started).Milliseconds(),
						EgressIP:  egressIP,
					})
					return Result{
						Transport: transport,
						Cycle:     cycle,
						Attempts:  attempts,
						EgressIP:  egressIP,
					}, nil
				}

				reason := ReasonOf(attemptErr)
				attempt.Result = AttemptFailed
				attempt.Reason = reason
				attempts = l.appendAttempt(attempts, attempt)
				lastReasons = append(lastReasons, reason)

				breaker = l.breaker(transport)
				opened := breaker.Failure(ended, l.policy.BreakerThreshold,
					l.policy.BreakerCooldown, l.policy.BreakerCooldownMax)
				l.setBreaker(transport, breaker)
				attempt.NextRetry = breaker.RetryAt
				if l.metrics != nil {
					l.metrics.ObserveAttempt(transport, AttemptFailed, reason,
						ended.Sub(started))
					l.metrics.SetBreaker(transport, breaker.State)
				}

				l.emit(Event{
					Type:      EventAttempt,
					Transport: transport,
					Server:    target.Hostname,
					Attempt:   attemptNumber,
					Result:    AttemptFailed,
					Reason:    reason,
					Cycle:     cycle,
					LatencyMS: ended.Sub(started).Milliseconds(),
				})
				l.emit(Event{
					Type:      EventFailed,
					Transport: transport,
					Server:    target.Hostname,
					Attempt:   attemptNumber,
					Result:    AttemptFailed,
					Reason:    reason,
					Cycle:     cycle,
					LatencyMS: ended.Sub(started).Milliseconds(),
				})
				if opened {
					l.emit(Event{
						Type:      EventBreakerOpen,
						Transport: transport,
						Server:    target.Hostname,
						Failures:  breaker.Failures,
						RetryAt:   breaker.RetryAt,
					})
				}

				if applied {
					l.teardown(ctx, transport)
				}

				if reason == ReasonAuth || reason == ReasonConfigInvalid {
					transportDone = true
					break
				}
			}

			if transportDone {
				continue
			}
		}

		l.emit(Event{
			Type:    EventCycleExhausted,
			Cycle:   cycle,
			Ladder:  append([]Transport(nil), l.policy.Ladder...),
			Reasons: append([]Reason(nil), lastReasons...),
		})
		if l.metrics != nil {
			l.metrics.ObserveCycle("exhausted")
			l.metrics.ObserveCycleExhausted()
		}

		if cycle == l.policy.MaxCycles {
			break
		}

		duration := l.backoff(cycle)
		next := l.now().Add(duration)
		l.setNextAt(&next)
		l.setPhase(PhaseCooldown)
		if err := l.sleep(ctx, duration); err != nil {
			l.setNextAt(nil)
			return Result{Cycle: cycle, Attempts: attempts}, err
		}
		l.setNextAt(nil)
	}

	l.setPhase(PhaseIdle)
	l.emit(Event{
		Type:    EventRepairNeeded,
		Cycles:  l.policy.MaxCycles,
		Ladder:  append([]Transport(nil), l.policy.Ladder...),
		Reasons: append([]Reason(nil), lastReasons...),
	})
	return Result{Attempts: attempts}, fmt.Errorf("%w: %d cycles",
		ErrExhausted, l.policy.MaxCycles)
}

func (l *Ladder) attempt(ctx context.Context, transport Transport,
	target Target,
) (egressIP netip.Addr, applied bool, err error) {
	l.setPhase(PhasePreflight)
	err = l.runner.Preflight(ctx, transport, target)
	if err != nil {
		return netip.Addr{}, false, err
	}

	l.setPhase(PhaseApplying)
	err = l.runner.Teardown(ctx)
	if err != nil {
		return netip.Addr{}, false, NewFailure(ReasonInterfaceDown, err)
	}
	if l.metrics != nil {
		l.metrics.SetActive("")
	}

	err = l.runner.Apply(ctx, transport, target)
	if err != nil {
		return netip.Addr{}, true, err
	}
	applied = true

	l.setPhase(PhaseAwaitingTunnel)
	err = l.runner.AwaitTunnel(ctx, transport, target)
	if err != nil {
		return netip.Addr{}, applied, err
	}

	l.setPhase(PhaseVerifying)
	egressIP, err = l.runner.VerifyEgress(ctx)
	if err != nil {
		return netip.Addr{}, applied, err
	}
	return egressIP, applied, nil
}

func (l *Ladder) teardown(ctx context.Context, transport Transport) {
	teardownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx),
		teardownTimeout)
	defer cancel()
	if err := l.runner.Teardown(teardownCtx); err != nil {
		l.emit(Event{
			Type:      EventFailed,
			Transport: transport,
			Reason:    ReasonInterfaceDown,
		})
	}
}

func (l *Ladder) backoff(cycle int) time.Duration {
	duration := l.policy.BackoffBase
	for i := 1; i < cycle; i++ {
		if duration >= l.policy.BackoffMax {
			break
		}
		duration *= 2
	}
	if duration > l.policy.BackoffMax {
		duration = l.policy.BackoffMax
	}
	if l.policy.Jitter > 0 {
		jitter := l.policy.Jitter
		factor := 1 - jitter + 2*jitter*rand.Float64()
		duration = time.Duration(float64(duration) * factor)
	}
	return duration
}

func (l *Ladder) begin() {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.state = State{
		Phase:     PhaseIdle,
		Breakers:  l.state.Breakers,
		Attempts:  nil,
		UpdatedAt: l.now(),
	}
}

func (l *Ladder) setCycle(cycle int) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.state.Cycle = cycle
	l.state.UpdatedAt = l.now()
}

func (l *Ladder) setPhase(phase Phase) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.state.Phase = phase
	l.state.UpdatedAt = l.now()
}

func (l *Ladder) setCommitted(transport Transport, cycle int) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	active := transport
	l.state.Active = &active
	l.state.Phase = PhaseCommitted
	l.state.Cycle = cycle
	l.state.UpdatedAt = l.now()
}

func (l *Ladder) setNextAt(next *time.Time) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	if next == nil {
		l.state.NextAt = nil
	} else {
		value := *next
		l.state.NextAt = &value
	}
	l.state.UpdatedAt = l.now()
}

func (l *Ladder) breaker(transport Transport) Breaker {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	breaker, ok := l.state.Breakers[transport]
	if !ok {
		return NewBreaker()
	}
	return breaker
}

func (l *Ladder) setBreaker(transport Transport, breaker Breaker) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.state.Breakers[transport] = breaker
	l.state.UpdatedAt = l.now()
}

func (l *Ladder) appendAttempt(attempts []Attempt, attempt Attempt) []Attempt {
	attempts = append(attempts, attempt)
	if len(attempts) > maxAttemptHistory {
		attempts = attempts[len(attempts)-maxAttemptHistory:]
	}
	l.mutex.Lock()
	l.state.Attempts = append([]Attempt(nil), attempts...)
	l.state.UpdatedAt = l.now()
	l.mutex.Unlock()
	return attempts
}

func (l *Ladder) attemptID(cycle int, transport Transport, attempt int) string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.nextID++
	return fmt.Sprintf("%d-%s-%d", cycle, transport, l.nextID)
}

func (l *Ladder) emit(event Event) {
	l.mutex.Lock()
	sink := l.events
	l.mutex.Unlock()
	if sink == nil {
		return
	}
	sink(event)
}

func sleepContext(ctx context.Context, duration time.Duration) error {
	if duration <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
