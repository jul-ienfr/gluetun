package transport

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type fakeRunner struct {
	mutex sync.Mutex

	calls      []string
	teardowns  int
	applies    map[Transport]int
	preflights map[Transport]int
	awaits     map[Transport]int
	verifies   map[Transport]int

	preflightErrs map[Transport][]error
	applyErrs     map[Transport][]error
	awaitErrs     map[Transport][]error
	verifyErrs    map[Transport][]error

	egress        netip.Addr
	preflightHook func()
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{
		applies:    make(map[Transport]int),
		preflights: make(map[Transport]int),
		awaits:     make(map[Transport]int),
		verifies:   make(map[Transport]int),
		egress:     netip.MustParseAddr("9.9.9.9"),
	}
}

func (r *fakeRunner) Preflight(ctx context.Context, transport Transport, target Target) error {
	r.mutex.Lock()
	r.calls = append(r.calls, "preflight:"+string(transport))
	index := r.preflights[transport]
	r.preflights[transport]++
	hook := r.preflightHook
	r.mutex.Unlock()
	if hook != nil {
		hook()
	}
	return sequenceError(r.preflightErrs, transport, index)
}

func (r *fakeRunner) Teardown(ctx context.Context) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.calls = append(r.calls, "teardown")
	r.teardowns++
	return nil
}

func (r *fakeRunner) Apply(ctx context.Context, transport Transport, target Target) error {
	r.mutex.Lock()
	r.calls = append(r.calls, "apply:"+string(transport))
	index := r.applies[transport]
	r.applies[transport]++
	r.mutex.Unlock()
	return sequenceError(r.applyErrs, transport, index)
}

func (r *fakeRunner) AwaitTunnel(ctx context.Context, transport Transport, target Target) error {
	r.mutex.Lock()
	r.calls = append(r.calls, "await:"+string(transport))
	index := r.awaits[transport]
	r.awaits[transport]++
	r.mutex.Unlock()
	return sequenceError(r.awaitErrs, transport, index)
}

func (r *fakeRunner) VerifyEgress(ctx context.Context) (netip.Addr, error) {
	r.mutex.Lock()
	r.calls = append(r.calls, "verify")
	r.mutex.Unlock()
	if len(r.verifyErrs) == 0 {
		return r.egress, nil
	}
	for _, sequence := range r.verifyErrs {
		if len(sequence) > 0 && sequence[0] != nil {
			return netip.Addr{}, sequence[0]
		}
	}
	return r.egress, nil
}

func (r *fakeRunner) applyCount(transport Transport) int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.applies[transport]
}

func (r *fakeRunner) preflightCount(transport Transport) int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.preflights[transport]
}

func (r *fakeRunner) teardownCount() int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.teardowns
}

func sequenceError(sequences map[Transport][]error, transport Transport,
	index int,
) error {
	sequence, ok := sequences[transport]
	if !ok || index >= len(sequence) {
		return nil
	}
	return sequence[index]
}

func testPolicy() Policy {
	policy := DefaultPolicy()
	policy.MaxAttempts = 1
	policy.BackoffBase = time.Second
	policy.BackoffMax = 2 * time.Second
	return policy
}

func noSleep(ctx context.Context, duration time.Duration) error {
	return nil
}

func TestLadderWireGuardFirstTry(t *testing.T) {
	t.Parallel()

	runner := newFakeRunner()
	var events []Event
	ladder, err := NewLadder(testPolicy(), runner,
		WithSleep(noSleep),
		WithEventSink(func(event Event) {
			events = append(events, event)
		}))
	if err != nil {
		t.Fatalf("creating ladder: %v", err)
	}

	result, err := ladder.Run(context.Background(), Target{Hostname: "server"})
	if err != nil {
		t.Fatalf("running ladder: %v", err)
	}
	if result.Transport != WireGuard || result.Cycle != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if result.EgressIP != netip.MustParseAddr("9.9.9.9") {
		t.Fatalf("egress: %s", result.EgressIP)
	}
	if runner.applyCount(WireGuard) != 1 ||
		runner.applyCount(OpenVPNUDP) != 0 ||
		runner.applyCount(OpenVPNTCP) != 0 {
		t.Fatalf("unexpected applies: %v", runner.applies)
	}
	if runner.teardownCount() != 1 {
		t.Fatalf("teardowns: expected 1, got %d", runner.teardownCount())
	}

	state := ladder.Snapshot()
	if state.Active == nil || *state.Active != WireGuard {
		t.Fatalf("active: %v", state.Active)
	}
	if state.Phase != PhaseCommitted {
		t.Fatalf("phase: %s", state.Phase)
	}
	if state.Breakers[WireGuard].State != BreakerClosed {
		t.Fatalf("breaker: %s", state.Breakers[WireGuard].State)
	}

	if countEvents(events, EventConnected) != 1 {
		t.Fatalf("connected events: %d", countEvents(events, EventConnected))
	}
	if countEvents(events, EventAttempt) != 1 {
		t.Fatalf("attempt events: %d", countEvents(events, EventAttempt))
	}
}

func TestLadderFallsBackToOpenVPNUDP(t *testing.T) {
	t.Parallel()

	runner := newFakeRunner()
	runner.preflightErrs = map[Transport][]error{
		WireGuard: {NewFailure(ReasonUDPBlocked, errors.New("no udp"))},
	}
	var events []Event
	ladder, err := NewLadder(testPolicy(), runner,
		WithSleep(noSleep),
		WithEventSink(func(event Event) { events = append(events, event) }))
	if err != nil {
		t.Fatalf("creating ladder: %v", err)
	}

	result, err := ladder.Run(context.Background(), Target{Hostname: "server"})
	if err != nil {
		t.Fatalf("running ladder: %v", err)
	}
	if result.Transport != OpenVPNUDP {
		t.Fatalf("transport: %s", result.Transport)
	}
	if len(result.Attempts) != 2 {
		t.Fatalf("attempts: %d", len(result.Attempts))
	}
	if result.Attempts[0].Reason != ReasonUDPBlocked ||
		result.Attempts[0].Result != AttemptFailed {
		t.Fatalf("first attempt: %+v", result.Attempts[0])
	}
	if result.Attempts[1].Result != AttemptSuccess {
		t.Fatalf("second attempt: %+v", result.Attempts[1])
	}
	if runner.applyCount(WireGuard) != 0 || runner.applyCount(OpenVPNUDP) != 1 {
		t.Fatalf("unexpected applies: %v", runner.applies)
	}
	if runner.teardownCount() != 1 {
		t.Fatalf("teardowns: %d", runner.teardownCount())
	}
	if countEvents(events, EventFailed) != 1 {
		t.Fatalf("failed events: %d", countEvents(events, EventFailed))
	}
}

func TestLadderExhausted(t *testing.T) {
	t.Parallel()

	runner := newFakeRunner()
	runner.preflightErrs = map[Transport][]error{
		WireGuard: {
			NewFailure(ReasonUDPBlocked, errors.New("no")),
			NewFailure(ReasonUDPBlocked, errors.New("no")),
		},
		OpenVPNUDP: {
			NewFailure(ReasonUDPBlocked, errors.New("no")),
			NewFailure(ReasonUDPBlocked, errors.New("no")),
		},
		OpenVPNTCP: {
			NewFailure(ReasonTCPRefused, errors.New("no")),
			NewFailure(ReasonTCPRefused, errors.New("no")),
		},
	}
	var events []Event
	var sleeps int
	policy := testPolicy()
	policy.MaxCycles = 2
	ladder, err := NewLadder(policy, runner,
		WithSleep(func(ctx context.Context, duration time.Duration) error {
			sleeps++
			return nil
		}),
		WithEventSink(func(event Event) { events = append(events, event) }))
	if err != nil {
		t.Fatalf("creating ladder: %v", err)
	}

	_, err = ladder.Run(context.Background(), Target{Hostname: "server"})
	if !errors.Is(err, ErrExhausted) {
		t.Fatalf("expected ErrExhausted, got %v", err)
	}
	if runner.preflightCount(WireGuard) != 2 ||
		runner.preflightCount(OpenVPNUDP) != 2 ||
		runner.preflightCount(OpenVPNTCP) != 2 {
		t.Fatalf("preflights: %v", runner.preflights)
	}
	if sleeps != 1 {
		t.Fatalf("sleeps: expected 1, got %d", sleeps)
	}
	if countEvents(events, EventCycleExhausted) != 2 {
		t.Fatalf("cycle exhausted events: %d",
			countEvents(events, EventCycleExhausted))
	}
	if countEvents(events, EventRepairNeeded) != 1 {
		t.Fatalf("repair needed events: %d",
			countEvents(events, EventRepairNeeded))
	}
}

func TestLadderBreakerSkipsOpenTransport(t *testing.T) {
	t.Parallel()

	runner := newFakeRunner()
	runner.preflightErrs = map[Transport][]error{
		WireGuard:  {NewFailure(ReasonUDPBlocked, errors.New("no"))},
		OpenVPNUDP: {NewFailure(ReasonUDPBlocked, errors.New("no"))},
		OpenVPNTCP: {NewFailure(ReasonTCPRefused, errors.New("no"))},
	}
	policy := testPolicy()
	policy.MaxCycles = 3
	policy.BreakerThreshold = 1
	var events []Event
	ladder, err := NewLadder(policy, runner,
		WithSleep(noSleep),
		WithEventSink(func(event Event) { events = append(events, event) }))
	if err != nil {
		t.Fatalf("creating ladder: %v", err)
	}

	_, err = ladder.Run(context.Background(), Target{Hostname: "server"})
	if !errors.Is(err, ErrExhausted) {
		t.Fatalf("expected ErrExhausted, got %v", err)
	}
	if runner.preflightCount(WireGuard) != 1 ||
		runner.preflightCount(OpenVPNUDP) != 1 ||
		runner.preflightCount(OpenVPNTCP) != 1 {
		t.Fatalf("preflights: %v", runner.preflights)
	}
	if countEvents(events, EventBreakerOpen) != 3 {
		t.Fatalf("breaker open events: %d",
			countEvents(events, EventBreakerOpen))
	}

	state := ladder.Snapshot()
	for _, transport := range DefaultLadder {
		if state.Breakers[transport].State != BreakerOpen {
			t.Fatalf("%s breaker: %s", transport,
				state.Breakers[transport].State)
		}
	}

	wireguard := WireGuard
	if err := ladder.Reset(&wireguard); err != nil {
		t.Fatalf("resetting breaker: %v", err)
	}
	state = ladder.Snapshot()
	if state.Breakers[WireGuard].State != BreakerClosed {
		t.Fatalf("wireguard breaker after reset: %s",
			state.Breakers[WireGuard].State)
	}
	if state.Breakers[OpenVPNUDP].State != BreakerOpen {
		t.Fatalf("udp breaker after reset: %s",
			state.Breakers[OpenVPNUDP].State)
	}
	if countEvents(events, EventBreakerReset) != 1 {
		t.Fatalf("breaker reset events: %d",
			countEvents(events, EventBreakerReset))
	}
}

func TestLadderRetriesSameTransport(t *testing.T) {
	t.Parallel()

	runner := newFakeRunner()
	runner.preflightErrs = map[Transport][]error{
		WireGuard: {
			NewFailure(ReasonUDPBlocked, errors.New("no")),
			nil,
		},
	}
	policy := testPolicy()
	policy.MaxAttempts = 2
	ladder, err := NewLadder(policy, runner, WithSleep(noSleep))
	if err != nil {
		t.Fatalf("creating ladder: %v", err)
	}

	result, err := ladder.Run(context.Background(), Target{Hostname: "server"})
	if err != nil {
		t.Fatalf("running ladder: %v", err)
	}
	if result.Transport != WireGuard {
		t.Fatalf("transport: %s", result.Transport)
	}
	if len(result.Attempts) != 2 {
		t.Fatalf("attempts: %d", len(result.Attempts))
	}
	if result.Attempts[0].Result != AttemptFailed ||
		result.Attempts[1].Result != AttemptSuccess {
		t.Fatalf("attempts: %+v", result.Attempts)
	}
	if runner.preflightCount(WireGuard) != 2 {
		t.Fatalf("preflights: %d", runner.preflightCount(WireGuard))
	}
	if runner.teardownCount() != 1 {
		t.Fatalf("teardowns: %d", runner.teardownCount())
	}
}

func TestLadderTeardownAfterAppliedFailure(t *testing.T) {
	t.Parallel()

	runner := newFakeRunner()
	runner.awaitErrs = map[Transport][]error{
		WireGuard: {NewFailure(ReasonHandshakeTimeout, errors.New("timeout"))},
	}
	ladder, err := NewLadder(testPolicy(), runner, WithSleep(noSleep))
	if err != nil {
		t.Fatalf("creating ladder: %v", err)
	}

	result, err := ladder.Run(context.Background(), Target{Hostname: "server"})
	if err != nil {
		t.Fatalf("running ladder: %v", err)
	}
	if result.Transport != OpenVPNUDP {
		t.Fatalf("transport: %s", result.Transport)
	}
	if runner.applyCount(WireGuard) != 1 || runner.applyCount(OpenVPNUDP) != 1 {
		t.Fatalf("applies: %v", runner.applies)
	}
	if runner.teardownCount() != 3 {
		t.Fatalf("teardowns: expected 3, got %d", runner.teardownCount())
	}
}

func TestLadderRejectsConcurrentRun(t *testing.T) {
	t.Parallel()

	runner := newFakeRunner()
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	runner.preflightHook = func() {
		once.Do(func() {
			close(entered)
			<-release
		})
	}
	ladder, err := NewLadder(testPolicy(), runner, WithSleep(noSleep))
	if err != nil {
		t.Fatalf("creating ladder: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := ladder.Run(context.Background(), Target{Hostname: "server"})
		done <- err
	}()

	<-entered
	_, err = ladder.Run(context.Background(), Target{Hostname: "server"})
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Fatalf("expected ErrAlreadyRunning, got %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("first run: %v", err)
	}
}

func countEvents(events []Event, eventType string) int {
	count := 0
	for _, event := range events {
		if event.Type == eventType {
			count++
		}
	}
	return count
}
