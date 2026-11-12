package integration

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/vpn/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ladderRunner struct {
	mutex sync.Mutex

	preflightErrs map[transport.Transport][]error
	applyErrs     map[transport.Transport][]error
	awaitErrs     map[transport.Transport][]error
	verifyErrs    []error
	egress        netip.Addr

	preflights map[transport.Transport]int
}

func newLadderRunner() *ladderRunner {
	return &ladderRunner{
		preflightErrs: make(map[transport.Transport][]error),
		applyErrs:     make(map[transport.Transport][]error),
		awaitErrs:     make(map[transport.Transport][]error),
		egress:        netip.MustParseAddr("198.51.100.8"),
		preflights:    make(map[transport.Transport]int),
	}
}

func popError(sequences map[transport.Transport][]error,
	name transport.Transport,
) error {
	sequence := sequences[name]
	if len(sequence) == 0 {
		return nil
	}
	err := sequence[0]
	sequences[name] = sequence[1:]
	return err
}

func (r *ladderRunner) Preflight(_ context.Context,
	name transport.Transport, _ transport.Target,
) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.preflights[name]++
	return popError(r.preflightErrs, name)
}

func (r *ladderRunner) Teardown(context.Context) error {
	return nil
}

func (r *ladderRunner) Apply(_ context.Context, name transport.Transport,
	_ transport.Target,
) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return popError(r.applyErrs, name)
}

func (r *ladderRunner) AwaitTunnel(_ context.Context,
	name transport.Transport, _ transport.Target,
) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return popError(r.awaitErrs, name)
}

func (r *ladderRunner) VerifyEgress(context.Context) (netip.Addr, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if len(r.verifyErrs) == 0 {
		return r.egress, nil
	}
	err := r.verifyErrs[0]
	r.verifyErrs = r.verifyErrs[1:]
	if err != nil {
		return netip.Addr{}, err
	}
	return r.egress, nil
}

func (r *ladderRunner) preflightCount(name transport.Transport) int {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.preflights[name]
}

func ladderPolicy(ladder ...transport.Transport) transport.Policy {
	policy := transport.DefaultPolicy()
	policy.Ladder = ladder
	policy.MaxAttempts = 1
	policy.MaxCycles = 1
	policy.BreakerThreshold = 5
	policy.BackoffBase = time.Millisecond
	policy.BackoffMax = time.Millisecond
	return policy
}

func noSleep(context.Context, time.Duration) error { return nil }

func newTestLadder(t *testing.T, policy transport.Policy,
	runner *ladderRunner,
) *transport.Ladder {
	t.Helper()
	ladder, err := transport.NewLadder(policy, runner,
		transport.WithSleep(noSleep))
	require.NoError(t, err)
	return ladder
}

func Test_TR_Ladder_UDPBlockedFallsBackToTCP(t *testing.T) {
	t.Parallel()

	runner := newLadderRunner()
	runner.preflightErrs[transport.OpenVPNUDP] = []error{
		transport.NewFailure(transport.ReasonUDPBlocked,
			errors.New("udp is blocked")),
	}
	ladder := newTestLadder(t, ladderPolicy(transport.OpenVPNUDP,
		transport.OpenVPNTCP), runner)

	result, err := ladder.Run(t.Context(), transport.Target{
		Hostname: "nl-1234.nordvpn.com",
	})
	require.NoError(t, err)
	assert.Equal(t, transport.OpenVPNTCP, result.Transport)
	require.Len(t, result.Attempts, 2)
	assert.Equal(t, transport.ReasonUDPBlocked, result.Attempts[0].Reason)
	assert.Equal(t, transport.AttemptSuccess, result.Attempts[1].Result)
	assert.Equal(t, netip.MustParseAddr("198.51.100.8"), result.EgressIP)
}

func Test_TR_Ladder_TCPRefusedExhausts(t *testing.T) {
	t.Parallel()

	runner := newLadderRunner()
	runner.preflightErrs[transport.OpenVPNUDP] = []error{
		transport.NewFailure(transport.ReasonUDPBlocked, errors.New("blocked")),
	}
	runner.preflightErrs[transport.OpenVPNTCP] = []error{
		transport.NewFailure(transport.ReasonTCPRefused,
			errors.New("connection refused")),
	}
	ladder := newTestLadder(t, ladderPolicy(transport.OpenVPNUDP,
		transport.OpenVPNTCP), runner)

	_, err := ladder.Run(t.Context(), transport.Target{
		Hostname: "nl-1234.nordvpn.com",
	})
	require.ErrorIs(t, err, transport.ErrExhausted)
	state := ladder.Snapshot()
	assert.Nil(t, state.Active)
	assert.Equal(t, transport.PhaseIdle, state.Phase)
}

func Test_TR_Ladder_AuthInvalidStopsTransportRetries(t *testing.T) {
	t.Parallel()

	runner := newLadderRunner()
	runner.awaitErrs[transport.OpenVPNUDP] = []error{
		transport.NewFailure(transport.ReasonAuth,
			errors.New("invalid credentials")),
	}
	policy := ladderPolicy(transport.OpenVPNUDP, transport.OpenVPNTCP)
	policy.MaxAttempts = 3
	ladder := newTestLadder(t, policy, runner)

	result, err := ladder.Run(t.Context(), transport.Target{
		Hostname: "nl-1234.nordvpn.com",
	})
	require.NoError(t, err)
	assert.Equal(t, transport.OpenVPNTCP, result.Transport)
	assert.Equal(t, 1, runner.preflightCount(transport.OpenVPNUDP),
		"auth failures must not retry the same transport")
}

func Test_TR_Ladder_TunnelDiesFallsThrough(t *testing.T) {
	t.Parallel()

	runner := newLadderRunner()
	runner.verifyErrs = []error{
		transport.NewFailure(transport.ReasonNoEgress,
			errors.New("tunnel died")),
		nil,
	}
	ladder := newTestLadder(t, ladderPolicy(transport.OpenVPNUDP,
		transport.OpenVPNTCP), runner)

	result, err := ladder.Run(t.Context(), transport.Target{
		Hostname: "nl-1234.nordvpn.com",
	})
	require.NoError(t, err)
	assert.Equal(t, transport.OpenVPNTCP, result.Transport)
	require.Len(t, result.Attempts, 2)
	assert.Equal(t, transport.ReasonNoEgress, result.Attempts[0].Reason)
}

func Test_TR_Ladder_SecondCycleSucceeds(t *testing.T) {
	t.Parallel()

	runner := newLadderRunner()
	runner.preflightErrs[transport.OpenVPNUDP] = []error{
		transport.NewFailure(transport.ReasonUDPBlocked, errors.New("blocked")),
	}
	runner.preflightErrs[transport.OpenVPNTCP] = []error{
		transport.NewFailure(transport.ReasonTCPRefused,
			errors.New("refused")),
	}
	policy := ladderPolicy(transport.OpenVPNUDP, transport.OpenVPNTCP)
	policy.MaxCycles = 2
	ladder := newTestLadder(t, policy, runner)

	result, err := ladder.Run(t.Context(), transport.Target{
		Hostname: "nl-1234.nordvpn.com",
	})
	require.NoError(t, err)
	assert.Equal(t, 2, result.Cycle)
	assert.Equal(t, transport.OpenVPNUDP, result.Transport)
}

func Test_TR_Ladder_BreakerResetRecovers(t *testing.T) {
	t.Parallel()

	runner := newLadderRunner()
	runner.preflightErrs[transport.OpenVPNUDP] = []error{
		transport.NewFailure(transport.ReasonUDPBlocked, errors.New("blocked")),
	}
	runner.preflightErrs[transport.OpenVPNTCP] = []error{
		transport.NewFailure(transport.ReasonTCPRefused, errors.New("refused")),
	}
	policy := ladderPolicy(transport.OpenVPNUDP, transport.OpenVPNTCP)
	policy.BreakerThreshold = 1
	ladder := newTestLadder(t, policy, runner)

	_, err := ladder.Run(t.Context(), transport.Target{
		Hostname: "nl-1234.nordvpn.com",
	})
	require.ErrorIs(t, err, transport.ErrExhausted)
	state := ladder.Snapshot()
	require.Equal(t, transport.BreakerOpen, state.Breakers[transport.OpenVPNUDP].State)
	require.Equal(t, transport.BreakerOpen, state.Breakers[transport.OpenVPNTCP].State)

	_, err = ladder.Run(t.Context(), transport.Target{
		Hostname: "nl-1234.nordvpn.com",
	})
	require.ErrorIs(t, err, transport.ErrExhausted)
	skipped := ladder.Snapshot()
	require.NotEmpty(t, skipped.Attempts)
	for _, attempt := range skipped.Attempts {
		assert.Equal(t, transport.AttemptSkipped, attempt.Result)
		assert.Equal(t, transport.ReasonBreakerOpen, attempt.Reason)
	}

	require.NoError(t, ladder.Reset(nil))
	reset := ladder.Snapshot()
	for name, breaker := range reset.Breakers {
		assert.Equal(t, transport.BreakerClosed, breaker.State,
			"breaker %s should be closed", name)
	}

	result, err := ladder.Run(t.Context(), transport.Target{
		Hostname: "nl-1234.nordvpn.com",
	})
	require.NoError(t, err)
	assert.Equal(t, transport.OpenVPNUDP, result.Transport)
}
