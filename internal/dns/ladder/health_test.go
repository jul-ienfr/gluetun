package ladder

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestHealth(now *time.Time) *Health {
	return NewHealth(HealthSettings{
		FailuresToDown:     2,
		SuccessesToRecover: 2,
		BaseCooldown:       5 * time.Second,
		MaxCooldown:        time.Minute,
		EWMAAlpha:          0.2,
		Now:                func() time.Time { return *now },
	})
}

func Test_Health_FailureAndRecovery(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	health := newTestHealth(&now)
	tier := NewTier(TierDoT, "", []Endpoint{NewEndpoint("1.1.1.1:853", "cf")})
	cause := errors.New("blocked")

	assert.True(t, health.Failure(&tier, 0, cause))
	assert.Equal(t, StateDegraded, tier.Endpoints[0].State)
	assert.Equal(t, StateDegraded, tier.State)
	assert.Nil(t, tier.CooldownUntil)

	assert.True(t, health.Failure(&tier, 0, cause))
	assert.Equal(t, StateDown, tier.Endpoints[0].State)
	assert.Equal(t, StateDown, tier.State)
	require.NotNil(t, tier.CooldownUntil)
	assert.Equal(t, now.Add(5*time.Second), *tier.CooldownUntil)
	require.NotNil(t, tier.LastError)
	assert.Equal(t, "blocked", *tier.LastError)

	assert.False(t, health.Failure(&tier, 0, cause))
	require.NotNil(t, tier.CooldownUntil)
	assert.Equal(t, now.Add(10*time.Second), *tier.CooldownUntil)

	assert.False(t, health.Success(&tier, 0, 20*time.Millisecond))
	assert.Equal(t, StateDown, tier.State)

	assert.True(t, health.Success(&tier, 0, 20*time.Millisecond))
	assert.Equal(t, StateUp, tier.Endpoints[0].State)
	assert.Equal(t, StateUp, tier.State)
	assert.Nil(t, tier.CooldownUntil)
	assert.Nil(t, tier.LastError)
	assert.Equal(t, uint64(2), tier.Successes)
	assert.Equal(t, uint64(3), tier.Failures)
	assert.Equal(t, int64(20), tier.LatencyEWMAMS)
}

func Test_Health_OneEndpointDoesNotChangeTier(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	health := newTestHealth(&now)

	healthy := NewEndpoint("1.0.0.1:853", "cf")
	healthy.State = StateUp
	failing := NewEndpoint("1.1.1.1:853", "cf")
	failing.State = StateUp
	tier := NewTier(TierDoT, "", []Endpoint{failing, healthy})
	tier.State = StateUp

	assert.False(t, health.Failure(&tier, 0, errors.New("servfail")))
	assert.Equal(t, StateUp, tier.State)
	assert.Equal(t, StateDegraded, tier.Endpoints[0].State)
	assert.Equal(t, StateUp, tier.Endpoints[1].State)

	assert.False(t, health.Failure(&tier, 0, errors.New("servfail")))
	assert.Equal(t, StateUp, tier.State)
	assert.Equal(t, StateDown, tier.Endpoints[0].State)

	assert.False(t, health.Success(&tier, 1, time.Millisecond))
	assert.Equal(t, StateUp, tier.State)
	assert.True(t, tier.Available(now))
}

func Test_Health_CooldownExpiryBecomesDegraded(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	health := newTestHealth(&now)
	tier := NewTier(TierDoT, "", []Endpoint{NewEndpoint("1.1.1.1:853", "cf")})

	health.Failure(&tier, 0, errors.New("blocked"))
	health.Failure(&tier, 0, errors.New("blocked"))
	require.Equal(t, StateDown, tier.State)

	now = now.Add(6 * time.Second)
	health.Refresh(&tier)
	assert.Equal(t, StateDegraded, tier.State)
	assert.Equal(t, StateDegraded, tier.Endpoints[0].State)
	assert.Nil(t, tier.CooldownUntil)
}

func Test_Health_InvalidInputs(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	health := newTestHealth(&now)
	tier := NewTier(TierDoT, "", nil)

	assert.False(t, health.Success(nil, 0, time.Millisecond))
	assert.False(t, health.Failure(nil, 0, errors.New("boom")))
	assert.False(t, health.Success(&tier, 0, time.Millisecond))
	assert.False(t, health.Failure(&tier, -1, errors.New("boom")))

	health.Refresh(nil)
	health.Refresh(&tier)
	assert.Equal(t, StateStandby, tier.State)
}

func Test_Health_BackoffCap(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	health := newTestHealth(&now)
	assert.Equal(t, 5*time.Second, health.backoff(2))
	assert.Equal(t, 10*time.Second, health.backoff(3))
	assert.Equal(t, 40*time.Second, health.backoff(5))
	assert.Equal(t, time.Minute, health.backoff(10))
	assert.Equal(t, time.Minute, health.backoff(1000))
}
