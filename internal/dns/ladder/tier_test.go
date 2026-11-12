package ladder

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TierType_Valid(t *testing.T) {
	t.Parallel()

	assert.True(t, TierDoT.Valid())
	assert.True(t, TierDoH.Valid())
	assert.True(t, TierPlain.Valid())
	assert.False(t, TierType("unknown").Valid())
}

func Test_State(t *testing.T) {
	t.Parallel()

	testCases := map[State]struct {
		valid   bool
		serving bool
	}{
		StateUp:       {valid: true, serving: true},
		StateDegraded: {valid: true, serving: true},
		StateDown:     {valid: true, serving: false},
		StateStandby:  {valid: true, serving: false},
		State("nope"): {valid: false, serving: false},
	}

	for state, expected := range testCases {
		assert.Equal(t, expected.valid, state.Valid(), state)
		assert.Equal(t, expected.serving, state.Serving(), state)
	}
}

func Test_NewTier(t *testing.T) {
	t.Parallel()

	tier := NewTier(TierDoT, "127.0.0.1:53", nil)
	assert.Equal(t, TierDoT, tier.Type)
	assert.Equal(t, StateStandby, tier.State)
	assert.Equal(t, "127.0.0.1:53", tier.Listener)
	assert.NotNil(t, tier.Endpoints)
	assert.Empty(t, tier.Endpoints)

	tier.AddEndpoint(NewEndpoint("1.1.1.1:853", "cloudflare"))
	require.Len(t, tier.Endpoints, 1)
	assert.Equal(t, "1.1.1.1:853", tier.Endpoints[0].Address)
}

func Test_Tier_Available(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	cooldown := now.Add(time.Minute)
	expired := now.Add(-time.Minute)

	testCases := map[string]struct {
		state     State
		cooldown  *time.Time
		available bool
	}{
		"up":              {state: StateUp, available: true},
		"degraded":        {state: StateDegraded, available: false},
		"down":            {state: StateDown, available: false},
		"standby":         {state: StateStandby, available: false},
		"up cooling":      {state: StateUp, cooldown: &cooldown, available: false},
		"up past cooling": {state: StateUp, cooldown: &expired, available: true},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tier := Tier{State: testCase.state, CooldownUntil: testCase.cooldown}
			assert.Equal(t, testCase.available, tier.Available(now))
		})
	}
}

func Test_Endpoint_Available(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	cooldown := now.Add(time.Minute)

	testCases := map[string]struct {
		state     State
		cooldown  *time.Time
		available bool
	}{
		"up":         {state: StateUp, available: true},
		"degraded":   {state: StateDegraded, available: true},
		"down":       {state: StateDown, available: false},
		"standby":    {state: StateStandby, available: false},
		"up cooling": {state: StateUp, cooldown: &cooldown, available: false},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			endpoint := Endpoint{
				State:         testCase.state,
				CooldownUntil: testCase.cooldown,
			}
			assert.Equal(t, testCase.available, endpoint.Available(now))
		})
	}
}

func Test_Tier_AvailableEndpoints(t *testing.T) {
	t.Parallel()

	tier := NewTier(TierDoT, "", []Endpoint{
		{State: StateUp},
		{State: StateDown},
		{State: StateDegraded},
		{State: StateUp},
	})

	assert.Equal(t, 3, tier.AvailableEndpoints(time.Now()))
}

func Test_EWMA(t *testing.T) {
	t.Parallel()

	assert.Equal(t, int64(40), EWMA(0, 40*time.Millisecond, 0.2))
	assert.Equal(t, int64(42), EWMA(40, 50*time.Millisecond, 0.2))
	assert.Equal(t, int64(50), EWMA(0, 50*time.Millisecond, 0))
	assert.Equal(t, int64(0), EWMA(0, -time.Second, 0.2))
}

func Test_Tier_JSON(t *testing.T) {
	t.Parallel()

	tier := NewTier(TierDoT, "127.0.0.1:53", []Endpoint{
		NewEndpoint("1.1.1.1:853", "cloudflare"),
	})
	tier.State = StateUp

	encoded, err := json.Marshal(tier)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(encoded, &decoded))
	assert.Equal(t, "dot", decoded["type"])
	assert.Equal(t, "up", decoded["state"])
	assert.Equal(t, "127.0.0.1:53", decoded["listener"])
	assert.Contains(t, decoded, "cooldown_until")
	assert.Contains(t, decoded, "last_error")

	endpoints, ok := decoded["endpoints"].([]any)
	require.True(t, ok)
	require.Len(t, endpoints, 1)
	endpoint := endpoints[0].(map[string]any)
	assert.Equal(t, "1.1.1.1:853", endpoint["address"])
	assert.Equal(t, "cloudflare", endpoint["provider"])
	assert.Equal(t, "up", endpoint["state"])

	var roundTripped Tier
	require.NoError(t, json.Unmarshal(encoded, &roundTripped))
	assert.Equal(t, tier.Type, roundTripped.Type)
	assert.Equal(t, tier.State, roundTripped.State)
	require.Len(t, roundTripped.Endpoints, 1)
	assert.Equal(t, tier.Endpoints[0].Address,
		roundTripped.Endpoints[0].Address)
}
