package settings

import (
	"testing"
	"time"

	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gosettings/reader/sources/env"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TransportLadder_SetDefaults(t *testing.T) {
	t.Parallel()

	var settings TransportLadder
	settings.setDefaults()

	assert.Equal(t, ptrTo(true), settings.Enabled)
	assert.Equal(t, []string{"wireguard", "openvpn-udp", "openvpn-tcp"},
		settings.Ladder)
	assert.Equal(t, 30*time.Second, settings.AttemptTimeout)
	assert.Equal(t, 45*time.Second, settings.AttemptTimeoutTCP)
	assert.Equal(t, 2, settings.MaxAttempts)
	assert.Equal(t, 3, settings.BreakerThreshold)
	assert.Equal(t, 120*time.Second, settings.BreakerCooldown)
	assert.Equal(t, 900*time.Second, settings.BreakerCooldownMax)
	assert.Equal(t, 30*time.Second, settings.BackoffBase)
	assert.Equal(t, 300*time.Second, settings.BackoffMax)
	assert.Equal(t, 3, settings.MaxCycles)
	assert.InDelta(t, 0.2, settings.Jitter, 0.0001)
	assert.Equal(t, 3, settings.LocalReconnectMax)
}

func Test_TransportLadder_Validate(t *testing.T) {
	t.Parallel()

	defaults := func() TransportLadder {
		var settings TransportLadder
		settings.setDefaults()
		return settings
	}

	testCases := map[string]struct {
		settings TransportLadder
		err      string
	}{
		"defaults": {
			settings: defaults(),
		},
		"disabled skips validation": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.Enabled = ptrTo(false)
				settings.Ladder = nil
				settings.AttemptTimeout = 0
				return settings
			}(),
		},
		"empty ladder": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.Ladder = nil
				return settings
			}(),
			err: "ladder is empty",
		},
		"unknown transport": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.Ladder = []string{"wireguard", "pptp"}
				return settings
			}(),
			err: "transport 2: value is not one of the possible choices",
		},
		"zero attempt timeout": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.AttemptTimeout = 0
				return settings
			}(),
			err: "attempt timeout must be positive",
		},
		"zero TCP attempt timeout": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.AttemptTimeoutTCP = 0
				return settings
			}(),
			err: "TCP attempt timeout must be positive",
		},
		"no attempt": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.MaxAttempts = 0
				return settings
			}(),
			err: "maximum attempts must be at least 1",
		},
		"breaker threshold below one": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.BreakerThreshold = 0
				return settings
			}(),
			err: "breaker threshold must be at least 1",
		},
		"negative breaker cooldown": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.BreakerCooldown = -time.Second
				return settings
			}(),
			err: "breaker cooldown must not be negative",
		},
		"breaker cooldown maximum below cooldown": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.BreakerCooldownMax = time.Minute
				return settings
			}(),
			err: "is less than cooldown",
		},
		"negative backoff base": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.BackoffBase = -time.Second
				return settings
			}(),
			err: "backoff base must not be negative",
		},
		"backoff maximum below base": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.BackoffMax = time.Second
				return settings
			}(),
			err: "is less than base",
		},
		"no cycle": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.MaxCycles = 0
				return settings
			}(),
			err: "maximum cycles must be at least 1",
		},
		"negative jitter": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.Jitter = -0.1
				return settings
			}(),
			err: "jitter must not be negative",
		},
		"jitter above one": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.Jitter = 1.1
				return settings
			}(),
			err: "jitter must not be above 1",
		},
		"no local reconnect": {
			settings: func() TransportLadder {
				settings := defaults()
				settings.LocalReconnectMax = 0
				return settings
			}(),
			err: "local reconnect maximum must be at least 1",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			err := testCase.settings.validate()

			if testCase.err == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorContains(t, err, testCase.err)
		})
	}
}

func Test_TransportLadder_Read(t *testing.T) {
	t.Parallel()

	environ := []string{
		"TRANSPORT_ENABLED=off",
		"TRANSPORT_LADDER=openvpn-tcp,wireguard",
		"TRANSPORT_ATTEMPT_TIMEOUT_S=20",
		"TRANSPORT_ATTEMPT_TIMEOUT_TCP_S=50",
		"TRANSPORT_MAX_ATTEMPTS=4",
		"TRANSPORT_BREAKER_THRESHOLD=5",
		"TRANSPORT_BREAKER_COOLDOWN_S=60",
		"TRANSPORT_BREAKER_COOLDOWN_MAX_S=600",
		"TRANSPORT_BACKOFF_BASE_S=10",
		"TRANSPORT_BACKOFF_MAX_S=120",
		"TRANSPORT_MAX_CYCLES=4",
		"TRANSPORT_JITTER=0.35",
		"TRANSPORT_LOCAL_RECONNECT_MAX=5",
	}
	settingsReader := reader.New(reader.Settings{
		Sources: []reader.Source{
			env.New(env.Settings{Environ: environ}),
		},
	})

	var settings TransportLadder
	err := settings.read(settingsReader)
	require.NoError(t, err)
	settings.setDefaults()

	assert.Equal(t, ptrTo(false), settings.Enabled)
	assert.Equal(t, []string{"openvpn-tcp", "wireguard"}, settings.Ladder)
	assert.Equal(t, 20*time.Second, settings.AttemptTimeout)
	assert.Equal(t, 50*time.Second, settings.AttemptTimeoutTCP)
	assert.Equal(t, 4, settings.MaxAttempts)
	assert.Equal(t, 5, settings.BreakerThreshold)
	assert.Equal(t, time.Minute, settings.BreakerCooldown)
	assert.Equal(t, 10*time.Minute, settings.BreakerCooldownMax)
	assert.Equal(t, 10*time.Second, settings.BackoffBase)
	assert.Equal(t, 2*time.Minute, settings.BackoffMax)
	assert.Equal(t, 4, settings.MaxCycles)
	assert.InDelta(t, 0.35, settings.Jitter, 0.0001)
	assert.Equal(t, 5, settings.LocalReconnectMax)
}
