package transport

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeIntegrationDriver struct {
	mutex    sync.Mutex
	applies  int
	verifies int
	health   Health
}

func (d *fakeIntegrationDriver) Preflight(_ context.Context,
	_ Transport, _ Target,
) error {
	return nil
}

func (d *fakeIntegrationDriver) Teardown(_ context.Context) error {
	return nil
}

func (d *fakeIntegrationDriver) Apply(_ context.Context,
	_ Transport, _ Target,
) error {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.applies++
	return nil
}

func (d *fakeIntegrationDriver) AwaitTunnel(_ context.Context,
	_ Transport, _ Target,
) error {
	return nil
}

func (d *fakeIntegrationDriver) VerifyEgress(_ context.Context) (netip.Addr, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	d.verifies++
	return netip.MustParseAddr("198.51.100.7"), nil
}

func (d *fakeIntegrationDriver) Health(_ context.Context,
	_ Transport, _ Target,
) (Health, error) {
	d.mutex.Lock()
	defer d.mutex.Unlock()
	return d.health, nil
}

func (d *fakeIntegrationDriver) Reconnect(_ context.Context,
	_ Transport, _ Target,
) error {
	return nil
}

func Test_Integration_Run(t *testing.T) {
	t.Parallel()

	driver := &fakeIntegrationDriver{
		health: Health{
			InterfaceUp:  true,
			HandshakeAt:  time.Now(),
			Status:       "running",
			DNSReachable: true,
		},
	}
	integration, err := NewIntegration(IntegrationSettings{
		Policy: Policy{
			Ladder:    []Transport{WireGuard},
			MaxCycles: 1,
		},
		Driver: driver,
	})
	require.NoError(t, err)
	require.NotNil(t, integration.Service())
	assert.Equal(t, "wireguard", integration.Policy().String())

	var events []Event
	integration.SetEventSink(func(event Event) {
		events = append(events, event)
	})

	ctx, cancel := context.WithCancel(t.Context())
	commits := 0
	result, err := integration.Run(ctx, Target{Hostname: "server.example.com"},
		func(Result) {
			commits++
			cancel()
		})
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, commits)
	assert.Equal(t, WireGuard, result.Transport)
	assert.Equal(t, netip.MustParseAddr("198.51.100.7"), result.EgressIP)

	driver.mutex.Lock()
	assert.Equal(t, 1, driver.applies)
	assert.Equal(t, 1, driver.verifies)
	driver.mutex.Unlock()

	state, available := integration.Service().TransportState()
	require.True(t, available)
	assert.Equal(t, PhaseCommitted, state.Phase)
	require.NotNil(t, state.Active)
	assert.Equal(t, WireGuard, *state.Active)

	var connected int
	for _, event := range events {
		if event.Type == EventConnected {
			connected++
		}
	}
	assert.Equal(t, 1, connected)
}
