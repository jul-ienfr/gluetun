package api

import (
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
)

func Test_NewCapabilities(t *testing.T) {
	t.Parallel()

	control := settings.Control{
		StateMode: "merge",
		Egress: settings.Egress{
			Quorum:     2,
			MinSources: 4,
			CacheTTL:   15 * time.Second,
		},
		DNS: settings.DNSLadder{
			Ladder: []string{"dot", "doh", "plain"},
		},
	}

	capabilities := NewCapabilities(control,
		models.BuildInformation{Version: "v3.41.3"}, "vpn-gluetun-3")

	assert.Equal(t, ControlPlaneVersion, capabilities.ControlPlaneVersion)
	assert.Equal(t, "v3.41.3", capabilities.UpstreamVersion)
	assert.Equal(t, "vpn-gluetun-3", capabilities.StationID)
	assert.Equal(t, "merge", capabilities.StateMode)
	assert.Equal(t, []string{"dot", "doh", "plain"}, capabilities.DNSDefaultLadder)
	assert.Equal(t, DefaultTransportLadder, capabilities.TransportDefault)
	assert.Equal(t, uint(2), capabilities.Limits.Quorum)
	assert.Equal(t, uint(4), capabilities.Limits.MinSources)
	assert.InDelta(t, 15.0, capabilities.Limits.EgressCacheTTLS, 0.001)
	assert.Equal(t, 30, capabilities.Limits.TransportAttemptTimeout["wireguard"])
	assert.Equal(t, 45, capabilities.Limits.TransportAttemptTimeout["openvpn-tcp"])

	// Only implemented features are advertised.
	assert.True(t, capabilities.Features.Switch)
	assert.True(t, capabilities.Features.Rotate)
	assert.True(t, capabilities.Features.Rollback)
	assert.True(t, capabilities.Features.DryRun)
	assert.True(t, capabilities.Features.Drain)
	assert.True(t, capabilities.Features.EgressConsensus)
	assert.False(t, capabilities.Features.TransportLadder)
}

func Test_NewCapabilities_EgressDisabled(t *testing.T) {
	t.Parallel()

	disabled := false
	capabilities := NewCapabilities(settings.Control{
		Egress: settings.Egress{Enabled: &disabled},
	}, models.BuildInformation{}, "")

	assert.False(t, capabilities.Features.EgressConsensus)
}

func Test_NewCapabilities_DefaultStateMode(t *testing.T) {
	t.Parallel()

	capabilities := NewCapabilities(settings.Control{},
		models.BuildInformation{}, "")

	assert.Equal(t, "state", capabilities.StateMode)
}

func Test_Handler_CapabilitiesEffective(t *testing.T) {
	t.Parallel()

	handler := New(settings.Control{}, models.BuildInformation{}, "station",
		nil, nil)

	empty := handler.capabilities()
	assert.False(t, empty.Features.Switch)
	assert.False(t, empty.Features.Rotate)
	assert.False(t, empty.Features.DNSLadder)
	assert.False(t, empty.Features.TransportLadder)
	assert.False(t, empty.Features.EgressConsensus)

	handler.jobs = fakeJobs{}
	handler.dns = &fakeDNS{}
	handler.transport = &fakeTransport{}
	handler.egress = fakeEgress{}

	full := handler.capabilities()
	assert.True(t, full.Features.Switch)
	assert.True(t, full.Features.Rotate)
	assert.True(t, full.Features.Rollback)
	assert.True(t, full.Features.DNSLadder)
	assert.True(t, full.Features.TransportLadder)
	assert.True(t, full.Features.EgressConsensus)
}
