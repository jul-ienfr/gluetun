package events

import (
	"net/netip"
	"testing"
	"time"

	transportpkg "github.com/qdm12/gluetun/internal/vpn/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewTransportSink(t *testing.T) {
	t.Parallel()

	bus := newTestBus(Options{})
	sink := NewTransportSink(bus, nil, nil)

	retryAt := fixedTime().Add(time.Minute)
	sink(transportpkg.Event{
		Type:      transportpkg.EventConnected,
		Transport: transportpkg.WireGuard,
		Server:    "server.example.com",
		Attempt:   1,
		Result:    transportpkg.AttemptSuccess,
		Cycle:     1,
		EgressIP:  netip.MustParseAddr("198.51.100.7"),
	})
	sink(transportpkg.Event{
		Type:      transportpkg.EventFailed,
		Transport: transportpkg.OpenVPNTCP,
		Result:    transportpkg.AttemptFailed,
		Reason:    transportpkg.ReasonNoEgress,
		Failures:  2,
		RetryAt:   retryAt,
	})
	sink(transportpkg.Event{})

	page := bus.Recent(0, "", 10)
	require.Len(t, page.Items, 2)

	connected := page.Items[0]
	assert.Equal(t, transportpkg.EventConnected, connected.Type)
	assert.Equal(t, SeverityInfo, connected.Severity)
	assert.Equal(t, "wireguard", connected.Data["transport"])
	assert.Equal(t, "server.example.com", connected.Data["server"])
	assert.Equal(t, 1, connected.Data["attempt"])
	assert.Equal(t, "success", connected.Data["result"])
	assert.Equal(t, 1, connected.Data["cycle"])
	assert.Equal(t, "198.51.100.7", connected.Data["egress_ip"])

	failed := page.Items[1]
	assert.Equal(t, transportpkg.EventFailed, failed.Type)
	assert.Equal(t, SeverityWarning, failed.Severity)
	assert.Equal(t, "openvpn-tcp", failed.Data["transport"])
	assert.Equal(t, "no_egress", failed.Data["reason"])
	assert.Equal(t, 2, failed.Data["failures"])
	assert.Equal(t, retryAt, failed.Data["retry_at"])
}
