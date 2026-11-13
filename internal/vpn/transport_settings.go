package vpn

import (
	"errors"
	"fmt"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	transportpkg "github.com/qdm12/gluetun/internal/vpn/transport"
)

// SetEgressVerifier attaches the egress verification service used by the
// transport ladder. It must be called before the loop starts.
func (l *Loop) SetEgressVerifier(verifier egressVerifier) {
	l.egress = verifier
}

// SetTransportLadder builds and attaches the runtime transport ladder. It is a
// no-op when the ladder is disabled. The ladder requires egress verification
// because a transport is only committed after its egress is proven.
func (l *Loop) SetTransportLadder(settings settings.TransportLadder) error {
	if !transportpkg.Enabled(settings) {
		return nil
	}
	if l.egress == nil {
		return errors.New("transport ladder requires egress verification")
	}

	policy, warnings, err := transportpkg.PolicyFromSettings(settings)
	if err != nil {
		return fmt.Errorf("building transport policy: %w", err)
	}
	for _, warning := range warnings {
		l.logger.Warn(warning)
	}

	metrics := transportpkg.NewMetrics()
	driver := newLadderDriver(l, l.state.GetSettings())
	integration, err := transportpkg.NewIntegration(transportpkg.IntegrationSettings{
		Policy:  policy,
		Driver:  driver,
		Metrics: metrics,
		Watchdog: transportpkg.WatchdogSettings{
			MaxReconnects: settings.LocalReconnectMax,
		},
	})
	if err != nil {
		return fmt.Errorf("building transport ladder: %w", err)
	}

	l.transport = integration
	l.transportDrv = driver
	l.transMetrics = metrics
	return nil
}

// TransportService exposes the transport ladder surface for the control API.
func (l *Loop) TransportService() *transportpkg.Service {
	if l.transport == nil {
		return nil
	}
	return l.transport.Service()
}

// TransportMetrics exposes the transport ladder metrics for Prometheus.
func (l *Loop) TransportMetrics() *transportpkg.Metrics {
	return l.transMetrics
}
