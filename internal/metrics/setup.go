// Package metrics sets up metrics and creates a metrics service.
package metrics

import (
	"fmt"

	promclient "github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/metrics/noop"
	"github.com/qdm12/gluetun/internal/metrics/prometheus"
	"github.com/qdm12/gluetun/internal/metrics/tunstats"
	"github.com/qdm12/goservices"
	"github.com/qdm12/log"
)

// gathererAdapter exposes the internal Gatherer interface as the Prometheus
// client Gatherer interface so additional collectors can be merged with the
// tunnel stats registry.
type gathererAdapter struct {
	inner prometheus.Gatherer
}

func (a gathererAdapter) Gather() ([]*dto.MetricFamily, error) {
	return a.inner.Gather()
}

// ParentLogger is the interface to create a new logger
// for the metrics service.
type ParentLogger interface {
	New(options ...log.Option) *log.Logger
}

// New creates a new metrics service based on the
// metrics type in the settings. For the Prometheus type,
// it creates the metrics gatherer, on which the metrics
// collectors (such as the tunnel stats) are registered.
//
//nolint:ireturn
func New(settings settings.Metrics, parentLogger ParentLogger,
	vpnLooper tunstats.VPNLooper, linkLister tunstats.LinkLister,
	extraGatherers ...prometheus.Gatherer,
) (service goservices.Service, err error) {
	switch settings.Type {
	case "noop":
		return noop.New()
	case "prometheus":
		registry := promclient.NewRegistry()
		tunLogger := parentLogger.New(log.SetComponent("tunnel stats"))
		err = tunstats.New(registry, vpnLooper, linkLister, tunLogger)
		if err != nil {
			return nil, fmt.Errorf("registering tunnel stats collector: %w", err)
		}
		gatherers := newGatherer(registry, extraGatherers...)
		serverLogger := parentLogger.New(log.SetComponent("prometheus server"))
		return prometheus.New(settings.Prometheus, gatherers, serverLogger)
	default:
		panic("unknown metrics type: " + settings.Type)
	}
}

func newGatherer(registry promclient.Gatherer,
	extraGatherers ...prometheus.Gatherer,
) promclient.Gatherer {
	if len(extraGatherers) == 0 {
		return registry
	}
	gatherers := promclient.Gatherers{registry}
	for _, extra := range extraGatherers {
		if extra == nil {
			continue
		}
		gatherers = append(gatherers, gathererAdapter{inner: extra})
	}
	return gatherers
}
