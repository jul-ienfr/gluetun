package metrics

import (
	"io"
	"testing"

	promclient "github.com/prometheus/client_golang/prometheus"
	"github.com/qdm12/gluetun/internal/configuration/settings"
	metricsprometheus "github.com/qdm12/gluetun/internal/metrics/prometheus"
	"github.com/qdm12/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_New(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		settings settings.Metrics
		expected string
	}{
		"noop_type": {
			settings: settings.Metrics{
				Type: "noop",
			},
			expected: "noop metrics service",
		},
		"prometheus_type": {
			settings: settings.Metrics{
				Type: "prometheus",
				Prometheus: settings.Prometheus{
					ListeningAddress: "127.0.0.1:0",
				},
			},
			expected: "prometheus http server",
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service, err := New(testCase.settings, log.New(),
				NewMockVPNLooper(nil), NewMockLinkLister(nil))
			assert.NoError(t, err)
			assert.Equal(t, testCase.expected, service.String())
		})
	}
}

func Test_New_UnknownTypePanics(t *testing.T) {
	t.Parallel()

	assert.PanicsWithValue(t, "unknown metrics type: unknown", func() {
		_, _ = New(settings.Metrics{Type: "unknown"}, log.New(),
			NewMockVPNLooper(nil), NewMockLinkLister(nil))
	})
}

func Test_newGatherer(t *testing.T) {
	t.Parallel()

	registry := promclient.NewRegistry()
	counter := promclient.NewCounter(promclient.CounterOpts{
		Name: "gluetun_tunnel_up",
		Help: "Tunnel up gauge.",
	})
	registry.MustRegister(counter)
	counter.Inc()

	extra := metricsprometheus.NewTextGatherer(func(w io.Writer) error {
		_, err := io.WriteString(w,
			"gluetun_control_jobs_total{kind=\"switch\",state=\"committed\"} 3\n")
		return err
	})

	families, err := newGatherer(registry, extra).Gather()
	require.NoError(t, err)

	names := make([]string, 0, len(families))
	for _, family := range families {
		names = append(names, family.GetName())
	}
	assert.ElementsMatch(t,
		[]string{"gluetun_tunnel_up", "gluetun_control_jobs_total"}, names)
}

func Test_newGatherer_NoExtra(t *testing.T) {
	t.Parallel()

	registry := promclient.NewRegistry()
	gatherer := newGatherer(registry)
	assert.Equal(t, promclient.Gatherer(registry), gatherer)
}
