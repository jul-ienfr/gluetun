package observability

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_MetricsSnapshotEmpty(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	assert.Empty(t, metrics.Snapshot())
}

func Test_MetricsIncRequest(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	metrics.IncRequest("GET", "/v1/vpn/state", 200)
	metrics.IncRequest("GET", "/v1/vpn/state", 200)
	metrics.IncRequest("GET", "/v1/vpn/state", 500)
	metrics.IncRequest("POST", "/v1/vpn/switch", 202)

	snapshots := metrics.Snapshot()
	require.Len(t, snapshots, 3)

	assert.Equal(t, RouteSnapshot{
		Method:   "GET",
		Path:     "/v1/vpn/state",
		Status:   200,
		Requests: 2,
	}, snapshots[0])
	assert.Equal(t, RouteSnapshot{
		Method:   "GET",
		Path:     "/v1/vpn/state",
		Status:   500,
		Requests: 1,
	}, snapshots[1])
	assert.Equal(t, RouteSnapshot{
		Method:   "POST",
		Path:     "/v1/vpn/switch",
		Status:   202,
		Requests: 1,
	}, snapshots[2])
}

func Test_MetricsObserveLatency(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	metrics.IncRequest("GET", "/v1/vpn/state", 200)
	metrics.ObserveLatency("GET", "/v1/vpn/state", 10*time.Millisecond)
	metrics.ObserveLatency("GET", "/v1/vpn/state", 30*time.Millisecond)
	metrics.ObserveLatency("GET", "/v1/vpn/state", 20*time.Millisecond)

	snapshots := metrics.Snapshot()
	require.Len(t, snapshots, 1)
	snapshot := snapshots[0]

	assert.Equal(t, uint64(3), snapshot.LatencyCount)
	assert.InDelta(t, 60, snapshot.LatencySumMS, 0.001)
	assert.InDelta(t, 10, snapshot.LatencyMinMS, 0.001)
	assert.InDelta(t, 30, snapshot.LatencyMaxMS, 0.001)
}

func Test_MetricsLatencyWithoutRequests(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	metrics.ObserveLatency("GET", "/v1/control/capabilities", time.Millisecond)

	// Latency is only exposed alongside a request counter.
	assert.Empty(t, metrics.Snapshot())
}

func Test_MetricsSnapshotIsACopy(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	metrics.IncRequest("GET", "/v1/vpn/state", 200)

	first := metrics.Snapshot()
	first[0].Requests = 99

	second := metrics.Snapshot()
	require.Len(t, second, 1)
	assert.Equal(t, uint64(1), second[0].Requests)
}

func Test_MetricsWritePrometheus(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	metrics.IncRequest("GET", "/v1/vpn/state", 200)
	metrics.ObserveLatency("GET", "/v1/vpn/state", 12*time.Millisecond)

	var builder strings.Builder
	err := metrics.WritePrometheus(&builder)
	require.NoError(t, err)

	output := builder.String()
	assert.Contains(t, output,
		`gluetun_control_requests_total{method="GET",path="/v1/vpn/state",status="200"} 1`)
	assert.Contains(t, output,
		`gluetun_control_request_duration_seconds_count{method="GET",path="/v1/vpn/state",status="200"} 1`)
	assert.Contains(t, output,
		`gluetun_control_request_duration_seconds_sum{method="GET",path="/v1/vpn/state",status="200"} 0.012`)
	assert.Contains(t, output,
		`gluetun_control_request_duration_seconds_min{method="GET",path="/v1/vpn/state",status="200"} 0.012`)
	assert.Contains(t, output,
		`gluetun_control_request_duration_seconds_max{method="GET",path="/v1/vpn/state",status="200"} 0.012`)
}

func Test_MetricsWritePrometheusWithoutLatency(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	metrics.IncRequest("GET", "/v1/vpn/state", 200)

	var builder strings.Builder
	err := metrics.WritePrometheus(&builder)
	require.NoError(t, err)

	output := builder.String()
	assert.Contains(t, output, "gluetun_control_requests_total{")
	assert.NotContains(t, output, "duration_seconds")
}

type failingWriter struct{}

var errWrite = errors.New("write failure")

func (failingWriter) Write([]byte) (int, error) {
	return 0, errWrite
}

func Test_MetricsWritePrometheusError(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	metrics.IncRequest("GET", "/v1/vpn/state", 200)

	err := metrics.WritePrometheus(failingWriter{})
	require.ErrorIs(t, err, errWrite)
}

func Test_MetricsObserveEgressVerification(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	canaryOK := egress.CanaryResult{OK: true}
	metrics.ObserveEgressVerification(egress.Verification{
		Verified:   true,
		IP:         netip.MustParseAddr("203.0.113.7"),
		Quorum:     2,
		Dissenters: []string{"dns:whoami"},
		Canary:     &canaryOK,
		Observations: []egress.Observation{
			{Source: "http:ipify", Accepted: true, LatencyMS: 120},
			{
				Source:    "dns:whoami",
				LatencyMS: 80,
				Error:     &egress.SourceError{Reason: egress.ReasonBanned},
			},
		},
	})

	noQuorum := egress.ReasonNoQuorum
	canaryFailed := egress.CanaryResult{OK: false}
	metrics.ObserveEgressVerification(egress.Verification{
		Reason:     &noQuorum,
		Cached:     true,
		Canary:     &canaryFailed,
		Quorum:     1,
		Dissenters: []string{"http:ipify", "dns:whoami"},
	})

	var builder strings.Builder
	err := metrics.WritePrometheus(&builder)
	require.NoError(t, err)

	output := builder.String()
	expectedLines := []string{
		`gluetun_egress_verifications_total{result="verified"} 1`,
		`gluetun_egress_verifications_total{result="no_quorum"} 1`,
		`gluetun_egress_source_requests_total{source="dns:whoami",result="banned"} 1`,
		`gluetun_egress_source_requests_total{source="http:ipify",result="accepted"} 1`,
		`gluetun_egress_source_latency_seconds{source="http:ipify"} 0.12`,
		`gluetun_egress_source_latency_seconds{source="dns:whoami"} 0.08`,
		`gluetun_egress_source_banned{source="http:ipify"} 0`,
		`gluetun_egress_source_banned{source="dns:whoami"} 1`,
		"gluetun_egress_quorum 1",
		"gluetun_egress_dissenters 2",
		"gluetun_egress_canary_ok 0",
		"gluetun_egress_cache_hits_total 1",
	}
	for _, line := range expectedLines {
		assert.Contains(t, output, line)
	}
}

func Test_MetricsEgressPrometheusWithoutObservation(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()

	var builder strings.Builder
	err := metrics.WritePrometheus(&builder)
	require.NoError(t, err)

	output := builder.String()
	assert.NotContains(t, output, "gluetun_egress_verifications_total")
	assert.NotContains(t, output, "gluetun_egress_canary_ok")
	assert.Contains(t, output, "gluetun_egress_quorum 0")
	assert.Contains(t, output, "gluetun_egress_cache_hits_total 0")
}

func Test_MetricsConcurrentAccess(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	var waitGroup sync.WaitGroup
	const goroutines = 20

	for range goroutines {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			metrics.IncRequest("GET", "/v1/vpn/state", 200)
			metrics.ObserveLatency("GET", "/v1/vpn/state", time.Millisecond)
			_ = metrics.Snapshot()
		}()
	}
	waitGroup.Wait()

	snapshots := metrics.Snapshot()
	require.Len(t, snapshots, 1)
	assert.Equal(t, uint64(goroutines), snapshots[0].Requests)
	assert.Equal(t, uint64(goroutines), snapshots[0].LatencyCount)
}
