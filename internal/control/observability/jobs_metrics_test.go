package observability

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_MetricsObserveJob(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	metrics.ObserveJob(JobObservation{
		Kind:     "switch",
		State:    "committed",
		Duration: 5 * time.Second,
		PhaseDurations: map[string]time.Duration{
			"preflight": 250 * time.Millisecond,
			"applying":  4 * time.Second,
		},
		AttemptResults: []string{"committed"},
	})
	metrics.ObserveJob(JobObservation{
		Kind:           "rotate",
		State:          "exhausted",
		Duration:       12 * time.Second,
		PhaseDurations: map[string]time.Duration{"preflight": 500 * time.Millisecond},
		AttemptResults: []string{"rejected", "rejected", "skipped"},
	})

	var builder strings.Builder
	err := metrics.WritePrometheus(&builder)
	require.NoError(t, err)

	output := builder.String()
	expectedLines := []string{
		`gluetun_control_jobs_total{kind="rotate",state="exhausted"} 1`,
		`gluetun_control_jobs_total{kind="switch",state="committed"} 1`,
		`gluetun_control_job_duration_seconds_count{kind="switch"} 1`,
		`gluetun_control_job_duration_seconds_sum{kind="switch"} 5`,
		`gluetun_control_job_duration_seconds_min{kind="switch"} 5`,
		`gluetun_control_job_duration_seconds_max{kind="switch"} 5`,
		`gluetun_control_job_duration_seconds_sum{kind="rotate"} 12`,
		`gluetun_control_job_phase_duration_seconds_count{phase="applying"} 1`,
		`gluetun_control_job_phase_duration_seconds_total{phase="applying"} 4`,
		`gluetun_control_job_phase_duration_seconds_count{phase="preflight"} 2`,
		`gluetun_control_job_phase_duration_seconds_total{phase="preflight"} 0.75`,
		`gluetun_control_job_attempts_total{kind="rotate",result="rejected"} 2`,
		`gluetun_control_job_attempts_total{kind="rotate",result="skipped"} 1`,
		`gluetun_control_job_attempts_total{kind="switch",result="committed"} 1`,
	}
	for _, line := range expectedLines {
		assert.Contains(t, output, line)
	}
}

func Test_MetricsJobLabelsAreBounded(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	metrics.ObserveJob(JobObservation{
		Kind:     "job-01J9Z3K4T5",
		State:    "hostname.example.com",
		Duration: time.Second,
		PhaseDurations: map[string]time.Duration{
			"hostname.example.com": time.Second,
		},
		AttemptResults: []string{"job-01J9Z3K4T5"},
	})

	var builder strings.Builder
	err := metrics.WritePrometheus(&builder)
	require.NoError(t, err)

	output := builder.String()
	assert.Contains(t,
		output, `gluetun_control_jobs_total{kind="other",state="other"} 1`)
	assert.Contains(t,
		output, `gluetun_control_job_phase_duration_seconds_count{phase="other"} 1`)
	assert.Contains(t,
		output, `gluetun_control_job_attempts_total{kind="other",result="other"} 1`)
	assert.NotContains(t, output, "job-01J9Z3K4T5")
	assert.NotContains(t, output, "hostname.example.com")
}

func Test_MetricsJobWithoutObservation(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()

	var builder strings.Builder
	err := metrics.WritePrometheus(&builder)
	require.NoError(t, err)

	output := builder.String()
	assert.NotContains(t, output, "gluetun_control_jobs_total")
	assert.NotContains(t, output, "gluetun_control_job_duration_seconds")
	assert.NotContains(t, output, "gluetun_control_job_phase_duration_seconds")
	assert.NotContains(t, output, "gluetun_control_job_attempts_total")
}

func Test_MetricsJobConcurrentAccess(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	var waitGroup sync.WaitGroup
	const goroutines = 20

	for range goroutines {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			metrics.ObserveJob(JobObservation{
				Kind:     "switch",
				State:    "committed",
				Duration: time.Second,
			})
		}()
	}
	waitGroup.Wait()

	var builder strings.Builder
	err := metrics.WritePrometheus(&builder)
	require.NoError(t, err)
	assert.Contains(t, builder.String(),
		`gluetun_control_jobs_total{kind="switch",state="committed"} 20`)
}
