package server

import (
	"strings"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/control/jobs"
	"github.com/qdm12/gluetun/internal/control/observability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_observeJob(t *testing.T) {
	t.Parallel()

	started := time.Date(2026, 11, 13, 10, 0, 0, 0, time.UTC)
	finished := started.Add(5 * time.Second)
	job := jobs.Job{
		ID:         "job-1",
		Kind:       jobs.KindRotate,
		State:      jobs.StateCommitted,
		StartedAt:  &started,
		FinishedAt: &finished,
		Timings: jobs.Timings{
			Preflight:       250,
			Applying:        4000,
			VerifyingEgress: 500,
		},
		Attempts: []jobs.Attempt{
			{Hostname: "new.example.com", Result: "rejected"},
			{Hostname: "next.example.com", Result: "committed"},
		},
	}

	metrics := observability.NewMetrics()
	observeJob(metrics, jobs.EventJobCommitted, job)

	var builder strings.Builder
	err := metrics.WritePrometheus(&builder)
	require.NoError(t, err)

	output := builder.String()
	assert.Contains(t,
		output, `gluetun_control_jobs_total{kind="rotate",state="committed"} 1`)
	assert.Contains(t,
		output, `gluetun_control_job_duration_seconds_sum{kind="rotate"} 5`)
	assert.Contains(t,
		output, `gluetun_control_job_phase_duration_seconds_total{phase="applying"} 4`)
	assert.Contains(t,
		output, `gluetun_control_job_attempts_total{kind="rotate",result="rejected"} 1`)
	assert.Contains(t,
		output, `gluetun_control_job_attempts_total{kind="rotate",result="committed"} 1`)
	assert.NotContains(t, output, "job-1")
	assert.NotContains(t, output, "new.example.com")
}

func Test_observeJobIgnoresIntermediateEvents(t *testing.T) {
	t.Parallel()

	metrics := observability.NewMetrics()
	job := jobs.Job{Kind: jobs.KindSwitch, State: jobs.StateApplying}
	observeJob(metrics, jobs.EventDrainTimeout, job)

	var builder strings.Builder
	err := metrics.WritePrometheus(&builder)
	require.NoError(t, err)
	assert.NotContains(t, builder.String(), "gluetun_control_jobs_total")
}
