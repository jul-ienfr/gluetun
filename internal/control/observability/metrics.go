package observability

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
)

const millisecondsPerSecond = 1000

type requestMetrics struct {
	method string
	path   string
	status int
	count  uint64
}

type latencyMetrics struct {
	count uint64
	sum   time.Duration
	min   time.Duration
	max   time.Duration
}

type egressSourceMetrics struct {
	results      map[string]uint64
	latencyCount uint64
	latencySum   time.Duration
	banned       bool
}

type jobResultKey struct {
	kind   string
	result string
}

type jobMetrics struct {
	results     map[jobResultKey]uint64
	attempts    map[jobResultKey]uint64
	durations   map[string]*latencyMetrics
	phases      map[string]time.Duration
	phaseCounts map[string]uint64
}

// JobObservation is one terminal job outcome, decoupled from the jobs package
// to keep the observability layer independent.
type JobObservation struct {
	Kind           string
	State          string
	Duration       time.Duration
	PhaseDurations map[string]time.Duration
	AttemptResults []string
}

// Metrics collects control plane route counters, egress counters, job outcomes
// and latency histograms.
type Metrics struct {
	mutex                sync.Mutex
	requests             map[string]*requestMetrics
	latency              map[string]*latencyMetrics
	egressVerifications  map[string]uint64
	egressSources        map[string]*egressSourceMetrics
	egressCacheHits      uint64
	egressQuorum         int
	egressDissenters     int
	egressCanaryOK       int
	egressCanaryObserved bool
	jobs                 *jobMetrics
}

// NewMetrics creates an empty metrics registry.
func NewMetrics() *Metrics {
	return &Metrics{
		requests:            make(map[string]*requestMetrics),
		latency:             make(map[string]*latencyMetrics),
		egressVerifications: make(map[string]uint64),
		egressSources:       make(map[string]*egressSourceMetrics),
		jobs:                newJobMetrics(),
	}
}

func newJobMetrics() *jobMetrics {
	return &jobMetrics{
		results:     make(map[jobResultKey]uint64),
		attempts:    make(map[jobResultKey]uint64),
		durations:   make(map[string]*latencyMetrics),
		phases:      make(map[string]time.Duration),
		phaseCounts: make(map[string]uint64),
	}
}

// IncRequest increments the request counter for a route and status.
func (m *Metrics) IncRequest(method, path string, status int) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := method + " " + path + " " + strconv.Itoa(status)
	metrics, ok := m.requests[key]
	if !ok {
		metrics = &requestMetrics{method: method, path: path, status: status}
		m.requests[key] = metrics
	}
	metrics.count++
}

// ObserveLatency records a request duration for a route.
func (m *Metrics) ObserveLatency(method, path string, duration time.Duration) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	key := method + " " + path
	metrics, ok := m.latency[key]
	if !ok {
		metrics = &latencyMetrics{}
		m.latency[key] = metrics
	}

	if metrics.count == 0 || duration < metrics.min {
		metrics.min = duration
	}
	if duration > metrics.max {
		metrics.max = duration
	}
	metrics.count++
	metrics.sum += duration
}

// ObserveEgressVerification records one egress verification outcome, its
// sources and its canary.
func (m *Metrics) ObserveEgressVerification(verification egress.Verification) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.egressVerifications[egressResult(verification)]++

	for _, observation := range verification.Observations {
		metrics, ok := m.egressSources[observation.Source]
		if !ok {
			metrics = &egressSourceMetrics{results: make(map[string]uint64)}
			m.egressSources[observation.Source] = metrics
		}
		metrics.results[egressObservationResult(observation)]++
		metrics.latencyCount++
		metrics.latencySum += time.Duration(observation.LatencyMS) * time.Millisecond
		if isBannedObservation(observation) {
			metrics.banned = true
		}
	}

	m.egressQuorum = verification.Quorum
	m.egressDissenters = len(verification.Dissenters)
	if verification.Canary != nil {
		m.egressCanaryObserved = true
		m.egressCanaryOK = 0
		if verification.Canary.OK {
			m.egressCanaryOK = 1
		}
	}

	if verification.Cached {
		m.egressCacheHits++
	}
}

// ObserveJob records one terminal job outcome. Labels are restricted to
// bounded enumerations so a stream of jobs cannot grow cardinality without
// limit.
func (m *Metrics) ObserveJob(observation JobObservation) {
	kind := boundedJobKind(observation.Kind)
	result := boundedJobState(observation.State)

	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.jobs == nil {
		m.jobs = newJobMetrics()
	}
	m.jobs.results[jobResultKey{kind: kind, result: result}]++

	if observation.Duration > 0 {
		metrics, ok := m.jobs.durations[kind]
		if !ok {
			metrics = &latencyMetrics{}
			m.jobs.durations[kind] = metrics
		}
		if metrics.count == 0 || observation.Duration < metrics.min {
			metrics.min = observation.Duration
		}
		if observation.Duration > metrics.max {
			metrics.max = observation.Duration
		}
		metrics.count++
		metrics.sum += observation.Duration
	}

	for phase, duration := range observation.PhaseDurations {
		if duration <= 0 {
			continue
		}
		phase = boundedJobPhase(phase)
		m.jobs.phases[phase] += duration
		m.jobs.phaseCounts[phase]++
	}

	for _, attempt := range observation.AttemptResults {
		attemptResult := boundedJobAttemptResult(attempt)
		m.jobs.attempts[jobResultKey{kind: kind, result: attemptResult}]++
	}
}

func boundedJobKind(kind string) string {
	switch kind {
	case "switch", "rotate", "rollback", "recover":
		return kind
	default:
		return "other"
	}
}

func boundedJobState(state string) string {
	switch state {
	case "committed", "rejected", "rolled_back", "failed_degraded",
		"exhausted", "cancelled", "interrupted":
		return state
	default:
		return "other"
	}
}

func boundedJobPhase(phase string) string {
	switch phase {
	case "validating", "preflight", "draining", "applying",
		"awaiting_tunnel", "verifying_egress", "rolling_back":
		return phase
	default:
		return "other"
	}
}

func boundedJobAttemptResult(result string) string {
	switch result {
	case "committed", "rejected", "skipped", "cooldown", "excluded",
		"accepted", "success", "failed":
		return result
	default:
		return "other"
	}
}

func egressResult(verification egress.Verification) string {
	switch {
	case verification.Verified:
		return "verified"
	case verification.Reason == nil:
		return "unverified"
	case *verification.Reason == egress.ReasonInsufficientSources:
		return "insufficient"
	case *verification.Reason == egress.ReasonNoQuorum:
		return "no_quorum"
	case *verification.Reason == egress.ReasonCanaryFailed:
		return "canary_failed"
	default:
		return "unverified"
	}
}

func egressObservationResult(observation egress.Observation) string {
	switch {
	case observation.Error != nil:
		return string(observation.Error.Reason)
	case observation.RejectionReason != nil:
		return string(*observation.RejectionReason)
	case observation.Accepted:
		return "accepted"
	default:
		return "rejected"
	}
}

func isBannedObservation(observation egress.Observation) bool {
	if observation.Error != nil && observation.Error.Reason == egress.ReasonBanned {
		return true
	}
	return observation.RejectionReason != nil &&
		*observation.RejectionReason == egress.ReasonBanned
}

// RouteSnapshot is a point-in-time view of one route.
type RouteSnapshot struct {
	Method       string  `json:"method"`
	Path         string  `json:"path"`
	Status       int     `json:"status"`
	Requests     uint64  `json:"requests"`
	LatencyCount uint64  `json:"latency_count"`
	LatencySumMS float64 `json:"latency_sum_ms"`
	LatencyMinMS float64 `json:"latency_min_ms"`
	LatencyMaxMS float64 `json:"latency_max_ms"`
}

// Snapshot returns a deterministic copy of the collected metrics.
func (m *Metrics) Snapshot() (snapshots []RouteSnapshot) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	snapshots = make([]RouteSnapshot, 0, len(m.requests))
	for _, request := range m.requests {
		snapshot := RouteSnapshot{
			Method:   request.method,
			Path:     request.path,
			Status:   request.status,
			Requests: request.count,
		}
		latency, ok := m.latency[request.method+" "+request.path]
		if ok {
			snapshot.LatencyCount = latency.count
			snapshot.LatencySumMS = durationMS(latency.sum)
			snapshot.LatencyMinMS = durationMS(latency.min)
			snapshot.LatencyMaxMS = durationMS(latency.max)
		}
		snapshots = append(snapshots, snapshot)
	}

	sort.Slice(snapshots, func(i, j int) bool {
		if snapshots[i].Path != snapshots[j].Path {
			return snapshots[i].Path < snapshots[j].Path
		}
		if snapshots[i].Method != snapshots[j].Method {
			return snapshots[i].Method < snapshots[j].Method
		}
		return snapshots[i].Status < snapshots[j].Status
	})

	return snapshots
}

// WritePrometheus writes the metrics in the Prometheus text exposition format.
func (m *Metrics) WritePrometheus(w io.Writer) error {
	for _, snapshot := range m.Snapshot() {
		labels := fmt.Sprintf(`method=%s,path=%s,status=%s`,
			strconv.Quote(snapshot.Method),
			strconv.Quote(snapshot.Path),
			strconv.Quote(strconv.Itoa(snapshot.Status)))

		_, err := fmt.Fprintf(w, "gluetun_control_requests_total{%s} %d\n",
			labels, snapshot.Requests)
		if err != nil {
			return err
		}

		if snapshot.LatencyCount == 0 {
			continue
		}

		_, err = fmt.Fprintf(w,
			"gluetun_control_request_duration_seconds_count{%s} %d\n",
			labels, snapshot.LatencyCount)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w,
			"gluetun_control_request_duration_seconds_sum{%s} %g\n",
			labels, snapshot.LatencySumMS/millisecondsPerSecond)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w,
			"gluetun_control_request_duration_seconds_min{%s} %g\n",
			labels, snapshot.LatencyMinMS/millisecondsPerSecond)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w,
			"gluetun_control_request_duration_seconds_max{%s} %g\n",
			labels, snapshot.LatencyMaxMS/millisecondsPerSecond)
		if err != nil {
			return err
		}
	}

	err := m.writeJobsPrometheus(w)
	if err != nil {
		return err
	}
	return m.writeEgressPrometheus(w)
}

func (m *Metrics) writeJobsPrometheus(w io.Writer) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.jobs == nil {
		return nil
	}
	keys := make([]jobResultKey, 0, len(m.jobs.results))
	for key := range m.jobs.results {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].kind != keys[j].kind {
			return keys[i].kind < keys[j].kind
		}
		return keys[i].result < keys[j].result
	})
	for _, key := range keys {
		_, err := fmt.Fprintf(w,
			"gluetun_control_jobs_total{kind=%s,state=%s} %d\n",
			strconv.Quote(key.kind), strconv.Quote(key.result),
			m.jobs.results[key])
		if err != nil {
			return err
		}
	}

	kinds := make([]string, 0, len(m.jobs.durations))
	for kind := range m.jobs.durations {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	for _, kind := range kinds {
		metrics := m.jobs.durations[kind]
		label := fmt.Sprintf("kind=%s", strconv.Quote(kind))
		_, err := fmt.Fprintf(w,
			"gluetun_control_job_duration_seconds_count{%s} %d\n",
			label, metrics.count)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w,
			"gluetun_control_job_duration_seconds_sum{%s} %g\n",
			label, metrics.sum.Seconds())
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w,
			"gluetun_control_job_duration_seconds_min{%s} %g\n",
			label, metrics.min.Seconds())
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w,
			"gluetun_control_job_duration_seconds_max{%s} %g\n",
			label, metrics.max.Seconds())
		if err != nil {
			return err
		}
	}

	phases := make([]string, 0, len(m.jobs.phases))
	for phase := range m.jobs.phases {
		phases = append(phases, phase)
	}
	sort.Strings(phases)
	for _, phase := range phases {
		_, err := fmt.Fprintf(w,
			"gluetun_control_job_phase_duration_seconds_total{phase=%s} %g\n",
			strconv.Quote(phase), m.jobs.phases[phase].Seconds())
		if err != nil {
			return err
		}
		_, err = fmt.Fprintf(w,
			"gluetun_control_job_phase_duration_seconds_count{phase=%s} %d\n",
			strconv.Quote(phase), m.jobs.phaseCounts[phase])
		if err != nil {
			return err
		}
	}

	attemptKeys := make([]jobResultKey, 0, len(m.jobs.attempts))
	for key := range m.jobs.attempts {
		attemptKeys = append(attemptKeys, key)
	}
	sort.Slice(attemptKeys, func(i, j int) bool {
		if attemptKeys[i].kind != attemptKeys[j].kind {
			return attemptKeys[i].kind < attemptKeys[j].kind
		}
		return attemptKeys[i].result < attemptKeys[j].result
	})
	for _, key := range attemptKeys {
		_, err := fmt.Fprintf(w,
			"gluetun_control_job_attempts_total{kind=%s,result=%s} %d\n",
			strconv.Quote(key.kind), strconv.Quote(key.result),
			m.jobs.attempts[key])
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *Metrics) writeEgressPrometheus(w io.Writer) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	results := make([]string, 0, len(m.egressVerifications))
	for result := range m.egressVerifications {
		results = append(results, result)
	}
	sort.Strings(results)
	for _, result := range results {
		_, err := fmt.Fprintf(w,
			"gluetun_egress_verifications_total{result=%s} %d\n",
			strconv.Quote(result), m.egressVerifications[result])
		if err != nil {
			return err
		}
	}

	sources := make([]string, 0, len(m.egressSources))
	for source := range m.egressSources {
		sources = append(sources, source)
	}
	sort.Strings(sources)
	for _, source := range sources {
		metrics := m.egressSources[source]
		err := writeEgressSourcePrometheus(w, source, metrics)
		if err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(w, "gluetun_egress_quorum %d\n", m.egressQuorum)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "gluetun_egress_dissenters %d\n", m.egressDissenters)
	if err != nil {
		return err
	}
	if m.egressCanaryObserved {
		_, err = fmt.Fprintf(w, "gluetun_egress_canary_ok %d\n", m.egressCanaryOK)
		if err != nil {
			return err
		}
	}
	_, err = fmt.Fprintf(w, "gluetun_egress_cache_hits_total %d\n", m.egressCacheHits)
	return err
}

func writeEgressSourcePrometheus(w io.Writer, source string,
	metrics *egressSourceMetrics,
) error {
	results := make([]string, 0, len(metrics.results))
	for result := range metrics.results {
		results = append(results, result)
	}
	sort.Strings(results)
	for _, result := range results {
		_, err := fmt.Fprintf(w,
			"gluetun_egress_source_requests_total{source=%s,result=%s} %d\n",
			strconv.Quote(source), strconv.Quote(result), metrics.results[result])
		if err != nil {
			return err
		}
	}

	if metrics.latencyCount > 0 {
		_, err := fmt.Fprintf(w,
			"gluetun_egress_source_latency_seconds{source=%s} %g\n",
			strconv.Quote(source),
			metrics.latencySum.Seconds()/float64(metrics.latencyCount))
		if err != nil {
			return err
		}
	}

	banned := 0
	if metrics.banned {
		banned = 1
	}
	_, err := fmt.Fprintf(w, "gluetun_egress_source_banned{source=%s} %d\n",
		strconv.Quote(source), banned)
	return err
}

func durationMS(duration time.Duration) float64 {
	return float64(duration) / float64(time.Millisecond)
}
