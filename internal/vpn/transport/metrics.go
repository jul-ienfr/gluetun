package transport

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

type transportAttemptMetrics struct {
	success uint64
	failed  uint64
	skipped uint64
	latency time.Duration
}

type Metrics struct {
	mutex     sync.Mutex
	attempts  map[Transport]*transportAttemptMetrics
	failures  map[Transport]map[Reason]uint64
	breakers  map[Transport]BreakerState
	active    map[Transport]bool
	cycles    map[string]uint64
	exhausted uint64
}

func NewMetrics() *Metrics {
	return &Metrics{
		attempts: make(map[Transport]*transportAttemptMetrics),
		failures: make(map[Transport]map[Reason]uint64),
		breakers: make(map[Transport]BreakerState),
		active:   make(map[Transport]bool),
		cycles:   make(map[string]uint64),
	}
}

func (m *Metrics) ObserveAttempt(transport Transport, result AttemptResult,
	reason Reason, latency time.Duration,
) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	metrics, ok := m.attempts[transport]
	if !ok {
		metrics = &transportAttemptMetrics{}
		m.attempts[transport] = metrics
	}
	switch result {
	case AttemptSuccess:
		metrics.success++
	case AttemptSkipped:
		metrics.skipped++
	default:
		metrics.failed++
	}
	metrics.latency += latency

	if reason != ReasonNone && reason != ReasonBreakerOpen {
		reasons, ok := m.failures[transport]
		if !ok {
			reasons = make(map[Reason]uint64)
			m.failures[transport] = reasons
		}
		reasons[reason]++
	}
}

func (m *Metrics) SetActive(transport Transport) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	for name := range m.active {
		m.active[name] = false
	}
	if transport != "" {
		m.active[transport] = true
	}
}

func (m *Metrics) SetBreaker(transport Transport, state BreakerState) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if state == "" {
		state = BreakerClosed
	}
	m.breakers[transport] = state
}

func (m *Metrics) ObserveCycle(result string) {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	if result == "" {
		result = "unknown"
	}
	m.cycles[result]++
}

func (m *Metrics) ObserveCycleExhausted() {
	m.mutex.Lock()
	defer m.mutex.Unlock()
	m.exhausted++
}

func (m *Metrics) WritePrometheus(w io.Writer) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	transports := make([]string, 0, len(m.attempts))
	seen := make(map[string]struct{}, len(m.attempts)+len(m.breakers)+len(m.active))
	for transport := range m.attempts {
		seen[string(transport)] = struct{}{}
	}
	for transport := range m.breakers {
		seen[string(transport)] = struct{}{}
	}
	for transport := range m.active {
		seen[string(transport)] = struct{}{}
	}
	for transport := range seen {
		transports = append(transports, transport)
	}
	sort.Strings(transports)

	for _, transport := range transports {
		metrics := m.attempts[Transport(transport)]
		if metrics != nil {
			err := writeAttemptMetrics(w, transport, metrics)
			if err != nil {
				return err
			}
		}
		err := writeFailureMetrics(w, Transport(transport), m.failures[Transport(transport)])
		if err != nil {
			return err
		}
		err = writeBreakerMetrics(w, Transport(transport), m.breakers[Transport(transport)],
			m.active[Transport(transport)])
		if err != nil {
			return err
		}
	}

	results := make([]string, 0, len(m.cycles))
	for result := range m.cycles {
		results = append(results, result)
	}
	sort.Strings(results)
	for _, result := range results {
		_, err := fmt.Fprintf(w, "gluetun_transport_cycles_total{result=%q} %d\n",
			result, m.cycles[result])
		if err != nil {
			return err
		}
	}

	_, err := fmt.Fprintf(w, "gluetun_transport_cycle_exhausted_total %d\n",
		m.exhausted)
	return err
}

func writeAttemptMetrics(w io.Writer, transport string,
	metrics *transportAttemptMetrics,
) error {
	results := []struct {
		name  string
		value uint64
	}{
		{name: "success", value: metrics.success},
		{name: "failed", value: metrics.failed},
		{name: "skipped", value: metrics.skipped},
	}
	for _, result := range results {
		_, err := fmt.Fprintf(w,
			"gluetun_transport_attempts_total{transport=%q,result=%q} %d\n",
			transport, result.name, result.value)
		if err != nil {
			return err
		}
	}

	if metrics.success > 0 {
		average := metrics.latency.Seconds() / float64(metrics.success)
		_, err := fmt.Fprintf(w,
			"gluetun_transport_connect_seconds{transport=%q} %g\n",
			transport, average)
		if err != nil {
			return err
		}
	}
	return nil
}

func writeFailureMetrics(w io.Writer, transport Transport,
	reasons map[Reason]uint64,
) error {
	names := make([]string, 0, len(reasons))
	for reason := range reasons {
		names = append(names, string(reason))
	}
	sort.Strings(names)
	for _, name := range names {
		_, err := fmt.Fprintf(w,
			"gluetun_transport_failures_total{transport=%q,reason=%q} %d\n",
			string(transport), name, reasons[Reason(name)])
		if err != nil {
			return err
		}
	}
	return nil
}

func writeBreakerMetrics(w io.Writer, transport Transport, state BreakerState,
	active bool,
) error {
	value := breakerStateValue(state)
	_, err := fmt.Fprintf(w,
		"gluetun_transport_breaker_state{transport=%q} %d\n",
		string(transport), value)
	if err != nil {
		return err
	}

	activeValue := 0
	if active {
		activeValue = 1
	}
	_, err = fmt.Fprintf(w, "gluetun_transport_active{transport=%q} %d\n",
		string(transport), activeValue)
	return err
}

func breakerStateValue(state BreakerState) int {
	switch state {
	case BreakerOpen:
		return 1
	case BreakerHalfOpen:
		return 2
	default:
		return 0
	}
}
