package transport

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMetricsWritePrometheus(t *testing.T) {
	t.Parallel()

	metrics := NewMetrics()
	metrics.ObserveAttempt(WireGuard, AttemptFailed,
		ReasonHandshakeTimeout, 30*time.Second)
	metrics.ObserveAttempt(WireGuard, AttemptFailed,
		ReasonHandshakeTimeout, 30*time.Second)
	metrics.ObserveAttempt(OpenVPNUDP, AttemptFailed,
		ReasonUDPBlocked, 30*time.Second)
	metrics.ObserveAttempt(OpenVPNTCP, AttemptSuccess, ReasonNone, 8*time.Second)
	metrics.ObserveAttempt(OpenVPNTCP, AttemptSkipped, ReasonBreakerOpen, 0)
	metrics.SetBreaker(WireGuard, BreakerOpen)
	metrics.SetBreaker(OpenVPNUDP, BreakerHalfOpen)
	metrics.SetBreaker(OpenVPNTCP, BreakerClosed)
	metrics.SetActive(OpenVPNTCP)
	metrics.ObserveCycle("committed")
	metrics.ObserveCycle("exhausted")
	metrics.ObserveCycleExhausted()

	var buffer bytes.Buffer
	err := metrics.WritePrometheus(&buffer)
	if err != nil {
		t.Fatalf("writing metrics: %v", err)
	}
	output := buffer.String()

	expected := []string{
		`gluetun_transport_attempts_total{transport="wireguard",result="failed"} 2`,
		`gluetun_transport_attempts_total{transport="wireguard",result="success"} 0`,
		`gluetun_transport_attempts_total{transport="openvpn-tcp",result="success"} 1`,
		`gluetun_transport_attempts_total{transport="openvpn-tcp",result="skipped"} 1`,
		`gluetun_transport_failures_total{transport="wireguard",reason="handshake_timeout"} 2`,
		`gluetun_transport_failures_total{transport="openvpn-udp",reason="udp_blocked"} 1`,
		`gluetun_transport_connect_seconds{transport="openvpn-tcp"} 8`,
		`gluetun_transport_active{transport="openvpn-tcp"} 1`,
		`gluetun_transport_active{transport="wireguard"} 0`,
		`gluetun_transport_breaker_state{transport="wireguard"} 1`,
		`gluetun_transport_breaker_state{transport="openvpn-udp"} 2`,
		`gluetun_transport_breaker_state{transport="openvpn-tcp"} 0`,
		`gluetun_transport_cycles_total{result="committed"} 1`,
		`gluetun_transport_cycles_total{result="exhausted"} 1`,
		`gluetun_transport_cycle_exhausted_total 1`,
	}
	for _, line := range expected {
		if !strings.Contains(output, line) {
			t.Fatalf("missing metric line %q in:\n%s", line, output)
		}
	}
}

func TestMetricsWithLadder(t *testing.T) {
	t.Parallel()

	runner := newFakeRunner()
	runner.preflightErrs = map[Transport][]error{
		WireGuard: {NewFailure(ReasonUDPBlocked, errors.New("blocked"))},
	}
	metrics := NewMetrics()
	ladder, err := NewLadder(testPolicy(), runner,
		WithSleep(noSleep),
		WithMetrics(metrics))
	if err != nil {
		t.Fatalf("creating ladder: %v", err)
	}

	result, err := ladder.Run(context.Background(), Target{Hostname: "server"})
	if err != nil {
		t.Fatalf("running ladder: %v", err)
	}
	if result.Transport != OpenVPNUDP {
		t.Fatalf("transport: %s", result.Transport)
	}

	var buffer bytes.Buffer
	err = metrics.WritePrometheus(&buffer)
	if err != nil {
		t.Fatalf("writing metrics: %v", err)
	}
	output := buffer.String()
	expected := []string{
		`gluetun_transport_attempts_total{transport="wireguard",result="failed"} 1`,
		`gluetun_transport_attempts_total{transport="openvpn-udp",result="success"} 1`,
		`gluetun_transport_active{transport="openvpn-udp"} 1`,
		`gluetun_transport_cycles_total{result="committed"} 1`,
	}
	for _, line := range expected {
		if !strings.Contains(output, line) {
			t.Fatalf("missing metric line %q in:\n%s", line, output)
		}
	}
}
