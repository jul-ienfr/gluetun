package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	transportpkg "github.com/qdm12/gluetun/internal/vpn/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTransport struct {
	state       transportpkg.State
	available   bool
	policy      transportpkg.Policy
	resetTarget *transportpkg.Transport
	resetErr    error
}

func (f *fakeTransport) TransportState() (transportpkg.State, bool) {
	return f.state, f.available
}

func (f *fakeTransport) TransportPolicy() transportpkg.Policy {
	return f.policy
}

func (f *fakeTransport) ResetTransport(target *transportpkg.Transport) error {
	f.resetTarget = target
	return f.resetErr
}

func serveTransport(t *testing.T, service TransportService, method, path,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()

	handler := New(settings.Control{}, models.BuildInformation{}, "station", nil,
		nil)
	if service != nil {
		handler.SetTransport(service)
	}
	request := httptest.NewRequestWithContext(context.Background(), method,
		path, strings.NewReader(body))
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func Test_Handler_TransportState(t *testing.T) {
	t.Parallel()

	active := transportpkg.OpenVPNTCP
	next := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	state := transportpkg.State{
		Active: &active,
		Phase:  transportpkg.PhaseCommitted,
		Cycle:  1,
		Breakers: map[transportpkg.Transport]transportpkg.Breaker{
			transportpkg.WireGuard: {
				State:    transportpkg.BreakerOpen,
				Failures: 3,
				RetryAt:  next,
			},
			transportpkg.OpenVPNUDP: {
				State:    transportpkg.BreakerOpen,
				Failures: 3,
				RetryAt:  next,
			},
			transportpkg.OpenVPNTCP: {State: transportpkg.BreakerClosed},
		},
		Attempts: []transportpkg.Attempt{
			{
				Transport: transportpkg.WireGuard,
				Result:    transportpkg.AttemptFailed,
				Reason:    transportpkg.ReasonHandshakeTimeout,
				Latency:   30 * time.Second,
			},
			{
				Transport: transportpkg.OpenVPNTCP,
				Result:    transportpkg.AttemptSuccess,
				Latency:   8 * time.Second,
			},
		},
		UpdatedAt: next,
	}
	service := &fakeTransport{
		state:     state,
		available: true,
		policy: transportpkg.Policy{
			Ladder: []transportpkg.Transport{
				transportpkg.WireGuard,
				transportpkg.OpenVPNUDP,
				transportpkg.OpenVPNTCP,
			},
		},
	}

	response := serveTransport(t, service, http.MethodGet, "/vpn/transport", "")
	require.Equal(t, http.StatusOK, response.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	assert.Equal(t, "openvpn-tcp", body["active_transport"])
	assert.Equal(t, "committed", body["phase"])
	assert.Contains(t, body, "breaker")
	assert.NotContains(t, body, "breakers")
	attempts, ok := body["attempts"].([]any)
	require.True(t, ok)
	require.Len(t, attempts, 2)
	first := attempts[0].(map[string]any)
	assert.Equal(t, float64(30000), first["latency_ms"])
	assert.Equal(t, "handshake_timeout", first["reason"])
}

func Test_Handler_TransportReset(t *testing.T) {
	t.Parallel()

	service := &fakeTransport{available: true, policy: transportpkg.Policy{
		Ladder: []transportpkg.Transport{
			transportpkg.WireGuard,
			transportpkg.OpenVPNUDP,
			transportpkg.OpenVPNTCP,
		},
	}}
	response := serveTransport(t, service, http.MethodPost,
		"/vpn/transport/reset", `{"transport":"wireguard"}`)
	require.Equal(t, http.StatusOK, response.Code)

	var body transportResetResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	assert.Equal(t, "wireguard", body.Transport)
	assert.Equal(t, transportpkg.BreakerClosed, body.Breaker)
	assert.True(t, body.Reset)
	require.NotNil(t, service.resetTarget)
	assert.Equal(t, transportpkg.WireGuard, *service.resetTarget)
}

func Test_Handler_TransportResetAll(t *testing.T) {
	t.Parallel()

	service := &fakeTransport{available: true}
	response := serveTransport(t, service, http.MethodPost,
		"/vpn/transport/reset", "")
	require.Equal(t, http.StatusOK, response.Code)

	var body transportResetResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	assert.Equal(t, "all", body.Transport)
	assert.Nil(t, service.resetTarget)
}

func Test_Handler_TransportResetUnknown(t *testing.T) {
	t.Parallel()

	service := &fakeTransport{available: true}
	response := serveTransport(t, service, http.MethodPost,
		"/vpn/transport/reset", `{"transport":"gre"}`)
	require.Equal(t, http.StatusUnprocessableEntity, response.Code)

	var body errorBody
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	assert.Equal(t, CodeInvalidTarget, body.Error.Code)
	assert.Nil(t, service.resetTarget)
}

func Test_Handler_TransportNotReady(t *testing.T) {
	t.Parallel()

	response := serveTransport(t, nil, http.MethodGet, "/vpn/transport", "")
	require.Equal(t, http.StatusServiceUnavailable, response.Code)

	var body errorBody
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	assert.Equal(t, CodeNotReady, body.Error.Code)
}
