package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_echoHandlerIP(t *testing.T) {
	t.Parallel()

	handler := newEchoHandler(echoSettings{
		name: "echo-a",
		ip:   "203.0.113.10",
		body: "ok",
	})

	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ip", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)

	var body struct {
		Source string `json:"source"`
		IP     string `json:"ip"`
	}
	err := json.Unmarshal(response.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "echo-a", body.Source)
	assert.Equal(t, "203.0.113.10", body.IP)
}

func Test_echoHandlerAutoIP(t *testing.T) {
	t.Parallel()

	handler := newEchoHandler(echoSettings{name: "auto", ip: "auto", body: "ok"})
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/ip", nil)
	request.RemoteAddr = "192.0.2.7:1234"
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	var body struct {
		IP string `json:"ip"`
	}
	err := json.Unmarshal(response.Body.Bytes(), &body)
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.7", body.IP)
}

func Test_echoHandlerCanary(t *testing.T) {
	t.Parallel()

	handler := newEchoHandler(echoSettings{
		name: "echo-a", ip: "203.0.113.10",
		body: "canary-ok",
	})
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/canary", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	assert.Equal(t, http.StatusOK, response.Code)
	assert.Equal(t, "canary-ok\n", response.Body.String())
}

func Test_echoHandlerInjectedFailure(t *testing.T) {
	t.Parallel()

	handler := newEchoHandler(echoSettings{
		name:   "echo-failing",
		ip:     "203.0.113.99",
		fail:   true,
		status: http.StatusServiceUnavailable,
	})

	for _, path := range []string{"/ip", "/canary"} {
		request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		assert.Equal(t, http.StatusServiceUnavailable, response.Code, path)
	}

	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusOK, response.Code)
}

func Test_echoHandlerStatusAndDelay(t *testing.T) {
	t.Parallel()

	handler := newEchoHandler(echoSettings{name: "echo-a", ip: "203.0.113.10"})

	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/status/429", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusTooManyRequests, response.Code)

	request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/delay/0", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusOK, response.Code)

	request = httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/status/nope", nil)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	assert.Equal(t, http.StatusBadRequest, response.Code)
}
