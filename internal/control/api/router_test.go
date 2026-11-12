package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testHandler() *Handler {
	control := settings.Control{
		StateMode: "state",
		Egress: settings.Egress{
			Quorum:     2,
			MinSources: 3,
		},
		DNS: settings.DNSLadder{
			Ladder: []string{"dot", "plain"},
		},
	}
	return New(control, models.BuildInformation{Version: "v3.41.3"}, "vpn-gluetun-2", nil, nil)
}

func Test_Handler_Handles(t *testing.T) {
	t.Parallel()

	handler := testHandler()

	testCases := map[string]bool{
		"/control/capabilities":           true,
		"/vpn/state":                      true,
		"/vpn/switch":                     true,
		"/vpn/jobs/job_01J9Z3K4T5":        true,
		"/vpn/jobs/job_01J9Z3K4T5/cancel": true,
		"/servers/nl-1234.nordvpn.com":    true,
		"/vpn/status":                     false,
		"/vpn/settings":                   false,
		"/dns/status":                     false,
		"/unknown":                        false,
	}

	for path, expected := range testCases {
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, expected, handler.Handles(path))
		})
	}
}

func Test_Handler_ServeHTTP(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		method      string
		path        string
		contentType string
		status      int
		code        string
		retryable   bool
	}{
		"capabilities": {
			method: http.MethodGet,
			path:   "/control/capabilities",
			status: http.StatusOK,
		},
		"unknown route": {
			method: http.MethodGet,
			path:   "/unknown",
			status: http.StatusNotFound,
			code:   CodeNotFound,
		},
		"wrong method": {
			method: http.MethodGet,
			path:   "/vpn/switch",
			status: http.StatusMethodNotAllowed,
			code:   CodeMethodNotAllowed,
		},
		"missing content type": {
			method: http.MethodPost,
			path:   "/vpn/switch",
			status: http.StatusUnsupportedMediaType,
			code:   CodeUnsupportedMedia,
		},
		"switch service unavailable": {
			method:      http.MethodPost,
			path:        "/vpn/switch",
			contentType: "application/json",
			status:      http.StatusServiceUnavailable,
			code:        CodeNotReady,
			retryable:   true,
		},
		"job service unavailable": {
			method:    http.MethodGet,
			path:      "/vpn/jobs/job_01J9Z3K4T5",
			status:    http.StatusServiceUnavailable,
			code:      CodeNotReady,
			retryable: true,
		},
		"transport not ready": {
			method:    http.MethodGet,
			path:      "/vpn/transport",
			status:    http.StatusServiceUnavailable,
			code:      CodeNotReady,
			retryable: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			request := httptest.NewRequestWithContext(context.Background(),
				testCase.method, testCase.path, strings.NewReader("{}"))
			if testCase.contentType != "" {
				request.Header.Set("Content-Type", testCase.contentType)
			}
			response := httptest.NewRecorder()

			testHandler().ServeHTTP(response, request)

			assert.Equal(t, testCase.status, response.Code)
			assert.Equal(t, "application/json; charset=utf-8",
				response.Header().Get("Content-Type"))

			if testCase.code == "" {
				return
			}
			var body errorBody
			err := json.NewDecoder(response.Body).Decode(&body)
			require.NoError(t, err)
			assert.Equal(t, testCase.code, body.Error.Code)
			assert.Equal(t, testCase.retryable, body.Error.Retryable)
		})
	}
}
