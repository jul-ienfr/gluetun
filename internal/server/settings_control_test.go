package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serveSettingsBody(t *testing.T, controlEnabled bool,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()

	handler := newTestHandler(t, controlEnabled)
	request := httptest.NewRequestWithContext(context.Background(),
		http.MethodPut, "/v1/vpn/settings", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func Test_ControlledSettingsDelegatesToControlPlane(t *testing.T) {
	t.Parallel()

	response := serveSettingsBody(t, true,
		`{"target":{"hostname":"new.example.com"}}`)

	// The control plane is mounted and delegates to the switch jobs, which
	// reject the unknown target before touching the tunnel.
	require.Equal(t, http.StatusUnprocessableEntity, response.Code)

	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
	assert.Equal(t, "invalid_target", body.Error.Code)
}

func Test_LegacySettingsKeepsUpstreamHandler(t *testing.T) {
	t.Parallel()

	response := serveSettingsBody(t, true, `{"legacy_field":true}`)

	require.Equal(t, http.StatusBadRequest, response.Code)
	assert.Contains(t, response.Body.String(), "unknown field")
}

func Test_ControlledSettingsStaysLegacyWhenDisabled(t *testing.T) {
	t.Parallel()

	response := serveSettingsBody(t, false,
		`{"target":{"hostname":"new.example.com"}}`)

	// Upstream strict decoding rejects the unknown controlled fields.
	require.Equal(t, http.StatusBadRequest, response.Code)
	assert.Contains(t, response.Body.String(), "unknown field")
}
