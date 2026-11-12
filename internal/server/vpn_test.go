package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func serverSecretSettings() settings.VPN {
	password := "super-secret-password"
	privateKey := "super-secret-private-key"
	return settings.VPN{
		Type: "wireguard",
		Provider: settings.Provider{
			Name: "nordvpn",
		},
		Wireguard: settings.Wireguard{
			PrivateKey: &privateKey,
			Interface:  "wg0",
		},
		OpenVPN: settings.OpenVPN{
			Password: &password,
		},
	}
}

func Test_VPNHandler_GetSettings_MasksSecretsByDefault(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	looper := NewMockVPNLooper(ctrl)
	looper.EXPECT().GetSettings().Return(serverSecretSettings())
	handler := &vpnHandler{looper: looper}

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/v1/vpn/settings", nil)
	response := httptest.NewRecorder()

	handler.getSettings(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	body := response.Body.String()
	assert.NotContains(t, body, "super-secret-password")
	assert.NotContains(t, body, "super-secret-private-key")
	assert.Contains(t, body, `"***"`)
	assert.Contains(t, body, "wg0")
}

func Test_VPNHandler_GetSettings_RevealsSecretsOnDemand(t *testing.T) {
	t.Parallel()

	ctrl := gomock.NewController(t)
	looper := NewMockVPNLooper(ctrl)
	looper.EXPECT().GetSettings().Return(serverSecretSettings())
	handler := &vpnHandler{looper: looper}

	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet,
		"/v1/vpn/settings?reveal=true", nil)
	response := httptest.NewRecorder()

	handler.getSettings(response, request)

	require.Equal(t, http.StatusOK, response.Code)
	body := response.Body.String()
	assert.Contains(t, body, "super-secret-password")
	assert.Contains(t, body, "super-secret-private-key")
}

func Test_VPNHandler_PatchSettings_rejects_unknown_field_when_payload_uses_legacy_names(t *testing.T) {
	t.Parallel()

	const body = `{"Provider":{"ServerSelection":{"Countries":["Netherlands"]}}}`
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/v1/vpn/settings", strings.NewReader(body))
	response := httptest.NewRecorder()
	ctrl := gomock.NewController(t)
	looper := NewMockVPNLooper(ctrl)
	handler := &vpnHandler{looper: looper}

	handler.patchSettings(response, request)

	require.Equal(t, http.StatusBadRequest, response.Code)
	assert.Contains(t, response.Body.String(), `json: unknown field "ServerSelection"`)
	assert.NotContains(t, response.Body.String(), "settings left unchanged")
}
