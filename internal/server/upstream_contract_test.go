package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/server/middlewares/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

type fakePublicIP struct {
	data models.PublicIP
}

func (f fakePublicIP) GetData() models.PublicIP { return f.data }

type fakeStorage struct{}

func (fakeStorage) GetFilterChoices(string) models.FilterChoices {
	return models.FilterChoices{}
}

func (fakeStorage) GetServers(string) []models.Server {
	return nil
}

type testLogger struct{}

func (testLogger) Debugf(string, ...any) {}
func (testLogger) Info(string)           {}
func (testLogger) Infof(string, ...any)  {}
func (testLogger) Warn(string)           {}
func (testLogger) Warnf(string, ...any)  {}
func (testLogger) Error(string)          {}

func newTestHandler(t *testing.T, controlEnabled bool) http.Handler {
	t.Helper()
	ctrl := gomock.NewController(t)

	vpn := NewMockVPNLooper(ctrl)
	vpn.EXPECT().GetStatus().Return(constants.Running).AnyTimes()
	vpn.EXPECT().GetSettings().Return(settings.VPN{}).AnyTimes()

	dns := NewMockDNSLoop(ctrl)
	dns.EXPECT().GetStatus().Return(constants.Running).AnyTimes()

	portForward := NewMockPortForwarding(ctrl)
	portForward.EXPECT().GetPortsForwarded().Return([]uint16{1234}).AnyTimes()

	updater := NewMockUpdaterLooper(ctrl)

	var authSettings auth.Settings
	err := authSettings.SetDefaultRole(`{"auth":"none"}`)
	require.NoError(t, err)
	require.NoError(t, authSettings.Validate())

	publicIP := fakePublicIP{data: models.PublicIP{
		IP:      netip.MustParseAddr("198.51.100.7"),
		Country: "Netherlands",
	}}

	controlSettings := settings.Control{
		Enabled:   &controlEnabled,
		StateMode: "state",
		Egress: settings.Egress{
			Quorum:     2,
			MinSources: 3,
		},
		DNS: settings.DNSLadder{
			Ladder: []string{"dot", "plain"},
		},
	}

	handler, err := newHandler(context.Background(), testLogger{}, false, authSettings,
		controlSettings,
		models.BuildInformation{
			Version: "test-version",
			Commit:  "test-commit",
			Created: "2026-01-01T00:00:00Z",
		},
		vpn, portForward, dns, updater, publicIP, fakeStorage{}, true)
	require.NoError(t, err)
	return handler
}

func serve(t *testing.T, handler http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequestWithContext(context.Background(), method, path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func Test_UpstreamContract(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, false)

	testCases := map[string]struct {
		path   string
		status int
		body   string
		json   string
	}{
		"version": {
			path:   "/v1/version",
			status: http.StatusOK,
			body: `{"version":"test-version","commit":"test-commit",` +
				`"created":"2026-01-01T00:00:00Z"}` + "\n",
		},
		"vpn status": {
			path:   "/v1/vpn/status",
			status: http.StatusOK,
			body:   `{"status":"running"}` + "\n",
		},
		"dns status": {
			path:   "/v1/dns/status",
			status: http.StatusOK,
			body:   `{"status":"running"}` + "\n",
		},
		"public ip": {
			path:   "/v1/publicip/ip",
			status: http.StatusOK,
			json:   `{"public_ip":"198.51.100.7","country":"Netherlands"}`,
		},
		"port forward": {
			path:   "/v1/portforward",
			status: http.StatusOK,
			body:   `{"port":1234,"ports":[1234]}` + "\n",
		},
		"vpn settings": {
			path:   "/v1/vpn/settings",
			status: http.StatusOK,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := serve(t, handler, http.MethodGet, testCase.path)

			assert.Equal(t, testCase.status, response.Code)
			switch {
			case testCase.body != "":
				assert.Equal(t, testCase.body, response.Body.String())
			case testCase.json != "":
				assert.JSONEq(t, testCase.json, response.Body.String())
			default:
				var decoded map[string]any
				err := json.Unmarshal(response.Body.Bytes(), &decoded)
				require.NoError(t, err)
				assert.NotEmpty(t, decoded)
			}
		})
	}
}

func Test_ControlPlaneDisabledKeepsUpstreamRoutes(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, false)
	response := serve(t, handler, http.MethodGet, "/v1/control/capabilities")

	// Unknown upstream route: the control plane is not mounted.
	assert.Equal(t, http.StatusBadRequest, response.Code)
}

func Test_ControlPlaneEnabledMountsCapabilities(t *testing.T) {
	t.Parallel()

	handler := newTestHandler(t, true)
	response := serve(t, handler, http.MethodGet, "/v1/control/capabilities")

	require.Equal(t, http.StatusOK, response.Code)

	var capabilities struct {
		ControlPlaneVersion string   `json:"control_plane_version"`
		UpstreamVersion     string   `json:"upstream_version"`
		DNSDefaultLadder    []string `json:"dns_default_ladder"`
	}
	err := json.Unmarshal(response.Body.Bytes(), &capabilities)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", capabilities.ControlPlaneVersion)
	assert.Equal(t, "test-version", capabilities.UpstreamVersion)
	assert.Equal(t, []string{"dot", "plain"}, capabilities.DNSDefaultLadder)
}
