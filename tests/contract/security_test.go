package contract

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/constants"
	"github.com/qdm12/gluetun/internal/control/events"
	"github.com/qdm12/gluetun/internal/control/state"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	readerAPIKey = "reader-key-0123456789"
	adminAPIKey  = "admin-key-0123456789"

	openVPNUser     = "openvpn-user"
	openVPNPassword = "openvpn-password-secret"
	openVPNKey      = "openvpn-private-key-secret"
	wireguardKey    = "wireguard-private-key-secret"
)

const authConfig = `[[roles]]
name = "reader"
auth = "apikey"
apikey = "` + readerAPIKey + `"
scope = "reader"
routes = [
  "GET /v1/vpn/state",
  "GET /v1/vpn/settings",
  "GET /v1/events",
  "POST /v1/vpn/switch",
]

[[roles]]
name = "admin"
auth = "apikey"
apikey = "` + adminAPIKey + `"
scope = "admin"
routes = [
  "GET /v1/vpn/state",
  "GET /v1/vpn/settings",
  "PUT /v1/vpn/settings",
  "GET /v1/events",
  "POST /v1/vpn/switch",
]
`

type captureLogger struct {
	mutex   sync.Mutex
	entries []string
}

func (l *captureLogger) record(level, message string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.entries = append(l.entries, level+" "+message)
}

func (l *captureLogger) Debugf(format string, args ...any) {
	l.record("debug", fmt.Sprintf(format, args...))
}

func (l *captureLogger) Info(message string) {
	l.record("info", message)
}

func (l *captureLogger) Infof(format string, args ...any) {
	l.record("info", fmt.Sprintf(format, args...))
}

func (l *captureLogger) Warn(message string) {
	l.record("warn", message)
}

func (l *captureLogger) Warnf(format string, args ...any) {
	l.record("warn", fmt.Sprintf(format, args...))
}

func (l *captureLogger) Error(message string) {
	l.record("error", message)
}

func (l *captureLogger) all() string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	return strings.Join(l.entries, "\n")
}

type fakeVPNLooper struct {
	mutex      sync.Mutex
	status     models.LoopStatus
	settings   settings.VPN
	setCalls   int
	applyCalls int
}

func (f *fakeVPNLooper) GetStatus() models.LoopStatus {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.status
}

func (f *fakeVPNLooper) ApplyStatus(_ context.Context,
	status models.LoopStatus,
) (string, error) {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.applyCalls++
	f.status = status
	return "ok", nil
}

func (f *fakeVPNLooper) GetSettings() settings.VPN {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.settings
}

func (f *fakeVPNLooper) SetSettings(_ context.Context,
	updated settings.VPN,
) string {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.setCalls++
	f.settings = updated
	return "ok"
}

func (f *fakeVPNLooper) writes() int {
	f.mutex.Lock()
	defer f.mutex.Unlock()
	return f.setCalls + f.applyCalls
}

type fakeDNSLoop struct{ status models.LoopStatus }

func (f fakeDNSLoop) GetStatus() models.LoopStatus { return f.status }

func (f fakeDNSLoop) ApplyStatus(context.Context,
	models.LoopStatus,
) (string, error) {
	return "ok", nil
}

type fakePortForwarding struct{}

func (fakePortForwarding) GetPortsForwarded() []uint16 { return nil }

func (fakePortForwarding) SetPortsForwarded([]uint16) error { return nil }

type fakeUpdater struct{ status models.LoopStatus }

func (f fakeUpdater) GetStatus() models.LoopStatus { return f.status }

func (f fakeUpdater) SetStatus(context.Context,
	models.LoopStatus,
) (string, error) {
	return "ok", nil
}

func (f fakeUpdater) SetSettings(settings.Updater) string { return "ok" }

type fakePublicIP struct{ data models.PublicIP }

func (f fakePublicIP) GetData() models.PublicIP { return f.data }

type fakeStorage struct{}

func (fakeStorage) GetFilterChoices(string) models.FilterChoices {
	return models.FilterChoices{}
}

func (fakeStorage) GetServers(string) []models.Server { return nil }

type testStation struct {
	url    string
	logger *captureLogger
	vpn    *fakeVPNLooper
	dir    string
}

type httpResult struct {
	status int
	body   []byte
	header http.Header
}

func (s *testStation) request(t *testing.T, method, path string, body []byte,
	headers map[string]string,
) httpResult {
	t.Helper()

	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	request, err := http.NewRequestWithContext(t.Context(), method,
		s.url+path, reader)
	require.NoError(t, err)
	for key, value := range headers {
		request.Header.Set(key, value)
	}

	response, err := http.DefaultClient.Do(request)
	require.NoError(t, err)
	defer response.Body.Close()

	content, err := io.ReadAll(response.Body)
	require.NoError(t, err)
	return httpResult{
		status: response.StatusCode,
		body:   content,
		header: response.Header,
	}
}

func secretVPNSettings() settings.VPN {
	return settings.VPN{
		Type: "openvpn",
		Provider: settings.Provider{
			Name: "nordvpn",
			PortForwarding: settings.PortForwarding{
				Username: "port-forward-user",
				Password: "port-forward-password-secret",
			},
		},
		OpenVPN: settings.OpenVPN{
			User:          stringPointer(openVPNUser),
			Password:      stringPointer(openVPNPassword),
			Key:           stringPointer(openVPNKey),
			ConfFile:      stringPointer(""),
			KeyPassphrase: stringPointer("openvpn-key-passphrase-secret"),
		},
		Wireguard: settings.Wireguard{
			PrivateKey:   stringPointer(wireguardKey),
			PreSharedKey: stringPointer("wireguard-pre-shared-secret"),
			Interface:    "wg0",
		},
	}
}

func stringPointer(value string) *string { return &value }

func boolPointer(value bool) *bool { return &value }

func startStation(t *testing.T) *testStation {
	t.Helper()

	dir := t.TempDir()
	authPath := filepath.Join(dir, "auth.toml")
	err := os.WriteFile(authPath, []byte(authConfig), 0o600)
	require.NoError(t, err)

	logger := &captureLogger{}
	vpn := &fakeVPNLooper{
		status:   constants.Running,
		settings: secretVPNSettings(),
	}

	address := "127.0.0.1:0"
	logRequests := true
	controlEnabled := true
	control := settings.Control{
		Enabled:   &controlEnabled,
		StateDir:  filepath.Join(dir, "control"),
		StateMode: state.ModeState,
		Egress: settings.Egress{
			Enabled: boolPointer(false),
		},
		DNS: settings.DNSLadder{Ladder: []string{"dot", "plain"}},
	}

	ctx, cancel := context.WithCancel(t.Context())
	httpServer, err := server.New(ctx, settings.ControlServer{
		Address:         &address,
		Log:             &logRequests,
		AuthFilePath:    authPath,
		AuthDefaultRole: "{}",
	}, control, logger, models.BuildInformation{
		Version: "test-version",
		Commit:  "test-commit",
		Created: "2026-01-01T00:00:00Z",
	}, vpn, fakePortForwarding{}, fakeDNSLoop{status: constants.Running},
		fakeUpdater{status: constants.Stopped}, fakePublicIP{}, fakeStorage{},
		true, nil, nil, nil)
	require.NoError(t, err)

	ready := make(chan struct{})
	done := make(chan struct{})
	go httpServer.Run(ctx, ready, done)

	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		t.Fatal("HTTP server did not become ready")
	}

	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("HTTP server did not stop")
		}
	})

	return &testStation{
		url:    "http://" + httpServer.GetAddress(),
		logger: logger,
		vpn:    vpn,
		dir:    dir,
	}
}

func Test_Security_AuthenticationAndScopes(t *testing.T) {
	t.Parallel()

	station := startStation(t)

	unauthenticated := station.request(t, http.MethodGet, "/v1/vpn/state",
		nil, nil)
	assert.Equal(t, http.StatusUnauthorized, unauthenticated.status)

	wrongKey := station.request(t, http.MethodGet, "/v1/vpn/state", nil,
		map[string]string{"X-API-Key": "wrong-key"})
	assert.Equal(t, http.StatusUnauthorized, wrongKey.status)

	readState := station.request(t, http.MethodGet, "/v1/vpn/state", nil,
		map[string]string{"X-API-Key": readerAPIKey})
	require.Equal(t, http.StatusOK, readState.status)

	readSwitch := station.request(t, http.MethodPost, "/v1/vpn/switch",
		[]byte(`{"target":{"hostname":"nl-1.example.com"}}`),
		map[string]string{
			"X-API-Key":    readerAPIKey,
			"Content-Type": "application/json",
		})
	require.Equal(t, http.StatusForbidden, readSwitch.status)
	assert.Contains(t, string(readSwitch.body), "forbidden_scope")
	assert.Equal(t, 0, station.vpn.writes(),
		"a forbidden switch must never touch the tunnel")

	readReveal := station.request(t, http.MethodGet,
		"/v1/vpn/settings?reveal=true", nil,
		map[string]string{"X-API-Key": readerAPIKey})
	require.Equal(t, http.StatusForbidden, readReveal.status)
	assert.NotContains(t, string(readReveal.body), openVPNPassword)

	adminReveal := station.request(t, http.MethodGet,
		"/v1/vpn/settings?reveal=true", nil,
		map[string]string{"X-API-Key": adminAPIKey})
	require.Equal(t, http.StatusOK, adminReveal.status)
	assert.Contains(t, string(adminReveal.body), openVPNPassword)
}

func Test_Security_RevealMasksSecrets(t *testing.T) {
	t.Parallel()

	station := startStation(t)

	masked := station.request(t, http.MethodGet, "/v1/vpn/settings", nil,
		map[string]string{"X-API-Key": readerAPIKey})
	require.Equal(t, http.StatusOK, masked.status)
	assert.Contains(t, masked.header.Get("Content-Type"), "application/json")
	assert.Contains(t, string(masked.body), "***")
	assert.Contains(t, string(masked.body), openVPNUser,
		"usernames are not secrets and must stay visible")

	for _, secret := range []string{
		openVPNPassword,
		openVPNKey,
		wireguardKey,
		"port-forward-password-secret",
		"openvpn-key-passphrase-secret",
		"wireguard-pre-shared-secret",
	} {
		assert.NotContains(t, string(masked.body), secret)
	}

	revealed := station.request(t, http.MethodGet,
		"/v1/vpn/settings?reveal=true", nil,
		map[string]string{"X-API-Key": adminAPIKey})
	require.Equal(t, http.StatusOK, revealed.status)
	for _, secret := range []string{
		openVPNPassword,
		openVPNKey,
		wireguardKey,
	} {
		assert.Contains(t, string(revealed.body), secret)
	}

	eventsPage := station.request(t, http.MethodGet, "/v1/events", nil,
		map[string]string{"X-API-Key": readerAPIKey})
	require.Equal(t, http.StatusOK, eventsPage.status)
	assert.NotContains(t, string(eventsPage.body), openVPNPassword)
}

func Test_Security_BodyLimit(t *testing.T) {
	t.Parallel()

	station := startStation(t)

	const maxBodyBytes = 1 << 20
	oversized := bytes.Repeat([]byte("a"), maxBodyBytes+1)
	result := station.request(t, http.MethodPost, "/v1/vpn/switch", oversized,
		map[string]string{
			"X-API-Key":    adminAPIKey,
			"Content-Type": "application/json",
		})

	require.Equal(t, http.StatusRequestEntityTooLarge, result.status)
	assert.Contains(t, string(result.body), "payload_too_large")
	assert.Equal(t, 0, station.vpn.writes(),
		"an oversized body must never touch the tunnel")
}

func Test_Security_AccessLogsScrubCredentials(t *testing.T) {
	t.Parallel()

	station := startStation(t)

	result := station.request(t, http.MethodGet,
		"/v1/vpn/state?api_key="+readerAPIKey+"&token=query-token-secret",
		nil, nil)
	require.Equal(t, http.StatusOK, result.status)

	logs := station.logger.all()
	assert.Contains(t, logs, "api_key=***")
	assert.Contains(t, logs, "token=***")
	assert.NotContains(t, logs, readerAPIKey)
	assert.NotContains(t, logs, "query-token-secret")
	for _, secret := range []string{openVPNPassword, openVPNKey, wireguardKey} {
		assert.NotContains(t, logs, secret)
	}
}

func Test_Security_EventStreamAndJournalScrubSecrets(t *testing.T) {
	t.Parallel()

	bus := events.New(events.Options{})
	t.Cleanup(bus.Close)

	published := bus.Publish(events.Event{
		Type: "security.test",
		Data: map[string]any{
			"server":        "nl-1.example.com",
			"password":      "event-password-secret",
			"authorization": "Bearer event-token-secret",
			"nested": map[string]any{
				"token": "nested-token-secret",
			},
			"endpoint": "https://user:url-secret@example.com/ip",
		},
	})

	assert.Equal(t, "nl-1.example.com", published.Data["server"])
	assert.Equal(t, "***", published.Data["password"])
	assert.Equal(t, "***", published.Data["authorization"])
	nested, ok := published.Data["nested"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "***", nested["token"])
	assert.Equal(t, "https://***@example.com/ip", published.Data["endpoint"])

	var stream bytes.Buffer
	err := events.WriteEvent(&stream, published)
	require.NoError(t, err)
	for _, secret := range []string{
		"event-password-secret",
		"event-token-secret",
		"nested-token-secret",
		"url-secret",
	} {
		assert.NotContains(t, stream.String(), secret)
	}

	directory := t.TempDir()
	log := events.NewFileLog(directory, events.DefaultLogMaxBytes,
		events.DefaultLogMaxFiles)
	require.NoError(t, log.Append(published))

	loaded, _, err := log.Load(0)
	require.NoError(t, err)
	require.Len(t, loaded, 1)
	assert.Equal(t, "***", loaded[0].Data["password"])
	assert.Equal(t, published, loaded[0])

	raw, err := os.ReadFile(filepath.Join(directory, "events.jsonl"))
	require.NoError(t, err)
	for _, secret := range []string{
		"event-password-secret",
		"event-token-secret",
		"nested-token-secret",
		"url-secret",
	} {
		assert.NotContains(t, string(raw), secret)
	}
}

func Test_Security_StateFilePermissions(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "control")
	store := state.New(directory)

	desired := state.DesiredState{
		SchemaVersion: state.SchemaVersion,
		StationID:     "station-test",
		UpdatedAt:     time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC),
		Mode:          state.ModeState,
		Desired: state.TunnelSettings{
			Provider:  "nordvpn",
			VPN:       "openvpn",
			Hostnames: []string{"nl-1.example.com"},
			Env: map[string]string{
				"VPN_PASSWORD": "env:VPN_PASSWORD",
				"VPN_USER":     "env:VPN_USER",
			},
		},
	}
	require.NoError(t, store.Save(desired))

	loaded, found, err := store.Load()
	require.NoError(t, err)
	require.True(t, found)
	assert.Equal(t, desired.Desired, loaded.Desired)

	if runtime.GOOS != "windows" {
		fileInfo, err := os.Stat(filepath.Join(directory, "state.json"))
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), fileInfo.Mode().Perm())

		directoryInfo, err := os.Stat(directory)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o700), directoryInfo.Mode().Perm())
	}

	raw, err := os.ReadFile(filepath.Join(directory, "state.json"))
	require.NoError(t, err)
	assert.Contains(t, string(raw), "env:VPN_PASSWORD",
		"state must persist environment references, not secret values")
	for _, secret := range []string{openVPNPassword, openVPNKey, wireguardKey} {
		assert.NotContains(t, string(raw), secret)
	}
}

func Test_Security_ErrorBodyNeverEchoesSecrets(t *testing.T) {
	t.Parallel()

	station := startStation(t)

	body, err := json.Marshal(map[string]any{
		"password": openVPNPassword,
		"unknown":  "value",
	})
	require.NoError(t, err)

	result := station.request(t, http.MethodPut, "/v1/vpn/settings", body,
		map[string]string{
			"X-API-Key":    adminAPIKey,
			"Content-Type": "application/json",
		})
	require.Equal(t, http.StatusBadRequest, result.status)
	assert.NotContains(t, string(result.body), openVPNPassword)
}
