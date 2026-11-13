package state

import (
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testTime() time.Time {
	return time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
}

func testSettings() TunnelSettings {
	return TunnelSettings{
		Provider:  "mullvad",
		VPN:       "wireguard",
		Countries: []string{"Switzerland"},
		Env: map[string]string{
			"provider": "env:VPN_SERVICE_PROVIDER",
		},
	}
}

func testSnapshot() TunnelSnapshot {
	provenAt := testTime()
	return TunnelSnapshot{
		SchemaVersion:  SchemaVersion,
		StationID:      "station-1",
		TakenAt:        testTime(),
		Trigger:        "switch",
		Settings:       testSettings(),
		ServerHostname: "ch-1.example.com",
		EndpointIP:     netip.MustParseAddr("1.2.3.4"),
		Transport:      "wireguard",
		Interface:      "wg0",
		VPNStatus:      "running",
		ProvenAt:       &provenAt,
	}
}

func testDesiredState(t *testing.T) DesiredState {
	t.Helper()
	state, err := NewDesiredState("station-1", ModeState, testSettings(), testTime())
	require.NoError(t, err)
	return state
}

func Test_NewDesiredState(t *testing.T) {
	t.Parallel()

	state, err := NewDesiredState("station-1", ModeMerge, testSettings(), testTime())
	require.NoError(t, err)

	assert.Equal(t, SchemaVersion, state.SchemaVersion)
	assert.Equal(t, "station-1", state.StationID)
	assert.Equal(t, ModeMerge, state.Mode)
	assert.Equal(t, testTime(), state.UpdatedAt)
	assert.NotEmpty(t, state.Checksum)
	assert.NoError(t, state.Validate())

	_, err = NewDesiredState("", ModeState, testSettings(), testTime())
	assert.ErrorIs(t, err, ErrInvalidState)

	_, err = NewDesiredState("station-1", "bogus", testSettings(), testTime())
	assert.ErrorIs(t, err, ErrInvalidState)

	_, err = NewDesiredState("station-1", ModeState, testSettings(), time.Time{})
	assert.ErrorIs(t, err, ErrInvalidState)
}

func Test_DesiredStateValidateStructural(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		mutate func(*DesiredState)
	}{
		"schema version": {
			mutate: func(state *DesiredState) { state.SchemaVersion = 0 },
		},
		"empty station ID": {
			mutate: func(state *DesiredState) { state.StationID = "" },
		},
		"missing updated at": {
			mutate: func(state *DesiredState) { state.UpdatedAt = time.Time{} },
		},
		"unknown mode": {
			mutate: func(state *DesiredState) { state.Mode = "bogus" },
		},
		"missing checksum": {
			mutate: func(state *DesiredState) { state.Checksum = "" },
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			state := testDesiredState(t)
			testCase.mutate(&state)

			err := state.Validate()
			assert.ErrorIs(t, err, ErrInvalidState)
		})
	}
}

func Test_DesiredStateValidateContent(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		mutate func(*DesiredState)
	}{
		"unknown VPN": {
			mutate: func(state *DesiredState) { state.Desired.VPN = "pptp" },
		},
		"empty country": {
			mutate: func(state *DesiredState) { state.Desired.Countries = []string{" "} },
		},
		"environment reference without prefix": {
			mutate: func(state *DesiredState) {
				state.Desired.Env["provider"] = "VPN_SERVICE_PROVIDER"
			},
		},
		"empty environment reference name": {
			mutate: func(state *DesiredState) { state.Desired.Env["provider"] = "env:" },
		},
		"empty environment reference key": {
			mutate: func(state *DesiredState) { state.Desired.Env[""] = "env:X" },
		},
		"snapshot schema version": {
			mutate: func(state *DesiredState) {
				snapshot := testSnapshot()
				snapshot.SchemaVersion = 0
				state.Current = &snapshot
			},
		},
		"snapshot empty station ID": {
			mutate: func(state *DesiredState) {
				snapshot := testSnapshot()
				snapshot.StationID = ""
				state.LastCommitted = &snapshot
			},
		},
		"snapshot missing taken at": {
			mutate: func(state *DesiredState) {
				snapshot := testSnapshot()
				snapshot.TakenAt = time.Time{}
				state.Current = &snapshot
			},
		},
		"snapshot unknown trigger": {
			mutate: func(state *DesiredState) {
				snapshot := testSnapshot()
				snapshot.Trigger = "bogus"
				state.Current = &snapshot
			},
		},
		"snapshot unknown transport": {
			mutate: func(state *DesiredState) {
				snapshot := testSnapshot()
				snapshot.Transport = "bogus"
				state.Current = &snapshot
			},
		},
		"snapshot unknown transport detail": {
			mutate: func(state *DesiredState) {
				snapshot := testSnapshot()
				snapshot.TransportDetail = "bogus"
				state.Current = &snapshot
			},
		},
		"snapshot transport detail mismatch": {
			mutate: func(state *DesiredState) {
				snapshot := testSnapshot()
				snapshot.Transport = "wireguard"
				snapshot.TransportDetail = "openvpn-tcp"
				state.Current = &snapshot
			},
		},
		"snapshot unknown VPN status": {
			mutate: func(state *DesiredState) {
				snapshot := testSnapshot()
				snapshot.VPNStatus = "bogus"
				state.Current = &snapshot
			},
		},
		"snapshot private endpoint": {
			mutate: func(state *DesiredState) {
				snapshot := testSnapshot()
				snapshot.EndpointIP = netip.MustParseAddr("10.0.0.1")
				state.Current = &snapshot
			},
		},
		"snapshot cgnat endpoint": {
			mutate: func(state *DesiredState) {
				snapshot := testSnapshot()
				snapshot.EndpointIP = netip.MustParseAddr("100.64.0.1")
				state.Current = &snapshot
			},
		},
		"negative observation capacity": {
			mutate: func(state *DesiredState) { state.Observations.Capacity = -1 },
		},
		"observations exceed capacity": {
			mutate: func(state *DesiredState) {
				state.Observations = ObservationRing{
					Capacity: 1,
					Items: []egress.Observation{
						{Source: "http:a"},
						{Source: "http:b"},
					},
				}
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			state := testDesiredState(t)
			testCase.mutate(&state)

			_, err := Seal(state)
			assert.ErrorIs(t, err, ErrInvalidState)
		})
	}
}

func Test_DesiredStateValidateChecksumMismatch(t *testing.T) {
	t.Parallel()

	state := testDesiredState(t)
	state.Desired.Countries = []string{"Iceland"}

	err := state.Validate()
	assert.ErrorIs(t, err, ErrChecksumMismatch)
}

func Test_checksum(t *testing.T) {
	t.Parallel()

	state := testDesiredState(t)

	first, err := checksum(state)
	require.NoError(t, err)
	assert.Equal(t, state.Checksum, first)

	second, err := checksum(state)
	require.NoError(t, err)
	assert.Equal(t, first, second)

	changed := state
	changed.Desired.Countries = []string{"Iceland"}
	changedChecksum, err := checksum(changed)
	require.NoError(t, err)
	assert.NotEqual(t, first, changedChecksum)

	tampered := state
	tampered.Checksum = "not-a-checksum"
	reset, err := checksum(tampered)
	require.NoError(t, err)
	assert.Equal(t, first, reset)
}

func Test_TunnelSettingsEqual(t *testing.T) {
	t.Parallel()

	settings := testSettings()

	testCases := map[string]struct {
		other    TunnelSettings
		expected bool
	}{
		"identical": {
			other:    testSettings(),
			expected: true,
		},
		"different provider": {
			other: func() TunnelSettings {
				other := testSettings()
				other.Provider = "proton"
				return other
			}(),
			expected: false,
		},
		"different countries": {
			other: func() TunnelSettings {
				other := testSettings()
				other.Countries = []string{"Iceland"}
				return other
			}(),
			expected: false,
		},
		"extra environment reference": {
			other: func() TunnelSettings {
				other := testSettings()
				other.Env["city"] = "env:VPN_CITY"
				return other
			}(),
			expected: false,
		},
		"different environment reference": {
			other: func() TunnelSettings {
				other := testSettings()
				other.Env["provider"] = "env:OTHER"
				return other
			}(),
			expected: false,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.expected, settings.Equal(testCase.other))
		})
	}
}

func Test_TunnelSettingsMergedWith(t *testing.T) {
	t.Parallel()

	environment := TunnelSettings{
		Provider:  "mullvad",
		VPN:       "wireguard",
		Countries: []string{"Switzerland"},
		Cities:    []string{"Zurich"},
		Env: map[string]string{
			"provider": "env:VPN_SERVICE_PROVIDER",
			"city":     "env:VPN_CITY",
		},
	}

	testCases := map[string]struct {
		explicit TunnelSettings
		expected TunnelSettings
	}{
		"explicit values win": {
			explicit: TunnelSettings{
				Provider:  "proton",
				VPN:       "openvpn",
				Countries: []string{"Iceland"},
				Env:       map[string]string{"provider": "env:PROTON_PROVIDER"},
			},
			expected: TunnelSettings{
				Provider:  "proton",
				VPN:       "openvpn",
				Countries: []string{"Iceland"},
				Cities:    []string{"Zurich"},
				Env: map[string]string{
					"provider": "env:PROTON_PROVIDER",
					"city":     "env:VPN_CITY",
				},
			},
		},
		"empty explicit slice wins": {
			explicit: TunnelSettings{
				Countries: []string{},
			},
			expected: TunnelSettings{
				Provider:  "mullvad",
				VPN:       "wireguard",
				Countries: []string{},
				Cities:    []string{"Zurich"},
				Env: map[string]string{
					"provider": "env:VPN_SERVICE_PROVIDER",
					"city":     "env:VPN_CITY",
				},
			},
		},
		"empty explicit settings fall back": {
			explicit: TunnelSettings{},
			expected: environment,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			merged := testCase.explicit.mergedWith(environment)
			assert.True(t, merged.Equal(testCase.expected))
		})
	}
}

func Test_TunnelSnapshot_TransportDetailValid(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		transport string
		detail    string
	}{
		"openvpn udp":            {transport: "openvpn", detail: "openvpn-udp"},
		"openvpn tcp":            {transport: "openvpn", detail: "openvpn-tcp"},
		"wireguard":              {transport: "wireguard", detail: "wireguard"},
		"openvpn without detail": {transport: "openvpn"},
		"empty":                  {},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			snapshot := testSnapshot()
			snapshot.Transport = testCase.transport
			snapshot.TransportDetail = testCase.detail

			state := testDesiredState(t)
			state.Current = &snapshot
			sealed, err := Seal(state)
			require.NoError(t, err)
			assert.NoError(t, sealed.Validate())
		})
	}
}
