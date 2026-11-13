package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeStateService struct {
	state VPNState
}

func (f fakeStateService) VPNState() VPNState {
	return f.state
}

func Test_Handler_GetVPNState(t *testing.T) {
	t.Parallel()

	handler := testHandler()
	verifiedAt := time.Date(2026, 11, 12, 18, 10, 6, 0, time.UTC)
	handler.SetState(fakeStateService{state: VPNState{
		StationID: "vpn-gluetun-2",
		VPNStatus: "running",
		Transport: "wireguard",
		Server: &VPNServerState{
			Hostname: "nl-1234.nordvpn.com",
			Country:  "Netherlands",
			City:     "Amsterdam",
		},
		EndpointIP: netip.MustParseAddr("203.0.113.10"),
		Egress: &VPNEgressState{
			Verified:   true,
			IP:         netip.MustParseAddr("198.51.100.7"),
			Quorum:     2,
			VerifiedAt: verifiedAt,
		},
		DNS: &VPNDNSState{
			Ladder:     []string{"dot", "plain"},
			ActiveTier: "dot",
			FailClosed: false,
		},
		Desired: &VPNDesiredState{
			Hostname:  "nl-1234.nordvpn.com",
			Transport: "wireguard",
		},
		LastCommitted: &VPNCommittedState{
			JobID: "job-1",
			At:    verifiedAt,
		},
		StateMode: "state",
		UpdatedAt: verifiedAt,
	}})

	request := httptest.NewRequest(http.MethodGet, "/vpn/state", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusOK, response.Code)

	var body VPNState
	err := json.NewDecoder(response.Body).Decode(&body)
	require.NoError(t, err)
	assert.Equal(t, "vpn-gluetun-2", body.StationID)
	assert.Equal(t, "running", body.VPNStatus)
	assert.Equal(t, "wireguard", body.Transport)
	require.NotNil(t, body.Server)
	assert.Equal(t, "Amsterdam", body.Server.City)
	assert.Equal(t, netip.MustParseAddr("203.0.113.10"), body.EndpointIP)
	require.NotNil(t, body.Egress)
	assert.True(t, body.Egress.Verified)
	assert.Equal(t, netip.MustParseAddr("198.51.100.7"), body.Egress.IP)
	require.NotNil(t, body.DNS)
	assert.Equal(t, []string{"dot", "plain"}, body.DNS.Ladder)
	require.NotNil(t, body.LastCommitted)
	assert.Equal(t, "job-1", body.LastCommitted.JobID)
	assert.Nil(t, body.ActiveJobID)
}

func Test_Handler_GetVPNState_NotReady(t *testing.T) {
	t.Parallel()

	handler := testHandler()

	request := httptest.NewRequest(http.MethodGet, "/vpn/state", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	require.Equal(t, http.StatusServiceUnavailable, response.Code)

	var body struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	err := json.NewDecoder(response.Body).Decode(&body)
	require.NoError(t, err)
	assert.Equal(t, CodeNotReady, body.Error.Code)
}
