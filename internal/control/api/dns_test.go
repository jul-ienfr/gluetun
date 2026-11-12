package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/dns/ladder"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeDNS struct {
	stateFunc func() (ladder.Snapshot, bool)
	probeFunc func(ctx context.Context, tier, domain string,
		timeout time.Duration, dryRun bool) (ladder.ProbeResult, error)
}

func (f fakeDNS) DNSState() (ladder.Snapshot, bool) { return f.stateFunc() }

func (f fakeDNS) DNSProbe(ctx context.Context, tier, domain string,
	timeout time.Duration, dryRun bool,
) (ladder.ProbeResult, error) {
	return f.probeFunc(ctx, tier, domain, timeout, dryRun)
}

func serveDNS(t *testing.T, service DNSService, method, path,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()

	handler := New(settings.Control{}, models.BuildInformation{}, "station", nil,
		nil)
	if service != nil {
		handler.SetDNS(service)
	}
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequestWithContext(t.Context(), method, path, reader)
	if method == http.MethodPost {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func Test_Handler_DNSState(t *testing.T) {
	t.Parallel()

	service := fakeDNS{
		stateFunc: func() (ladder.Snapshot, bool) {
			return ladder.Snapshot{
				Ladder:     []ladder.TierType{ladder.TierDoT, ladder.TierPlain},
				ActiveTier: ladder.TierDoT,
				Tiers: []ladder.Tier{
					{Type: ladder.TierDoT, State: ladder.StateUp},
				},
			}, true
		},
	}

	response := serveDNS(t, service, http.MethodGet, "/dns/state", "")
	require.Equal(t, http.StatusOK, response.Code)

	var snapshot ladder.Snapshot
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &snapshot))
	assert.Equal(t, ladder.TierDoT, snapshot.ActiveTier)
	assert.Len(t, snapshot.Tiers, 1)
}

func Test_Handler_DNSTiers(t *testing.T) {
	t.Parallel()

	service := fakeDNS{
		stateFunc: func() (ladder.Snapshot, bool) {
			return ladder.Snapshot{
				Ladder: []ladder.TierType{ladder.TierDoT},
				Tiers: []ladder.Tier{{
					Type:  ladder.TierDoT,
					State: ladder.StateUp,
					Endpoints: []ladder.Endpoint{
						{Address: "1.1.1.1:853", Provider: "cloudflare"},
					},
				}},
			}, true
		},
	}

	response := serveDNS(t, service, http.MethodGet, "/dns/tiers", "")
	require.Equal(t, http.StatusOK, response.Code)

	var body dnsTiersResponse
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	assert.Equal(t, []ladder.TierType{ladder.TierDoT}, body.Ladder)
	require.Len(t, body.Tiers, 1)
	require.Len(t, body.Tiers[0].Endpoints, 1)
	assert.Equal(t, "1.1.1.1:853", body.Tiers[0].Endpoints[0].Address)
}

func Test_Handler_DNSNotReady(t *testing.T) {
	t.Parallel()

	response := serveDNS(t, nil, http.MethodGet, "/dns/state", "")
	assert.Equal(t, http.StatusServiceUnavailable, response.Code)

	var body errorBody
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
	assert.Equal(t, CodeNotReady, body.Error.Code)
}

func Test_Handler_DNSProbe(t *testing.T) {
	t.Parallel()

	service := fakeDNS{
		probeFunc: func(_ context.Context, tier, domain string,
			timeout time.Duration, dryRun bool,
		) (ladder.ProbeResult, error) {
			assert.Equal(t, "dot", tier)
			assert.Equal(t, "example.com", domain)
			assert.Equal(t, 2*time.Second, timeout)
			assert.True(t, dryRun)
			return ladder.ProbeResult{
				Tier:      ladder.TierDoT,
				OK:        true,
				LatencyMS: 42,
				Rcode:     "NOERROR",
				Answers:   1,
			}, nil
		},
	}

	response := serveDNS(t, service, http.MethodPost, "/dns/probe",
		`{"tier":"dot","domain":"example.com","timeout_s":2,"dry_run":true}`)
	require.Equal(t, http.StatusOK, response.Code)

	var result ladder.ProbeResult
	require.NoError(t, json.Unmarshal(response.Body.Bytes(), &result))
	assert.True(t, result.OK)
	assert.Equal(t, int64(42), result.LatencyMS)
	assert.Equal(t, "NOERROR", result.Rcode)
}

func Test_Handler_DNSProbe_Errors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		body   string
		err    error
		status int
		code   string
	}{
		"missing tier": {
			body:   `{"domain":"example.com"}`,
			status: http.StatusBadRequest,
			code:   CodeMissingField,
		},
		"unknown tier": {
			body:   `{"tier":"dnscrypt"}`,
			err:    ladder.ErrUnknownTier,
			status: http.StatusUnprocessableEntity,
			code:   CodeInvalidTarget,
		},
		"invalid domain": {
			body:   `{"tier":"dot"}`,
			err:    errors.New("invalid probe domain"),
			status: http.StatusBadRequest,
			code:   CodeInvalidRequest,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			service := fakeDNS{
				probeFunc: func(context.Context, string, string,
					time.Duration, bool,
				) (ladder.ProbeResult, error) {
					return ladder.ProbeResult{}, testCase.err
				},
			}
			response := serveDNS(t, service, http.MethodPost, "/dns/probe",
				testCase.body)
			assert.Equal(t, testCase.status, response.Code)

			var body errorBody
			require.NoError(t, json.Unmarshal(response.Body.Bytes(), &body))
			assert.Equal(t, testCase.code, body.Error.Code)
		})
	}
}
