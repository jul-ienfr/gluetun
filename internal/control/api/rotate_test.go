package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/control/jobs"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ParseRotateRequest(t *testing.T) {
	t.Parallel()

	body := `{
		"candidates": [
			{"hostname": "nl-1234.nordvpn.com"},
			{"hostname": " nl-5678.nordvpn.com ", "endpoint_ip": "203.0.113.10"},
			{"hostname": "nl-9012.nordvpn.com", "expected_egress_ip": "198.51.100.9"}
		],
		"constraints": {
			"require_new_ip": true,
			"require_new_subnet": true,
			"exclude_hostnames": ["nl-9999.nordvpn.com"],
			"exclude_ips": ["198.51.100.8"],
			"exclude_subnets": ["198.51.100.0/24"],
			"forbidden_ips": ["192.0.2.1"],
			"max_candidates": 7,
			"max_attempts": 5
		},
		"options": {
			"timeout_s": 30,
			"transport_policy": ["wireguard", "openvpn-udp", "openvpn-tcp"],
			"verify": {"quorum": 2, "min_sources": 3, "canary": true}
		},
		"idempotency_key": "rotate-s2-1731"
	}`

	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/vpn/rotate", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	parsed, err := parseRotateRequest(response, request)
	require.NoError(t, err)

	require.Len(t, parsed.Candidates, 3)
	assert.Equal(t, "nl-1234.nordvpn.com", parsed.Candidates[0].Hostname)
	assert.Equal(t, "nl-5678.nordvpn.com", parsed.Candidates[1].Hostname)
	assert.Equal(t, "203.0.113.10", parsed.Candidates[1].EndpointIP.String())
	assert.Equal(t, "198.51.100.9",
		parsed.Candidates[2].ExpectedEgressIP.String())

	assert.Nil(t, parsed.Policy)
	assert.True(t, parsed.Constraints.RequireNewIP)
	assert.True(t, parsed.Constraints.RequireNewSubnet)
	assert.Equal(t, []string{"nl-9999.nordvpn.com"},
		parsed.Constraints.ExcludeHostnames)
	assert.Len(t, parsed.Constraints.ExcludeIPs, 1)
	assert.Len(t, parsed.Constraints.ExcludeSubnets, 1)
	assert.Len(t, parsed.Constraints.ForbiddenIPs, 1)
	assert.Equal(t, 7, parsed.Constraints.MaxCandidates)
	assert.Equal(t, 5, parsed.Constraints.MaxAttempts)

	assert.Equal(t, []jobs.Transport{
		jobs.TransportWireGuard,
		jobs.TransportOpenVPNUDP,
		jobs.TransportOpenVPNTCP,
	}, parsed.Options.TransportPolicy)
	assert.Equal(t, 2, parsed.Options.Verify.Quorum)
	assert.Equal(t, 3, parsed.Options.Verify.MinSources)
	require.NotNil(t, parsed.Options.Verify.Canary)
	assert.True(t, *parsed.Options.Verify.Canary)
	assert.Equal(t, "rotate-s2-1731", parsed.IdempotencyKey)
	assert.NotEmpty(t, parsed.RequestHash)
}

func Test_ParseRotateRequest_Policy(t *testing.T) {
	t.Parallel()

	body := `{
		"policy": {
			"countries": ["Netherlands"],
			"cities": ["Amsterdam"],
			"categories": ["standard"],
			"tiers": ["free"],
			"free_only": true,
			"mode": "ordered"
		}
	}`

	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/vpn/rotate", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	parsed, err := parseRotateRequest(response, request)
	require.NoError(t, err)

	require.NotNil(t, parsed.Policy)
	assert.Equal(t, []string{"Netherlands"}, parsed.Policy.Countries)
	assert.Equal(t, []string{"Amsterdam"}, parsed.Policy.Cities)
	assert.Equal(t, []string{"standard"}, parsed.Policy.Categories)
	assert.Equal(t, []string{"free"}, parsed.Policy.Tiers)
	assert.True(t, parsed.Policy.FreeOnly)
	assert.Equal(t, "ordered", parsed.Policy.Mode)
	assert.Empty(t, parsed.Candidates)
}

func Test_Handler_Rotate(t *testing.T) {
	t.Parallel()

	queued := jobs.Job{ID: "job-1", Kind: jobs.KindRotate, State: jobs.StateQueued}
	committed := jobs.Job{ID: "job-1", Kind: jobs.KindRotate, State: jobs.StateCommitted}
	unusedRotate := func(t *testing.T) func(ctx context.Context, request jobs.RotationRequest) (jobs.Submission, error) {
		t.Helper()
		return func(_ context.Context, _ jobs.RotationRequest) (jobs.Submission, error) {
			require.FailNow(t, "SubmitRotation should not be called")
			return jobs.Submission{}, nil
		}
	}

	testCases := map[string]struct {
		body     string
		service  func(t *testing.T) JobsService
		status   int
		code     string
		location string
		state    string
	}{
		"accepted": {
			body: `{"candidates":[{"hostname":"nl-1234.nordvpn.com"}]}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					rotateFunc: func(_ context.Context, request jobs.RotationRequest) (jobs.Submission, error) {
						assert.Len(t, request.Candidates, 1)
						return jobs.Submission{Job: queued}, nil
					},
				}
			},
			status:   http.StatusAccepted,
			location: "/v1/vpn/jobs/job-1",
			state:    "queued",
		},
		"wait committed": {
			body: `{"candidates":[{"hostname":"nl-1234.nordvpn.com"}],"options":{"wait":true}}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					rotateFunc: func(_ context.Context, _ jobs.RotationRequest) (jobs.Submission, error) {
						return jobs.Submission{Job: queued}, nil
					},
					waitFunc: func(_ context.Context, _ string) (jobs.Job, error) {
						return committed, nil
					},
				}
			},
			status:   http.StatusOK,
			location: "/v1/vpn/jobs/job-1",
			state:    "committed",
		},
		"replayed": {
			body: `{"candidates":[{"hostname":"nl-1234.nordvpn.com"}],"idempotency_key":"rotate-1"}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					rotateFunc: func(_ context.Context, _ jobs.RotationRequest) (jobs.Submission, error) {
						return jobs.Submission{Job: committed, Replayed: true}, nil
					},
				}
			},
			status:   http.StatusOK,
			location: "/v1/vpn/jobs/job-1",
			state:    "committed",
		},
		"noop": {
			body: `{"candidates":[{"hostname":"nl-1234.nordvpn.com"}]}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					rotateFunc: func(_ context.Context, _ jobs.RotationRequest) (jobs.Submission, error) {
						return jobs.Submission{Noop: true}, nil
					},
				}
			},
			status: http.StatusOK,
			state:  "noop",
		},
		"ordered candidates passed": {
			body: `{"candidates":[{"hostname":"c.example.com"},{"hostname":"a.example.com"},{"hostname":"b.example.com"}]}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					rotateFunc: func(_ context.Context, request jobs.RotationRequest) (jobs.Submission, error) {
						hostnames := make([]string, len(request.Candidates))
						for index, candidate := range request.Candidates {
							hostnames[index] = candidate.Hostname
						}
						assert.Equal(t,
							[]string{"c.example.com", "a.example.com", "b.example.com"},
							hostnames)
						return jobs.Submission{Job: queued}, nil
					},
				}
			},
			status:   http.StatusAccepted,
			location: "/v1/vpn/jobs/job-1",
			state:    "queued",
		},
		"candidates and policy exclusive": {
			body: `{"candidates":[{"hostname":"nl-1234.nordvpn.com"}],"policy":{"countries":["Netherlands"]}}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					rotateFunc: func(_ context.Context, _ jobs.RotationRequest) (jobs.Submission, error) {
						return jobs.Submission{}, jobs.ErrInvalidTarget
					},
				}
			},
			status: http.StatusUnprocessableEntity,
			code:   CodeInvalidTarget,
		},
		"no candidates": {
			body: `{"candidates":[]}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					rotateFunc: func(_ context.Context, _ jobs.RotationRequest) (jobs.Submission, error) {
						return jobs.Submission{}, jobs.ErrNoCandidates
					},
				}
			},
			status: http.StatusUnprocessableEntity,
			code:   CodeInvalidTarget,
		},
		"active job": {
			body: `{"candidates":[{"hostname":"nl-1234.nordvpn.com"}]}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					rotateFunc: func(_ context.Context, _ jobs.RotationRequest) (jobs.Submission, error) {
						return jobs.Submission{}, &jobs.ActiveJobError{ID: "job-0"}
					},
				}
			},
			status: http.StatusConflict,
			code:   CodeActiveJob,
		},
		"dry run unsupported": {
			body:    `{"candidates":[{"hostname":"nl-1234.nordvpn.com"}],"options":{"dry_run":true}}`,
			service: func(_ *testing.T) JobsService { return fakeJobs{} },
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
		"supersede unsupported": {
			body:    `{"candidates":[{"hostname":"nl-1234.nordvpn.com"}],"options":{"supersede":true}}`,
			service: func(_ *testing.T) JobsService { return fakeJobs{} },
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
		"malformed body": {
			body:    `{"candidates":`,
			service: func(_ *testing.T) JobsService { return fakeJobs{} },
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
		"malformed endpoint IP": {
			body:    `{"candidates":[{"hostname":"nl-1234.nordvpn.com","endpoint_ip":"nope"}]}`,
			service: func(_ *testing.T) JobsService { return fakeJobs{} },
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
		"non positive max candidates": {
			body:    `{"candidates":[{"hostname":"nl-1234.nordvpn.com"}],"constraints":{"max_candidates":0}}`,
			service: func(_ *testing.T) JobsService { return fakeJobs{} },
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
		"not ready": {
			body:    `{"candidates":[{"hostname":"nl-1234.nordvpn.com"}]}`,
			service: func(_ *testing.T) JobsService { return nil },
			status:  http.StatusServiceUnavailable,
			code:    CodeNotReady,
		},
		"unused rotate": {
			body: `{"candidates":[{"hostname":"nl-1234.nordvpn.com"}],"options":{"dry_run":true}}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{rotateFunc: unusedRotate(t)}
			},
			status: http.StatusBadRequest,
			code:   CodeInvalidRequest,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := serveRotateRequest(t, testCase.service(t), testCase.body)

			assert.Equal(t, testCase.status, response.Code)
			if testCase.location != "" {
				assert.Equal(t, testCase.location,
					response.Header().Get("Location"))
			}
			if testCase.code != "" {
				assert.Equal(t, testCase.code,
					decodeError(t, response).Code)
				return
			}
			var body map[string]any
			require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
			if testCase.state != "" {
				assert.Equal(t, testCase.state, body["state"])
			}
		})
	}
}

func serveRotateRequest(t *testing.T, service JobsService,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()

	handler := New(settings.Control{}, models.BuildInformation{}, "station", nil,
		service)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/vpn/rotate", strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
