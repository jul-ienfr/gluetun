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

func Test_IsControlledSettingsBody(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		body     string
		expected bool
	}{
		"empty":            {body: "", expected: false},
		"malformed":        {body: `{"target":`, expected: false},
		"array":            {body: `[]`, expected: false},
		"legacy":           {body: `{"type":"openvpn","openvpn":{"protocol":"udp"}}`, expected: false},
		"target":           {body: `{"target":{"hostname":"new.example.com"}}`, expected: true},
		"dry run":          {body: `{"dry_run":true}`, expected: true},
		"wait":             {body: `{"wait":true}`, expected: true},
		"require verified": {body: `{"require_verified":true}`, expected: true},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, testCase.expected,
				IsControlledSettingsBody([]byte(testCase.body)))
		})
	}
}

func serveSettings(t *testing.T, service JobsService, body string,
	contentType string,
) *httptest.ResponseRecorder {
	t.Helper()

	handler := New(settings.Control{}, models.BuildInformation{}, "station", nil,
		service)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodPut,
		"/vpn/settings", strings.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response := httptest.NewRecorder()
	handler.ServeSettings(response, request)
	return response
}

func Test_Handler_ServeSettings(t *testing.T) {
	t.Parallel()

	queued := jobs.Job{ID: "job-1", Kind: jobs.KindSwitch, State: jobs.StateQueued}
	committed := jobs.Job{ID: "job-1", Kind: jobs.KindSwitch, State: jobs.StateCommitted}
	unusedSubmit := func(t *testing.T) func(context.Context, jobs.SwitchRequest) (jobs.Submission, error) {
		t.Helper()
		return func(context.Context, jobs.SwitchRequest) (jobs.Submission, error) {
			require.FailNow(t, "Submit should not be called")
			return jobs.Submission{}, nil
		}
	}

	testCases := map[string]struct {
		body        string
		contentType string
		service     func(t *testing.T) JobsService
		status      int
		code        string
		location    string
		state       string
	}{
		"not ready": {
			body:        `{"target":{"hostname":"new.example.com"}}`,
			contentType: "application/json",
			service:     func(*testing.T) JobsService { return nil },
			status:      http.StatusServiceUnavailable,
			code:        CodeNotReady,
		},
		"unsupported media type": {
			body:        `{"target":{"hostname":"new.example.com"}}`,
			contentType: "text/plain",
			service:     func(*testing.T) JobsService { return fakeJobs{} },
			status:      http.StatusUnsupportedMediaType,
			code:        CodeUnsupportedMedia,
		},
		"legacy body rejected": {
			body:        `{"type":"openvpn"}`,
			contentType: "application/json",
			service:     func(*testing.T) JobsService { return fakeJobs{} },
			status:      http.StatusBadRequest,
			code:        CodeInvalidRequest,
		},
		"missing target": {
			body:        `{"dry_run":true}`,
			contentType: "application/json",
			service:     func(*testing.T) JobsService { return fakeJobs{} },
			status:      http.StatusBadRequest,
			code:        CodeMissingField,
		},
		"empty hostname": {
			body:        `{"target":{"hostname":"  "}}`,
			contentType: "application/json",
			service:     func(*testing.T) JobsService { return fakeJobs{} },
			status:      http.StatusBadRequest,
			code:        CodeMissingField,
		},
		"malformed endpoint IP": {
			body:        `{"target":{"hostname":"new.example.com","endpoint_ip":"nope"}}`,
			contentType: "application/json",
			service:     func(*testing.T) JobsService { return fakeJobs{} },
			status:      http.StatusBadRequest,
			code:        CodeInvalidRequest,
		},
		"bad timeout": {
			body:        `{"target":{"hostname":"new.example.com"},"timeout_s":0}`,
			contentType: "application/json",
			service:     func(*testing.T) JobsService { return fakeJobs{} },
			status:      http.StatusBadRequest,
			code:        CodeInvalidRequest,
		},
		"accepted": {
			body:        `{"target":{"hostname":"new.example.com"}}`,
			contentType: "application/json",
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: func(_ context.Context, request jobs.SwitchRequest) (jobs.Submission, error) {
						assert.Equal(t, "new.example.com", request.Target.Hostname)
						assert.False(t, request.Options.DryRun)
						return jobs.Submission{Job: queued}, nil
					},
				}
			},
			status:   http.StatusAccepted,
			location: "/v1/vpn/jobs/job-1",
			state:    "queued",
		},
		"wait committed": {
			body:        `{"target":{"hostname":"new.example.com"},"wait":true}`,
			contentType: "application/json",
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: func(context.Context, jobs.SwitchRequest) (jobs.Submission, error) {
						return jobs.Submission{Job: queued}, nil
					},
					waitFunc: func(context.Context, string) (jobs.Job, error) {
						return committed, nil
					},
				}
			},
			status:   http.StatusOK,
			location: "/v1/vpn/jobs/job-1",
			state:    "committed",
		},
		"replayed": {
			body:        `{"target":{"hostname":"new.example.com"}}`,
			contentType: "application/json",
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: func(context.Context, jobs.SwitchRequest) (jobs.Submission, error) {
						return jobs.Submission{Job: committed, Replayed: true}, nil
					},
				}
			},
			status:   http.StatusOK,
			location: "/v1/vpn/jobs/job-1",
			state:    "committed",
		},
		"noop": {
			body:        `{"target":{"hostname":"new.example.com"}}`,
			contentType: "application/json",
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: func(context.Context, jobs.SwitchRequest) (jobs.Submission, error) {
						return jobs.Submission{Noop: true}, nil
					},
				}
			},
			status: http.StatusOK,
			state:  "noop",
		},
		"dry run": {
			body:        `{"target":{"hostname":"new.example.com"},"dry_run":true}`,
			contentType: "application/json",
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: unusedSubmit(t),
					planFunc: func(context.Context, jobs.SwitchRequest) (jobs.PlanResult, error) {
						return jobs.PlanResult{
							Plan: jobs.Plan{
								Transport: jobs.TransportWireGuard,
							},
							WouldCutTunnel: true,
						}, nil
					},
				}
			},
			status: http.StatusOK,
			state:  "planned",
		},
		"active job": {
			body:        `{"target":{"hostname":"new.example.com"}}`,
			contentType: "application/json",
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: func(context.Context, jobs.SwitchRequest) (jobs.Submission, error) {
						return jobs.Submission{}, &jobs.ActiveJobError{ID: "job-0"}
					},
				}
			},
			status: http.StatusConflict,
			code:   CodeActiveJob,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := serveSettings(t, testCase.service(t), testCase.body,
				testCase.contentType)

			assert.Equal(t, testCase.status, response.Code)
			if testCase.location != "" {
				assert.Equal(t, testCase.location,
					response.Header().Get("Location"))
			}
			if testCase.code != "" {
				assert.Equal(t, testCase.code, decodeError(t, response).Code)
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
