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

type fakeJobs struct {
	submitFunc   func(ctx context.Context, request jobs.SwitchRequest) (jobs.Submission, error)
	planFunc     func(ctx context.Context, request jobs.SwitchRequest) (jobs.PlanResult, error)
	rotateFunc   func(ctx context.Context, request jobs.RotationRequest) (jobs.Submission, error)
	rollbackFunc func(ctx context.Context, request jobs.RollbackRequest) (jobs.Submission, error)
	getFunc      func(id string) (jobs.Job, bool)
	listFunc     func(filter jobs.Filter) (jobs.Page, error)
	cancelFunc   func(id string) (jobs.Job, error)
	waitFunc     func(ctx context.Context, id string) (jobs.Job, error)
}

func (f fakeJobs) Submit(ctx context.Context, request jobs.SwitchRequest) (jobs.Submission, error) {
	return f.submitFunc(ctx, request)
}

func (f fakeJobs) Plan(ctx context.Context, request jobs.SwitchRequest) (jobs.PlanResult, error) {
	return f.planFunc(ctx, request)
}

func (f fakeJobs) SubmitRotation(ctx context.Context, request jobs.RotationRequest) (jobs.Submission, error) {
	return f.rotateFunc(ctx, request)
}

func (f fakeJobs) SubmitRollback(ctx context.Context, request jobs.RollbackRequest) (jobs.Submission, error) {
	return f.rollbackFunc(ctx, request)
}

func (f fakeJobs) Get(id string) (jobs.Job, bool) {
	return f.getFunc(id)
}

func (f fakeJobs) List(filter jobs.Filter) (jobs.Page, error) {
	return f.listFunc(filter)
}

func (f fakeJobs) Cancel(id string) (jobs.Job, error) {
	return f.cancelFunc(id)
}

func (f fakeJobs) Wait(ctx context.Context, id string) (jobs.Job, error) {
	return f.waitFunc(ctx, id)
}

func serveJobRequest(t *testing.T, service JobsService, method, path,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()

	handler := New(settings.Control{}, models.BuildInformation{}, "station", nil,
		service)
	request := httptest.NewRequestWithContext(t.Context(), method, path,
		strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func decodeError(t *testing.T, response *httptest.ResponseRecorder) errorDetail {
	t.Helper()
	var body errorBody
	require.NoError(t, json.NewDecoder(response.Body).Decode(&body))
	return body.Error
}

func Test_Handler_Switch(t *testing.T) {
	t.Parallel()

	queued := jobs.Job{ID: "job-1", Kind: jobs.KindSwitch, State: jobs.StateQueued}
	committed := jobs.Job{ID: "job-1", Kind: jobs.KindSwitch, State: jobs.StateCommitted}
	unusedSubmit := func(t *testing.T) func(ctx context.Context, request jobs.SwitchRequest) (jobs.Submission, error) {
		t.Helper()
		return func(_ context.Context, _ jobs.SwitchRequest) (jobs.Submission, error) {
			require.FailNow(t, "Submit should not be called")
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
			body: `{"target":{"hostname":"new.example.com"}}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: func(_ context.Context, _ jobs.SwitchRequest) (jobs.Submission, error) {
						return jobs.Submission{Job: queued}, nil
					},
				}
			},
			status:   http.StatusAccepted,
			location: "/v1/vpn/jobs/job-1",
			state:    "queued",
		},
		"wait committed": {
			body: `{"target":{"hostname":"new.example.com"},"options":{"wait":true}}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: func(_ context.Context, _ jobs.SwitchRequest) (jobs.Submission, error) {
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
			body: `{"target":{"hostname":"new.example.com"},"idempotency_key":"switch-1"}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: func(_ context.Context, _ jobs.SwitchRequest) (jobs.Submission, error) {
						return jobs.Submission{Job: committed, Replayed: true}, nil
					},
				}
			},
			status:   http.StatusOK,
			location: "/v1/vpn/jobs/job-1",
			state:    "committed",
		},
		"noop": {
			body: `{"target":{"hostname":"new.example.com"}}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: func(_ context.Context, _ jobs.SwitchRequest) (jobs.Submission, error) {
						return jobs.Submission{Noop: true}, nil
					},
				}
			},
			status: http.StatusOK,
			state:  "noop",
		},
		"dry run": {
			body: `{"target":{"hostname":"new.example.com"},"options":{"dry_run":true}}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: unusedSubmit(t),
					planFunc: func(_ context.Context, _ jobs.SwitchRequest) (jobs.PlanResult, error) {
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
			body: `{"target":{"hostname":"new.example.com"}}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: func(_ context.Context, _ jobs.SwitchRequest) (jobs.Submission, error) {
						return jobs.Submission{}, &jobs.ActiveJobError{ID: "job-0"}
					},
				}
			},
			status: http.StatusConflict,
			code:   CodeActiveJob,
		},
		"idempotency conflict": {
			body: `{"target":{"hostname":"new.example.com"},"idempotency_key":"switch-1"}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: func(_ context.Context, _ jobs.SwitchRequest) (jobs.Submission, error) {
						return jobs.Submission{}, jobs.ErrIdempotencyConflict
					},
				}
			},
			status: http.StatusConflict,
			code:   CodeIdempotencyConflict,
		},
		"unknown target": {
			body: `{"target":{"hostname":"missing.example.com"}}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: func(_ context.Context, _ jobs.SwitchRequest) (jobs.Submission, error) {
						return jobs.Submission{}, jobs.ErrUnknownTarget
					},
				}
			},
			status: http.StatusUnprocessableEntity,
			code:   CodeUnknownTarget,
		},
		"invalid target": {
			body: `{"target":{"hostname":"new.example.com"}}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					submitFunc: func(_ context.Context, _ jobs.SwitchRequest) (jobs.Submission, error) {
						return jobs.Submission{}, jobs.ErrTargetExcluded
					},
				}
			},
			status: http.StatusUnprocessableEntity,
			code:   CodeInvalidTarget,
		},
		"malformed body": {
			body:    `{"target":`,
			service: func(_ *testing.T) JobsService { return fakeJobs{} },
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
		"malformed endpoint IP": {
			body:    `{"target":{"hostname":"new.example.com","endpoint_ip":"nope"}}`,
			service: func(_ *testing.T) JobsService { return fakeJobs{} },
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
		"supersede unsupported": {
			body:    `{"target":{"hostname":"new.example.com"},"options":{"supersede":true}}`,
			service: func(_ *testing.T) JobsService { return fakeJobs{} },
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := serveJobRequest(t, testCase.service(t),
				http.MethodPost, "/vpn/switch", testCase.body)

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

func Test_Handler_Jobs(t *testing.T) {
	t.Parallel()

	job := jobs.Job{ID: "job-1", Kind: jobs.KindSwitch, State: jobs.StateCommitted}

	testCases := map[string]struct {
		method  string
		path    string
		body    string
		service func(t *testing.T) JobsService
		status  int
		code    string
		check   func(t *testing.T, body []byte)
	}{
		"list": {
			method: http.MethodGet,
			path:   "/vpn/jobs?limit=1",
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					listFunc: func(filter jobs.Filter) (jobs.Page, error) {
						assert.Equal(t, 1, filter.Limit)
						return jobs.Page{
							Jobs:       []jobs.Job{job},
							NextCursor: "job-1",
						}, nil
					},
				}
			},
			status: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var response jobsListResponse
				require.NoError(t, json.Unmarshal(body, &response))
				assert.Len(t, response.Jobs, 1)
				assert.Equal(t, "job-1", response.NextCursor)
			},
		},
		"list invalid state": {
			method: http.MethodGet,
			path:   "/vpn/jobs?state=nope",
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					listFunc: func(_ jobs.Filter) (jobs.Page, error) {
						return jobs.Page{}, jobs.ErrInvalidTarget
					},
				}
			},
			status: http.StatusUnprocessableEntity,
			code:   CodeInvalidTarget,
		},
		"get": {
			method: http.MethodGet,
			path:   "/vpn/jobs/job-1",
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					getFunc: func(id string) (jobs.Job, bool) {
						return job, id == "job-1"
					},
				}
			},
			status: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var decoded jobs.Job
				require.NoError(t, json.Unmarshal(body, &decoded))
				assert.Equal(t, "job-1", decoded.ID)
			},
		},
		"get missing": {
			method: http.MethodGet,
			path:   "/vpn/jobs/job-2",
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					getFunc: func(string) (jobs.Job, bool) {
						return jobs.Job{}, false
					},
				}
			},
			status: http.StatusNotFound,
			code:   CodeNotFound,
		},
		"cancel": {
			method: http.MethodPost,
			path:   "/vpn/jobs/job-1/cancel",
			body:   `{}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					cancelFunc: func(string) (jobs.Job, error) {
						canceled := job
						canceled.State = jobs.StateCanceled
						return canceled, nil
					},
				}
			},
			status: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var decoded jobs.Job
				require.NoError(t, json.Unmarshal(body, &decoded))
				assert.Equal(t, jobs.StateCanceled, decoded.State)
			},
		},
		"rollback no snapshot": {
			method: http.MethodPost,
			path:   "/vpn/rollback",
			body:   `{}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					rollbackFunc: func(_ context.Context, _ jobs.RollbackRequest) (jobs.Submission, error) {
						return jobs.Submission{}, jobs.ErrNoSnapshot
					},
				}
			},
			status: http.StatusConflict,
			code:   CodeNoSnapshot,
		},
		"rollback accepted": {
			method: http.MethodPost,
			path:   "/vpn/rollback",
			body:   `{"to":"last_committed"}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{
					rollbackFunc: func(_ context.Context, _ jobs.RollbackRequest) (jobs.Submission, error) {
						return jobs.Submission{Job: jobs.Job{
							ID:    "job-2",
							Kind:  jobs.KindRollback,
							State: jobs.StateQueued,
						}}, nil
					},
				}
			},
			status: http.StatusAccepted,
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var decoded jobs.Job
				require.NoError(t, json.Unmarshal(body, &decoded))
				assert.Equal(t, jobs.KindRollback, decoded.Kind)
			},
		},
		"rollback explicit snapshot unsupported": {
			method: http.MethodPost,
			path:   "/vpn/rollback",
			body:   `{"to":"snap-1"}`,
			service: func(t *testing.T) JobsService {
				t.Helper()
				return fakeJobs{}
			},
			status: http.StatusUnprocessableEntity,
			code:   CodeInvalidTarget,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := serveJobRequest(t, testCase.service(t),
				testCase.method, testCase.path, testCase.body)

			assert.Equal(t, testCase.status, response.Code)
			if testCase.code != "" {
				assert.Equal(t, testCase.code,
					decodeError(t, response).Code)
				return
			}
			if testCase.check != nil {
				testCase.check(t, response.Body.Bytes())
			}
		})
	}
}
