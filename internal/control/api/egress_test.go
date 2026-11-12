package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/verify"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeEgress struct {
	verifyFunc  func(ctx context.Context, request verify.Request) (egress.Verification, error)
	historyFunc func(limit int, since time.Time) (verifications []egress.Verification)
	canaryFunc  func(ctx context.Context) (result egress.CanaryResult, err error)
}

func (f fakeEgress) Verify(ctx context.Context, request verify.Request) (
	verification egress.Verification, err error,
) {
	return f.verifyFunc(ctx, request)
}

func (f fakeEgress) History(limit int, since time.Time) (
	verifications []egress.Verification,
) {
	return f.historyFunc(limit, since)
}

func (f fakeEgress) CheckCanary(ctx context.Context) (
	result egress.CanaryResult, err error,
) {
	return f.canaryFunc(ctx)
}

func serveEgress(t *testing.T, service EgressService, path string) *httptest.ResponseRecorder {
	t.Helper()

	handler := New(settings.Control{}, models.BuildInformation{}, "station", service, nil)
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func Test_Handler_Egress(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	verified := egress.Verification{
		Verified:     true,
		IP:           netip.MustParseAddr("203.0.113.7"),
		Family:       4,
		Quorum:       2,
		SourceCount:  3,
		Confidence:   egress.ConfidenceHigh,
		Dissenters:   []string{},
		VerifiedAt:   now,
		TTLS:         10,
		Observations: []egress.Observation{},
	}
	insufficientReason := egress.ReasonInsufficientSources
	insufficient := egress.Verification{
		Verified:    false,
		Family:      4,
		SourceCount: 1,
		Dissenters:  []string{},
		VerifiedAt:  now,
		TTLS:        10,
		Reason:      &insufficientReason,
	}
	unexpected := func(t *testing.T) EgressService {
		t.Helper()
		return fakeEgress{
			verifyFunc: func(_ context.Context, _ verify.Request) (egress.Verification, error) {
				require.FailNow(t, "Verify should not be called")
				return egress.Verification{}, nil
			},
		}
	}

	testCases := map[string]struct {
		path    string
		service func(t *testing.T) EgressService
		status  int
		code    string
		check   func(t *testing.T, body []byte)
	}{
		"cached_result": {
			path: "/egress",
			service: func(t *testing.T) EgressService {
				t.Helper()
				return fakeEgress{
					verifyFunc: func(_ context.Context, request verify.Request) (
						egress.Verification, error,
					) {
						assert.False(t, request.Fresh)
						return verified, nil
					},
				}
			},
			status: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var verification egress.Verification
				err := json.Unmarshal(body, &verification)
				require.NoError(t, err)
				assert.True(t, verification.Verified)
				assert.Equal(t, "203.0.113.7", verification.IP.String())
				assert.Equal(t, 10, verification.TTLS)
			},
		},
		"verify_overrides": {
			path: "/egress/verify?fresh=true&quorum=3&min_sources=4" +
				"&canary=false&timeout_s=5",
			service: func(t *testing.T) EgressService {
				t.Helper()
				return fakeEgress{
					verifyFunc: func(_ context.Context, request verify.Request) (
						egress.Verification, error,
					) {
						assert.True(t, request.Fresh)
						assert.Equal(t, 3, request.Quorum)
						assert.Equal(t, 4, request.MinSources)
						require.NotNil(t, request.Canary)
						assert.False(t, *request.Canary)
						assert.Equal(t, 5*time.Second, request.Timeout)
						return verified, nil
					},
				}
			},
			status: http.StatusOK,
			check: func(t *testing.T, _ []byte) {
				t.Helper()
			},
		},
		"verify_defaults_to_fresh": {
			path: "/egress/verify",
			service: func(t *testing.T) EgressService {
				t.Helper()
				return fakeEgress{
					verifyFunc: func(_ context.Context, request verify.Request) (
						egress.Verification, error,
					) {
						assert.True(t, request.Fresh)
						assert.Zero(t, request.Quorum)
						assert.Zero(t, request.MinSources)
						assert.Nil(t, request.Canary)
						assert.Zero(t, request.Timeout)
						return verified, nil
					},
				}
			},
			status: http.StatusOK,
			check: func(t *testing.T, _ []byte) {
				t.Helper()
			},
		},
		"insufficient_sources": {
			path: "/egress/verify",
			service: func(t *testing.T) EgressService {
				t.Helper()
				return fakeEgress{
					verifyFunc: func(_ context.Context, _ verify.Request) (
						egress.Verification, error,
					) {
						return insufficient, nil
					},
				}
			},
			status: http.StatusUnprocessableEntity,
			code:   CodeInsufficientSources,
		},
		"timeout": {
			path: "/egress/verify",
			service: func(t *testing.T) EgressService {
				t.Helper()
				return fakeEgress{
					verifyFunc: func(_ context.Context, _ verify.Request) (
						egress.Verification, error,
					) {
						return egress.Verification{}, verify.ErrTimeout
					},
				}
			},
			status: http.StatusServiceUnavailable,
			code:   CodeNotReady,
		},
		"internal_error": {
			path: "/egress/verify",
			service: func(t *testing.T) EgressService {
				t.Helper()
				return fakeEgress{
					verifyFunc: func(_ context.Context, _ verify.Request) (
						egress.Verification, error,
					) {
						return egress.Verification{}, errors.New("boom")
					},
				}
			},
			status: http.StatusInternalServerError,
			code:   CodeInternalError,
		},
		"invalid_quorum": {
			path:    "/egress?quorum=0",
			service: unexpected,
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
		"invalid_fresh": {
			path:    "/egress?fresh=maybe",
			service: unexpected,
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
		"invalid_timeout": {
			path:    "/egress?timeout_s=1000",
			service: unexpected,
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
		"disabled": {
			path: "/egress",
			service: func(t *testing.T) EgressService {
				t.Helper()
				return nil
			},
			status: http.StatusBadRequest,
			code:   CodeInvalidRequest,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := serveEgress(t, testCase.service(t), testCase.path)
			assert.Equal(t, testCase.status, response.Code)

			if testCase.code != "" {
				var body errorBody
				err := json.Unmarshal(response.Body.Bytes(), &body)
				require.NoError(t, err)
				assert.Equal(t, testCase.code, body.Error.Code)
				return
			}
			require.NotNil(t, testCase.check)
			testCase.check(t, response.Body.Bytes())
		})
	}
}

func Test_Handler_EgressCanary(t *testing.T) {
	t.Parallel()

	checkedAt := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	result := egress.CanaryResult{
		URL:        "https://canary.invalid/health",
		Status:     http.StatusOK,
		BodyBytes:  128,
		BodySHA256: "0123",
		LatencyMS:  190,
		OK:         true,
		CheckedAt:  checkedAt,
	}

	testCases := map[string]struct {
		service func(t *testing.T) EgressService
		status  int
		code    string
		check   func(t *testing.T, body []byte)
	}{
		"ok": {
			service: func(t *testing.T) EgressService {
				t.Helper()
				return fakeEgress{
					canaryFunc: func(_ context.Context) (egress.CanaryResult, error) {
						return result, nil
					},
				}
			},
			status: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var canary egress.CanaryResult
				err := json.Unmarshal(body, &canary)
				require.NoError(t, err)
				assert.True(t, canary.OK)
				assert.Equal(t, http.StatusOK, canary.Status)
				assert.Equal(t, int64(128), canary.BodyBytes)
				assert.Equal(t, checkedAt, canary.CheckedAt)
			},
		},
		"canary_not_configured": {
			service: func(t *testing.T) EgressService {
				t.Helper()
				return fakeEgress{
					canaryFunc: func(_ context.Context) (egress.CanaryResult, error) {
						return egress.CanaryResult{}, verify.ErrCanaryDisabled
					},
				}
			},
			status: http.StatusBadRequest,
			code:   CodeInvalidRequest,
		},
		"internal_error": {
			service: func(t *testing.T) EgressService {
				t.Helper()
				return fakeEgress{
					canaryFunc: func(_ context.Context) (egress.CanaryResult, error) {
						return egress.CanaryResult{}, errors.New("boom")
					},
				}
			},
			status: http.StatusInternalServerError,
			code:   CodeInternalError,
		},
		"disabled": {
			service: func(t *testing.T) EgressService {
				t.Helper()
				return nil
			},
			status: http.StatusBadRequest,
			code:   CodeInvalidRequest,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := serveEgress(t, testCase.service(t), "/egress/canary")
			assert.Equal(t, testCase.status, response.Code)

			if testCase.code != "" {
				var body errorBody
				err := json.Unmarshal(response.Body.Bytes(), &body)
				require.NoError(t, err)
				assert.Equal(t, testCase.code, body.Error.Code)
				return
			}
			require.NotNil(t, testCase.check)
			testCase.check(t, response.Body.Bytes())
		})
	}
}

func Test_Handler_EgressHistory(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	canaryOK := egress.CanaryResult{OK: true}
	first := egress.Verification{
		Verified:    true,
		IP:          netip.MustParseAddr("203.0.113.7"),
		Family:      4,
		Quorum:      2,
		SourceCount: 3,
		Confidence:  egress.ConfidenceHigh,
		Dissenters:  []string{"dns:whoami"},
		Canary:      &canaryOK,
		VerifiedAt:  now,
		TTLS:        10,
	}
	second := egress.Verification{
		Verified:    false,
		Family:      4,
		SourceCount: 1,
		Dissenters:  []string{},
		VerifiedAt:  now.Add(-time.Minute),
		TTLS:        10,
	}
	unexpected := func(t *testing.T) EgressService {
		t.Helper()
		return fakeEgress{
			historyFunc: func(_ int, _ time.Time) []egress.Verification {
				require.FailNow(t, "History should not be called")
				return nil
			},
		}
	}

	testCases := map[string]struct {
		path    string
		service func(t *testing.T) EgressService
		status  int
		code    string
		check   func(t *testing.T, body []byte)
	}{
		"defaults": {
			path: "/egress/history",
			service: func(t *testing.T) EgressService {
				t.Helper()
				return fakeEgress{
					historyFunc: func(limit int, since time.Time) []egress.Verification {
						assert.Equal(t, defaultEgressHistoryLimit, limit)
						assert.True(t, since.IsZero())
						return []egress.Verification{first, second}
					},
				}
			},
			status: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var response struct {
					Items []egressHistoryItem `json:"items"`
					Count int                 `json:"count"`
				}
				err := json.Unmarshal(body, &response)
				require.NoError(t, err)
				assert.Equal(t, 2, response.Count)
				require.Len(t, response.Items, 2)
				assert.Equal(t, "203.0.113.7", response.Items[0].IP.String())
				require.NotNil(t, response.Items[0].CanaryOK)
				assert.True(t, *response.Items[0].CanaryOK)
				assert.Equal(t, []string{"dns:whoami"}, response.Items[0].Dissenters)
				assert.Nil(t, response.Items[1].CanaryOK)
			},
		},
		"limit_and_since": {
			path: "/egress/history?limit=5&since=2026-11-12T11:00:00Z",
			service: func(t *testing.T) EgressService {
				t.Helper()
				return fakeEgress{
					historyFunc: func(limit int, since time.Time) []egress.Verification {
						assert.Equal(t, 5, limit)
						assert.Equal(t,
							time.Date(2026, 11, 12, 11, 0, 0, 0, time.UTC), since)
						return nil
					},
				}
			},
			status: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var response struct {
					Count int `json:"count"`
				}
				err := json.Unmarshal(body, &response)
				require.NoError(t, err)
				assert.Zero(t, response.Count)
			},
		},
		"limit_clamped": {
			path: "/egress/history?limit=1000",
			service: func(t *testing.T) EgressService {
				t.Helper()
				return fakeEgress{
					historyFunc: func(limit int, _ time.Time) []egress.Verification {
						assert.Equal(t, maxEgressHistoryLimit, limit)
						return nil
					},
				}
			},
			status: http.StatusOK,
			check: func(t *testing.T, _ []byte) {
				t.Helper()
			},
		},
		"invalid_limit": {
			path:    "/egress/history?limit=0",
			service: unexpected,
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
		"invalid_since": {
			path:    "/egress/history?since=yesterday",
			service: unexpected,
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
		"disabled": {
			path: "/egress/history",
			service: func(t *testing.T) EgressService {
				t.Helper()
				return nil
			},
			status: http.StatusBadRequest,
			code:   CodeInvalidRequest,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := serveEgress(t, testCase.service(t), testCase.path)
			assert.Equal(t, testCase.status, response.Code)

			if testCase.code != "" {
				var body errorBody
				err := json.Unmarshal(response.Body.Bytes(), &body)
				require.NoError(t, err)
				assert.Equal(t, testCase.code, body.Error.Code)
				return
			}
			require.NotNil(t, testCase.check)
			testCase.check(t, response.Body.Bytes())
		})
	}
}
