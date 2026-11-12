package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/control/jobs"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serveOnHandler(t *testing.T, handler *Handler, method, path,
	body string,
) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), method, path,
		strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func queuedJobs() fakeJobs {
	return fakeJobs{
		submitFunc: func(context.Context, jobs.SwitchRequest) (jobs.Submission, error) {
			return jobs.Submission{Job: jobs.Job{
				ID:    "job-1",
				Kind:  jobs.KindSwitch,
				State: jobs.StateQueued,
			}}, nil
		},
		rotateFunc: func(context.Context, jobs.RotationRequest) (jobs.Submission, error) {
			return jobs.Submission{Job: jobs.Job{
				ID:    "job-2",
				Kind:  jobs.KindRotate,
				State: jobs.StateQueued,
			}}, nil
		},
	}
}

func Test_Handler_RejectsOversizedBody(t *testing.T) {
	t.Parallel()

	handler := New(settings.Control{}, models.BuildInformation{}, "station",
		nil, queuedJobs())

	body := `{"target":{"hostname":"` +
		strings.Repeat("a", maxBodyBytes) + `"}}`

	response := serveOnHandler(t, handler, http.MethodPost, "/vpn/switch", body)

	assert.Equal(t, http.StatusRequestEntityTooLarge, response.Code)
	assert.Equal(t, CodePayloadTooLarge, decodeError(t, response).Code)
}

func Test_Handler_AllowsBodyUnderLimit(t *testing.T) {
	t.Parallel()

	handler := New(settings.Control{}, models.BuildInformation{}, "station",
		nil, queuedJobs())

	response := serveOnHandler(t, handler, http.MethodPost, "/vpn/switch",
		`{"target":{"hostname":"nl-1234.nordvpn.com"}}`)

	assert.Equal(t, http.StatusAccepted, response.Code)
}

func Test_Handler_SwitchRateLimit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	current := now
	var calls int
	service := queuedJobs()
	submit := service.submitFunc
	service.submitFunc = func(ctx context.Context,
		request jobs.SwitchRequest,
	) (jobs.Submission, error) {
		calls++
		return submit(ctx, request)
	}

	handler := New(settings.Control{}, models.BuildInformation{}, "station",
		nil, service)
	handler.now = func() time.Time { return current }

	body := `{"target":{"hostname":"nl-1234.nordvpn.com"}}`
	for index := 0; index < maxSwitchPerMinute; index++ {
		response := serveOnHandler(t, handler, http.MethodPost, "/vpn/switch",
			body)
		require.Equal(t, http.StatusAccepted, response.Code,
			"request %d", index+1)
	}

	limited := serveOnHandler(t, handler, http.MethodPost, "/vpn/switch", body)
	assert.Equal(t, http.StatusTooManyRequests, limited.Code)
	assert.Equal(t, CodeRateLimited, decodeError(t, limited).Code)
	assert.NotEmpty(t, limited.Header().Get("Retry-After"))
	assert.Equal(t, maxSwitchPerMinute, calls,
		"a rate limited switch must not reach the jobs service")

	current = now.Add(time.Minute)
	recovered := serveOnHandler(t, handler, http.MethodPost, "/vpn/switch",
		body)
	assert.Equal(t, http.StatusAccepted, recovered.Code)
	assert.Equal(t, maxSwitchPerMinute+1, calls)
}

func Test_Handler_RotateSharesSwitchRateLimit(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	handler := New(settings.Control{}, models.BuildInformation{}, "station",
		nil, queuedJobs())
	handler.now = func() time.Time { return now }

	for index := 0; index < maxSwitchPerMinute; index++ {
		response := serveOnHandler(t, handler, http.MethodPost, "/vpn/switch",
			`{"target":{"hostname":"nl-1234.nordvpn.com"}}`)
		require.Equal(t, http.StatusAccepted, response.Code)
	}

	limited := serveOnHandler(t, handler, http.MethodPost, "/vpn/rotate",
		`{"candidates":[{"hostname":"nl-1234.nordvpn.com"}]}`)
	assert.Equal(t, http.StatusTooManyRequests, limited.Code)
	assert.Equal(t, CodeRateLimited, decodeError(t, limited).Code)
}

func Test_RateLimiter_Window(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	limiter := newRateLimiter(2, time.Minute)

	allowed, _ := limiter.Allow(now)
	assert.True(t, allowed)
	allowed, _ = limiter.Allow(now.Add(10 * time.Second))
	assert.True(t, allowed)

	allowed, retryAfter := limiter.Allow(now.Add(20 * time.Second))
	assert.False(t, allowed)
	assert.Equal(t, 40*time.Second, retryAfter)

	allowed, _ = limiter.Allow(now.Add(time.Minute))
	assert.True(t, allowed)
}
