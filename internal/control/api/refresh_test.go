package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/control/catalog"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newRefreshHandler(service CatalogService,
	now func() time.Time,
) *Handler {
	handler := New(settings.Control{}, models.BuildInformation{}, "station", nil,
		nil)
	handler.now = now
	if service != nil {
		handler.SetCatalog(service)
	}
	return handler
}

func serveRefresh(t *testing.T, handler *Handler,
) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequestWithContext(t.Context(), http.MethodPost,
		"/servers/refresh", strings.NewReader(`{}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func Test_Handler_ServersRefresh(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	current := now
	var calls atomic.Int32
	service := fakeCatalog{
		refreshFunc: func(_ context.Context) (catalog.RefreshResult, error) {
			calls.Add(1)
			return catalog.RefreshResult{Refreshed: true, Servers: 42}, nil
		},
	}
	handler := newRefreshHandler(service, func() time.Time { return current })

	first := serveRefresh(t, handler)
	require.Equal(t, http.StatusOK, first.Code)
	var result catalog.RefreshResult
	require.NoError(t, json.NewDecoder(first.Body).Decode(&result))
	assert.True(t, result.Refreshed)
	assert.Equal(t, 42, result.Servers)
	assert.EqualValues(t, 1, calls.Load())

	current = now.Add(30 * time.Second)
	second := serveRefresh(t, handler)
	assert.Equal(t, http.StatusTooManyRequests, second.Code)
	assert.Equal(t, CodeRateLimited, decodeError(t, second).Code)
	assert.Equal(t, "30", second.Header().Get("Retry-After"))
	assert.EqualValues(t, 1, calls.Load(),
		"rate limited refresh must not call the source")

	current = now.Add(time.Minute)
	third := serveRefresh(t, handler)
	assert.Equal(t, http.StatusOK, third.Code)
	assert.EqualValues(t, 2, calls.Load())
}

func Test_Handler_ServersRefreshErrors(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		service CatalogService
		status  int
		code    string
	}{
		"not ready": {
			service: nil,
			status:  http.StatusServiceUnavailable,
			code:    CodeNotReady,
		},
		"unsupported": {
			service: fakeCatalog{
				refreshFunc: func(context.Context) (catalog.RefreshResult, error) {
					return catalog.RefreshResult{},
						catalog.ErrRefreshUnsupported
				},
			},
			status: http.StatusNotImplemented,
			code:   CodeNotImplemented,
		},
		"internal error": {
			service: fakeCatalog{
				refreshFunc: func(context.Context) (catalog.RefreshResult, error) {
					return catalog.RefreshResult{}, errors.New("boom")
				},
			},
			status: http.StatusInternalServerError,
			code:   CodeInternalError,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := serveRefresh(t, newRefreshHandler(testCase.service,
				time.Now))
			assert.Equal(t, testCase.status, response.Code)
			assert.Equal(t, testCase.code, decodeError(t, response).Code)
		})
	}
}
