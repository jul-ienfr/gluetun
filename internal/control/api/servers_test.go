package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/control/catalog"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCatalog struct {
	queryFunc   func(query catalog.Query) (catalog.Page, error)
	facetsFunc  func() (catalog.Facets, error)
	detailFunc  func(hostname string) (catalog.ServerDetail, bool, error)
	refreshFunc func(ctx context.Context) (catalog.RefreshResult, error)
}

func (f fakeCatalog) Query(query catalog.Query) (catalog.Page, error) {
	return f.queryFunc(query)
}

func (f fakeCatalog) Facets() (catalog.Facets, error) {
	return f.facetsFunc()
}

func (f fakeCatalog) Detail(hostname string) (catalog.ServerDetail, bool,
	error,
) {
	return f.detailFunc(hostname)
}

func (f fakeCatalog) Refresh(ctx context.Context) (catalog.RefreshResult,
	error,
) {
	return f.refreshFunc(ctx)
}

func serveCatalog(t *testing.T, service CatalogService, path string,
) *httptest.ResponseRecorder {
	t.Helper()

	handler := New(settings.Control{}, models.BuildInformation{}, "station", nil,
		nil)
	if service != nil {
		handler.SetCatalog(service)
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path,
		nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func Test_Handler_Servers(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		path    string
		service func(t *testing.T) CatalogService
		status  int
		code    string
		check   func(t *testing.T, body []byte)
	}{
		"list": {
			path: "/servers?country=Netherlands&limit=10",
			service: func(t *testing.T) CatalogService {
				t.Helper()
				return fakeCatalog{
					queryFunc: func(query catalog.Query) (catalog.Page, error) {
						assert.Equal(t, []string{"Netherlands"}, query.Countries)
						assert.Equal(t, 10, query.Limit)
						cursor := "next"
						return catalog.Page{
							Items: []catalog.ServerCandidate{
								{Hostname: "nl-1.example.com", Tier: "free"},
							},
							NextCursor:    &cursor,
							TotalEstimate: 1,
						}, nil
					},
				}
			},
			status: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var page catalog.Page
				require.NoError(t, json.Unmarshal(body, &page))
				require.Len(t, page.Items, 1)
				assert.Equal(t, "nl-1.example.com", page.Items[0].Hostname)
				require.NotNil(t, page.NextCursor)
				assert.Equal(t, "next", *page.NextCursor)
			},
		},
		"invalid query": {
			path:    "/servers?limit=nope",
			service: func(*testing.T) CatalogService { return fakeCatalog{} },
			status:  http.StatusBadRequest,
			code:    CodeInvalidRequest,
		},
		"invalid cursor": {
			path: "/servers?cursor=nope",
			service: func(*testing.T) CatalogService {
				return fakeCatalog{
					queryFunc: func(catalog.Query) (catalog.Page, error) {
						return catalog.Page{}, catalog.ErrInvalidCursor
					},
				}
			},
			status: http.StatusBadRequest,
			code:   CodeInvalidRequest,
		},
		"service error": {
			path: "/servers",
			service: func(*testing.T) CatalogService {
				return fakeCatalog{
					queryFunc: func(catalog.Query) (catalog.Page, error) {
						return catalog.Page{}, errors.New("boom")
					},
				}
			},
			status: http.StatusInternalServerError,
			code:   CodeInternalError,
		},
		"facets": {
			path: "/servers/facets",
			service: func(*testing.T) CatalogService {
				return fakeCatalog{
					facetsFunc: func() (catalog.Facets, error) {
						return catalog.Facets{
							Countries: []catalog.FacetValue{
								{Value: "Netherlands", Count: 1},
							},
						}, nil
					},
				}
			},
			status: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var facets catalog.Facets
				require.NoError(t, json.Unmarshal(body, &facets))
				require.Len(t, facets.Countries, 1)
				assert.Equal(t, "Netherlands", facets.Countries[0].Value)
			},
		},
		"facets error": {
			path: "/servers/facets",
			service: func(*testing.T) CatalogService {
				return fakeCatalog{
					facetsFunc: func() (catalog.Facets, error) {
						return catalog.Facets{}, errors.New("boom")
					},
				}
			},
			status: http.StatusInternalServerError,
			code:   CodeInternalError,
		},
		"detail": {
			path: "/servers/nl-1.example.com",
			service: func(t *testing.T) CatalogService {
				t.Helper()
				return fakeCatalog{
					detailFunc: func(hostname string) (catalog.ServerDetail, bool, error) {
						assert.Equal(t, "nl-1.example.com", hostname)
						return catalog.ServerDetail{
							ServerCandidate: catalog.ServerCandidate{
								Hostname: "nl-1.example.com",
								Tier:     "free",
							},
							AvailableTransports: []string{"wireguard"},
						}, true, nil
					},
				}
			},
			status: http.StatusOK,
			check: func(t *testing.T, body []byte) {
				t.Helper()
				var detail catalog.ServerDetail
				require.NoError(t, json.Unmarshal(body, &detail))
				assert.Equal(t, "nl-1.example.com", detail.Hostname)
				assert.Equal(t, []string{"wireguard"}, detail.AvailableTransports)
			},
		},
		"detail not found": {
			path: "/servers/missing.example.com",
			service: func(*testing.T) CatalogService {
				return fakeCatalog{
					detailFunc: func(string) (catalog.ServerDetail, bool, error) {
						return catalog.ServerDetail{}, false, nil
					},
				}
			},
			status: http.StatusNotFound,
			code:   CodeNotFound,
		},
		"detail error": {
			path: "/servers/nl-1.example.com",
			service: func(*testing.T) CatalogService {
				return fakeCatalog{
					detailFunc: func(string) (catalog.ServerDetail, bool, error) {
						return catalog.ServerDetail{}, false, errors.New("boom")
					},
				}
			},
			status: http.StatusInternalServerError,
			code:   CodeInternalError,
		},
		"not ready": {
			path:    "/servers",
			service: func(*testing.T) CatalogService { return nil },
			status:  http.StatusServiceUnavailable,
			code:    CodeNotReady,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			response := serveCatalog(t, testCase.service(t), testCase.path)

			assert.Equal(t, testCase.status, response.Code)
			if testCase.code != "" {
				assert.Equal(t, testCase.code, decodeError(t, response).Code)
				return
			}
			if testCase.check != nil {
				testCase.check(t, response.Body.Bytes())
			}
		})
	}
}
