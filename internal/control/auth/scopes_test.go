package auth

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_ParseScope(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		input string
		scope Scope
		err   string
	}{
		"empty":      {input: "", scope: ScopeNone},
		"reader":     {input: "reader", scope: ScopeReader},
		"controller": {input: "controller", scope: ScopeController},
		"admin":      {input: "admin", scope: ScopeAdmin},
		"uppercase":  {input: "ADMIN", scope: ScopeAdmin},
		"unknown":    {input: "operator", err: "unknown scope: operator"},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			scope, err := ParseScope(testCase.input)
			if testCase.err == "" {
				require.NoError(t, err)
				assert.Equal(t, testCase.scope, scope)
				return
			}
			require.Error(t, err)
			assert.Equal(t, testCase.err, err.Error())
		})
	}
}

func Test_ScopeFromRoleName(t *testing.T) {
	t.Parallel()

	testCases := map[string]Scope{
		"reader":          ScopeReader,
		"api-reader":      ScopeReader,
		"controller":      ScopeController,
		"station-control": ScopeController,
		"admin":           ScopeAdmin,
		"gluetun-admin":   ScopeAdmin,
		"legacy":          ScopeNone,
	}

	for name, expected := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, expected, ScopeFromRoleName(name))
		})
	}
}

func Test_Allows(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		have     Scope
		required Scope
		allowed  bool
	}{
		"legacy allows everything": {ScopeNone, ScopeAdmin, true},
		"reader reads":             {ScopeReader, ScopeReader, true},
		"reader cannot control":    {ScopeReader, ScopeController, false},
		"reader cannot admin":      {ScopeReader, ScopeAdmin, false},
		"controller controls":      {ScopeController, ScopeController, true},
		"controller cannot admin":  {ScopeController, ScopeAdmin, false},
		"admin does everything":    {ScopeAdmin, ScopeAdmin, true},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, testCase.allowed,
				Allows(testCase.have, testCase.required))
		})
	}
}

func Test_RequiredScope(t *testing.T) {
	t.Parallel()

	testCases := map[string]struct {
		method   string
		path     string
		query    url.Values
		expected Scope
	}{
		"read state": {
			method: http.MethodGet, path: "/v1/vpn/state",
			expected: ScopeReader,
		},
		"switch": {
			method: http.MethodPost, path: "/v1/vpn/switch",
			expected: ScopeController,
		},
		"rotate": {
			method: http.MethodPost, path: "/v1/vpn/rotate",
			expected: ScopeController,
		},
		"settings update": {
			method: http.MethodPut, path: "/v1/vpn/settings",
			expected: ScopeController,
		},
		"cancel job": {
			method: http.MethodPost, path: "/v1/vpn/jobs/job_01J9Z3K4T5/cancel",
			expected: ScopeAdmin,
		},
		"refresh servers": {
			method: http.MethodPost, path: "/v1/servers/refresh",
			expected: ScopeAdmin,
		},
		"reset transport": {
			method: http.MethodPost, path: "/v1/vpn/transport/reset",
			expected: ScopeAdmin,
		},
		"reveal settings": {
			method: http.MethodGet, path: "/v1/vpn/settings",
			query:    url.Values{"reveal": []string{"true"}},
			expected: ScopeAdmin,
		},
		"settings without reveal": {
			method: http.MethodGet, path: "/v1/vpn/settings",
			expected: ScopeReader,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, testCase.expected,
				RequiredScope(testCase.method, testCase.path, testCase.query))
		})
	}
}

func Test_RoutePatternMatches(t *testing.T) {
	t.Parallel()

	assert.True(t, RoutePatternMatches("/v1/vpn/jobs/{id}", "/v1/vpn/jobs/job_01"))
	assert.True(t, RoutePatternMatches("/v1/servers/{hostname}", "/v1/servers/nl-1"))
	assert.False(t, RoutePatternMatches("/v1/vpn/jobs/{id}", "/v1/vpn/jobs/job_01/cancel"))
	assert.False(t, RoutePatternMatches("/v1/vpn/jobs/{id}", "/v1/vpn/jobs/"))
	assert.False(t, RoutePatternMatches("/v1/vpn/state", "/v1/vpn/switch"))
}
