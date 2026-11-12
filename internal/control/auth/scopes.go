package auth

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Scope is the permission level carried by a control server role.
type Scope uint8

const (
	// ScopeNone keeps the legacy route-only behavior: the role has no scope
	// restriction beyond the routes it is explicitly granted.
	ScopeNone Scope = iota
	// ScopeReader can read every route.
	ScopeReader
	// ScopeController can read and mutate the tunnel, DNS and settings.
	ScopeController
	// ScopeAdmin can do everything, including secret reveal and breaker reset.
	ScopeAdmin
)

func (s Scope) String() string {
	switch s {
	case ScopeNone:
		return "none"
	case ScopeReader:
		return "reader"
	case ScopeController:
		return "controller"
	case ScopeAdmin:
		return "admin"
	default:
		return fmt.Sprintf("scope(%d)", s)
	}
}

// ParseScope parses a scope name. An empty string maps to ScopeNone.
func ParseScope(name string) (scope Scope, err error) {
	switch strings.ToLower(name) {
	case "":
		return ScopeNone, nil
	case "reader":
		return ScopeReader, nil
	case "controller":
		return ScopeController, nil
	case "admin":
		return ScopeAdmin, nil
	default:
		return ScopeNone, fmt.Errorf("unknown scope: %s", name)
	}
}

// ScopeFromRoleName infers a scope from a legacy role name. Unknown names
// return ScopeNone so existing configurations keep their route-only behavior.
func ScopeFromRoleName(name string) Scope {
	name = strings.ToLower(name)
	switch {
	case strings.Contains(name, "admin"):
		return ScopeAdmin
	case strings.Contains(name, "control"):
		return ScopeController
	case strings.Contains(name, "reader"):
		return ScopeReader
	default:
		return ScopeNone
	}
}

// Allows reports whether a role with the have scope can perform an action
// requiring the required scope.
func Allows(have, required Scope) bool {
	if have == ScopeNone {
		return true
	}
	return have >= required
}

// RequiredScope returns the minimal scope needed for a route. Unknown routes
// default to reader for reads and controller for writes.
func RequiredScope(method, path string, query url.Values) Scope {
	path = strings.TrimSuffix(path, "/")

	switch {
	case method == http.MethodPost && pathMatches("/v1/vpn/jobs/{id}/cancel", path):
		return ScopeAdmin
	case method == http.MethodPost && path == "/v1/servers/refresh":
		return ScopeAdmin
	case method == http.MethodPost && path == "/v1/vpn/transport/reset":
		return ScopeAdmin
	case method == http.MethodGet && path == "/v1/vpn/settings" &&
		strings.EqualFold(query.Get("reveal"), "true"):
		return ScopeAdmin
	}

	switch method {
	case http.MethodGet, http.MethodHead:
		return ScopeReader
	case http.MethodPut, http.MethodPost, http.MethodPatch, http.MethodDelete:
		return ScopeController
	default:
		return ScopeReader
	}
}

func pathMatches(pattern, path string) bool {
	patternParts := strings.Split(strings.Trim(pattern, "/"), "/")
	pathParts := strings.Split(strings.Trim(path, "/"), "/")
	if len(patternParts) != len(pathParts) {
		return false
	}
	for i, patternPart := range patternParts {
		if strings.HasPrefix(patternPart, "{") && strings.HasSuffix(patternPart, "}") {
			if pathParts[i] == "" {
				return false
			}
			continue
		}
		if patternPart != pathParts[i] {
			return false
		}
	}
	return true
}

// RoutePatternMatches reports whether a route pattern such as
// "/v1/vpn/jobs/{id}" matches a concrete path.
func RoutePatternMatches(pattern, path string) bool {
	return pathMatches(pattern, path)
}
