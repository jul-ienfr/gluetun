package auth

import (
	"fmt"

	controlauth "github.com/qdm12/gluetun/internal/control/auth"
)

type internalRole struct {
	name    string
	scope   controlauth.Scope
	checker authorizationChecker
}

func settingsToLookupMap(settings Settings) (routeToRoles map[string][]internalRole, err error) {
	routeToRoles = make(map[string][]internalRole)
	for _, role := range settings.Roles {
		var checker authorizationChecker
		switch role.Auth {
		case AuthNone:
			checker = newNoneMethod()
		case AuthAPIKey:
			checker = newAPIKeyMethod(role.APIKey)
		case AuthBasic:
			checker = newBasicAuthMethod(role.Username, role.Password)
		default:
			return nil, fmt.Errorf("authentication method not supported: %s", role.Auth)
		}

		iRole := internalRole{
			name:    role.Name,
			scope:   roleScope(role),
			checker: checker,
		}
		for _, route := range role.Routes {
			checkerExists := false
			for _, role := range routeToRoles[route] {
				if role.checker.equal(iRole.checker) {
					checkerExists = true
					break
				}
			}
			if checkerExists {
				// even if the role name is different, if the checker is the same, skip it.
				continue
			}
			routeToRoles[route] = append(routeToRoles[route], iRole)
		}
	}
	return routeToRoles, nil
}

func roleScope(role Role) controlauth.Scope {
	if role.Scope != "" {
		scope, err := controlauth.ParseScope(role.Scope)
		if err == nil {
			return scope
		}
	}
	return controlauth.ScopeFromRoleName(role.Name)
}
