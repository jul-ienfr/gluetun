package server

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/control/observability"
	"github.com/qdm12/gluetun/internal/egress/verify"
	"github.com/qdm12/gluetun/internal/httpserver"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/server/middlewares/auth"
	transportpkg "github.com/qdm12/gluetun/internal/vpn/transport"
)

func New(ctx context.Context, controlServerSettings settings.ControlServer,
	controlSettings settings.Control, logger Logger,
	buildInfo models.BuildInformation, openvpnLooper VPNLooper,
	pf PortForwarding, dnsLooper DNSLoop,
	updaterLooper UpdaterLooper, publicIPLooper PublicIPLoop, storage Storage,
	ipv6Supported bool, controlMetrics *observability.Metrics,
	egress *verify.Service, transportService *transportpkg.Service) (
	server *httpserver.Server, err error,
) {
	authSettings, err := setupAuthMiddleware(controlServerSettings.AuthFilePath,
		controlServerSettings.AuthDefaultRole, logger)
	if err != nil {
		return nil, fmt.Errorf("building authentication middleware settings: %w", err)
	}

	handler, err := newHandler(ctx, logger, *controlServerSettings.Log, authSettings,
		controlSettings, buildInfo, openvpnLooper, pf, dnsLooper, updaterLooper, publicIPLooper,
		storage, ipv6Supported, controlMetrics, egress, transportService)
	if err != nil {
		return nil, fmt.Errorf("creating handler: %w", err)
	}

	httpServerSettings := httpserver.Settings{
		Address: *controlServerSettings.Address,
		Handler: handler,
		Logger:  logger,
	}

	server, err = httpserver.New(httpServerSettings)
	if err != nil {
		return nil, fmt.Errorf("creating server: %w", err)
	}

	return server, nil
}

func setupAuthMiddleware(authPath, jsonDefaultRole string, logger Logger) (
	authSettings auth.Settings, err error,
) {
	authSettings, err = auth.Read(authPath)
	switch {
	case errors.Is(err, os.ErrNotExist): // no auth file present
	case err != nil:
		return auth.Settings{}, fmt.Errorf("reading auth settings: %w", err)
	default:
		logger.Infof("read %d roles from authentication file", len(authSettings.Roles))
	}
	err = authSettings.SetDefaultRole(jsonDefaultRole)
	if err != nil {
		return auth.Settings{}, fmt.Errorf("setting default role: %w", err)
	}
	err = authSettings.Validate()
	if err != nil {
		return auth.Settings{}, fmt.Errorf("validating auth settings: %w", err)
	}
	return authSettings, nil
}
