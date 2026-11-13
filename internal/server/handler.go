package server

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/control/api"
	"github.com/qdm12/gluetun/internal/models"
	"github.com/qdm12/gluetun/internal/server/middlewares/auth"
	"github.com/qdm12/gluetun/internal/server/middlewares/log"
)

func newHandler(ctx context.Context, logger Logger, logging bool,
	authSettings auth.Settings,
	controlSettings settings.Control,
	buildInfo models.BuildInformation,
	vpnLooper VPNLooper,
	pf PortForwarding,
	dnsLooper DNSLoop,
	updaterLooper UpdaterLooper,
	publicIPLooper PublicIPLoop,
	storage Storage,
	ipv6Supported bool,
) (httpHandler http.Handler, err error) {
	handler := &handler{}

	var controlHandler *api.Handler
	controlEnabled := controlSettings.Enabled == nil || *controlSettings.Enabled
	if controlEnabled {
		stationID, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("getting station hostname: %w", err)
		}
		controlHandler = newControlHandler(logger, controlSettings, buildInfo,
			stationID, vpnLooper, dnsLooper, publicIPLooper, storage)
	}

	vpn := newVPNHandler(ctx, vpnLooper, storage, ipv6Supported, logger,
		controlHandler)
	openvpn := newOpenvpnHandler(ctx, vpnLooper, logger)
	dns := newDNSHandler(ctx, dnsLooper, logger)
	updater := newUpdaterHandler(ctx, updaterLooper, logger)
	publicip := newPublicIPHandler(publicIPLooper, logger)
	portForward := newPortForwardHandler(ctx, pf, logger)

	handler.v0 = newHandlerV0(ctx, logger, vpnLooper, dnsLooper, updaterLooper)
	handler.v1 = newHandlerV1(logger, buildInfo, vpn, openvpn, dns, updater, publicip, portForward)
	handler.control = controlHandler

	authMiddleware, err := auth.New(authSettings, logger)
	if err != nil {
		return nil, fmt.Errorf("creating auth middleware: %w", err)
	}

	middlewares := []func(http.Handler) http.Handler{
		authMiddleware,
		log.New(logger, logging),
	}
	httpHandler = handler
	for _, middleware := range middlewares {
		httpHandler = middleware(httpHandler)
	}
	return httpHandler, nil
}

type handler struct {
	v0      http.Handler
	v1      http.Handler
	control *api.Handler
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.RequestURI = strings.TrimSuffix(r.RequestURI, "/")
	if !strings.HasPrefix(r.RequestURI, "/v1/") && r.RequestURI != "/v1" {
		h.v0.ServeHTTP(w, r)
		return
	}
	r.RequestURI = strings.TrimPrefix(r.RequestURI, "/v1")
	controlPath := r.RequestURI
	if index := strings.IndexByte(controlPath, '?'); index >= 0 {
		controlPath = controlPath[:index]
	}
	if h.control != nil && h.control.Handles(controlPath) {
		h.control.ServeHTTP(w, r)
		return
	}
	h.v1.ServeHTTP(w, r)
}
