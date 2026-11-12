package api

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/qdm12/gluetun/internal/configuration/settings"
	"github.com/qdm12/gluetun/internal/control/events"
	"github.com/qdm12/gluetun/internal/models"
)

type route struct {
	method  string
	pattern string
	handler func(w http.ResponseWriter, r *http.Request)
}

// Handler serves the control plane API routes.
type Handler struct {
	control   settings.Control
	buildInfo models.BuildInformation
	stationID string
	egress    EgressService
	jobs      JobsService
	catalog   CatalogService
	dns       DNSService
	transport TransportService
	eventBus  *events.Bus
	routes    []route
	now       func() time.Time

	switchLimiter *rateLimiter
	refreshMutex  sync.Mutex
	lastRefresh   time.Time
}

// New creates a control plane API handler.
func New(control settings.Control, buildInfo models.BuildInformation,
	stationID string, egress EgressService, jobService JobsService,
) *Handler {
	handler := &Handler{
		control:   control,
		buildInfo: buildInfo,
		stationID: stationID,
		egress:    egress,
		jobs:      jobService,
		now:       time.Now,
		switchLimiter: newRateLimiter(maxSwitchPerMinute,
			switchRateWindow),
	}

	handler.routes = []route{
		{http.MethodGet, "/control/capabilities", handler.getCapabilities},
		{http.MethodGet, "/vpn/state", handler.notImplemented},
		{http.MethodPost, "/vpn/switch", handler.postSwitch},
		{http.MethodPost, "/vpn/rotate", handler.postRotate},
		{http.MethodPost, "/vpn/rollback", handler.postRollback},
		{http.MethodGet, "/vpn/jobs", handler.getJobs},
		{http.MethodGet, "/vpn/jobs/{id}", handler.getJob},
		{http.MethodPost, "/vpn/jobs/{id}/cancel", handler.postJobCancel},
		{http.MethodGet, "/vpn/transport", handler.getTransportState},
		{http.MethodPost, "/vpn/transport/reset", handler.postTransportReset},
		{http.MethodGet, "/egress", handler.getEgress},
		{http.MethodGet, "/egress/verify", handler.getEgressVerify},
		{http.MethodGet, "/egress/canary", handler.getEgressCanary},
		{http.MethodGet, "/egress/history", handler.getEgressHistory},
		{http.MethodGet, "/dns/state", handler.getDNSState},
		{http.MethodGet, "/dns/tiers", handler.getDNSTiers},
		{http.MethodPost, "/dns/probe", handler.postDNSProbe},
		{http.MethodGet, "/events", handler.getEvents},
		{http.MethodGet, "/events/stream", handler.getEventsStream},
		{http.MethodGet, "/servers", handler.getServers},
		{http.MethodGet, "/servers/facets", handler.getServerFacets},
		{http.MethodPost, "/servers/refresh", handler.postServersRefresh},
		{http.MethodGet, "/servers/{hostname}", handler.getServer},
	}

	return handler
}

// SetCatalog attaches the server catalogue service to the handler.
func (h *Handler) SetCatalog(service CatalogService) {
	h.catalog = service
}

// SetDNS attaches the DNS ladder service to the handler.
func (h *Handler) SetDNS(service DNSService) {
	h.dns = service
}

// SetTransport attaches the transport ladder service to the handler.
func (h *Handler) SetTransport(service TransportService) {
	h.transport = service
}

// SetEvents attaches the event bus to the handler.
func (h *Handler) SetEvents(bus *events.Bus) {
	h.eventBus = bus
}

// Handles returns true if the path matches a control plane route.
func (h *Handler) Handles(path string) bool {
	path = strings.TrimSuffix(path, "/")
	for _, route := range h.routes {
		if routeMatches(route.pattern, path) {
			return true
		}
	}
	return false
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.RequestURI
	if path == "" {
		path = r.URL.Path
	}
	if index := strings.IndexByte(path, '?'); index >= 0 {
		path = path[:index]
	}
	path = strings.TrimSuffix(path, "/")

	if !h.enforceLimits(w, r, path) {
		return
	}

	pathMatched := false
	for _, route := range h.routes {
		if !routeMatches(route.pattern, path) {
			continue
		}
		pathMatched = true
		if route.method != r.Method {
			continue
		}
		if r.Method == http.MethodPost || r.Method == http.MethodPut {
			contentType := r.Header.Get("Content-Type")
			if !strings.HasPrefix(contentType, "application/json") {
				writeError(w, http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
					"content type must be application/json", nil, nil)
				return
			}
		}
		route.handler(w, r)
		return
	}

	if pathMatched {
		writeError(w, http.StatusMethodNotAllowed, CodeMethodNotAllowed,
			"method "+r.Method+" is not allowed for "+path, nil, nil)
		return
	}

	writeError(w, http.StatusNotFound, CodeNotFound,
		"route "+path+" not found", nil, nil)
}

func routeMatches(pattern, path string) bool {
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

func (h *Handler) getCapabilities(w http.ResponseWriter, _ *http.Request) {
	capabilities := h.capabilities()
	writeJSON(w, capabilities)
}

// capabilities returns the capabilities restricted to the services actually
// attached to this handler.
func (h *Handler) capabilities() Capabilities {
	capabilities := NewCapabilities(h.control, h.buildInfo, h.stationID)
	jobsReady := h.jobs != nil
	capabilities.Features.Switch = jobsReady
	capabilities.Features.Rotate = jobsReady
	capabilities.Features.Rollback = jobsReady
	capabilities.Features.DryRun = jobsReady
	capabilities.Features.Drain = jobsReady
	capabilities.Features.DNSLadder = h.dns != nil
	capabilities.Features.TransportLadder = h.transport != nil
	capabilities.Features.EgressConsensus =
		capabilities.Features.EgressConsensus && h.egress != nil
	return capabilities
}

func (h *Handler) notImplemented(w http.ResponseWriter, r *http.Request) {
	writeError(w, http.StatusNotImplemented, CodeNotImplemented,
		"route is not implemented yet",
		map[string]any{"path": r.URL.Path}, nil)
}
