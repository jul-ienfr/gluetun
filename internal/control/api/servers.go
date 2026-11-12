package api

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/qdm12/gluetun/internal/control/catalog"
)

const (
	serverHostnamePathIndex = 1
	catalogRefreshInterval  = time.Minute
)

func (h *Handler) getServers(w http.ResponseWriter, r *http.Request) {
	if h.catalog == nil {
		writeCatalogNotReady(w)
		return
	}

	query, err := catalog.QueryFromValues(r.URL.Query())
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}

	page, err := h.catalog.Query(query)
	if err != nil {
		if errors.Is(err, catalog.ErrInvalidCursor) {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest,
				"invalid cursor", nil, nil)
			return
		}
		writeError(w, http.StatusInternalServerError, CodeInternalError,
			"reading server catalogue", nil, nil)
		return
	}

	writeJSON(w, page)
}

func (h *Handler) getServer(w http.ResponseWriter, r *http.Request) {
	if h.catalog == nil {
		writeCatalogNotReady(w)
		return
	}

	hostname := requestPathSegment(r, serverHostnamePathIndex)
	detail, found, err := h.catalog.Detail(hostname)
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternalError,
			"reading server catalogue", nil, nil)
		return
	}
	if !found {
		writeError(w, http.StatusNotFound, CodeNotFound,
			"server "+hostname+" not found", nil, nil)
		return
	}

	writeJSON(w, detail)
}

func (h *Handler) getServerFacets(w http.ResponseWriter, _ *http.Request) {
	if h.catalog == nil {
		writeCatalogNotReady(w)
		return
	}

	facets, err := h.catalog.Facets()
	if err != nil {
		writeError(w, http.StatusInternalServerError, CodeInternalError,
			"reading server catalogue", nil, nil)
		return
	}

	writeJSON(w, facets)
}

func writeCatalogNotReady(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, CodeNotReady,
		"control plane catalogue service is not available", nil, nil)
}

func (h *Handler) postServersRefresh(w http.ResponseWriter, r *http.Request) {
	if h.catalog == nil {
		writeCatalogNotReady(w)
		return
	}

	h.refreshMutex.Lock()
	defer h.refreshMutex.Unlock()

	now := h.now()
	if !h.lastRefresh.IsZero() {
		elapsed := now.Sub(h.lastRefresh)
		if elapsed < catalogRefreshInterval {
			retryAfter := catalogRefreshInterval - elapsed
			seconds := int(math.Ceil(retryAfter.Seconds()))
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
			writeError(w, http.StatusTooManyRequests, CodeRateLimited,
				"catalogue refresh is rate limited",
				map[string]any{"retry_after_s": seconds}, nil)
			return
		}
	}

	result, err := h.catalog.Refresh(r.Context())
	if err != nil {
		if errors.Is(err, catalog.ErrRefreshUnsupported) {
			writeError(w, http.StatusNotImplemented, CodeNotImplemented,
				"catalogue source does not support refresh", nil, nil)
			return
		}
		writeError(w, http.StatusInternalServerError, CodeInternalError,
			"refreshing server catalogue", nil, nil)
		return
	}
	h.lastRefresh = now
	writeJSON(w, result)
}
