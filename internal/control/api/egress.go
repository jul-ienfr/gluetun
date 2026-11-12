package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
	"github.com/qdm12/gluetun/internal/egress/verify"
)

const (
	defaultEgressHistoryLimit = 50
	maxEgressHistoryLimit     = 500
	maxEgressTimeoutS         = 120
	egressRetryAfterMS        = 1000
)

type egressHistoryItem struct {
	Verified    bool              `json:"verified"`
	Reason      *egress.Reason    `json:"reason,omitempty"`
	IP          netip.Addr        `json:"ip,omitzero"`
	Family      int               `json:"family"`
	Quorum      int               `json:"quorum"`
	SourceCount int               `json:"source_count"`
	Confidence  egress.Confidence `json:"confidence"`
	Dissenters  []string          `json:"dissenters"`
	CanaryOK    *bool             `json:"canary_ok,omitempty"`
	Cached      bool              `json:"cached"`
	VerifiedAt  time.Time         `json:"verified_at"`
	TTLS        int               `json:"ttl_s"`
}

func (h *Handler) getEgress(w http.ResponseWriter, r *http.Request) {
	h.verifyEgress(w, r, false)
}

func (h *Handler) getEgressVerify(w http.ResponseWriter, r *http.Request) {
	h.verifyEgress(w, r, true)
}

func (h *Handler) verifyEgress(w http.ResponseWriter, r *http.Request,
	defaultFresh bool,
) {
	if h.egress == nil {
		writeEgressDisabled(w)
		return
	}

	request, err := parseEgressRequest(r, defaultFresh)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(), nil, nil)
		return
	}

	verification, err := h.egress.Verify(r.Context(), request)
	if err != nil {
		writeEgressFailure(w, err)
		return
	}

	if verification.Reason != nil &&
		*verification.Reason == egress.ReasonInsufficientSources {
		writeError(w, http.StatusUnprocessableEntity, CodeInsufficientSources,
			"not enough egress sources to verify the public IP",
			map[string]any{"verification": verification}, nil)
		return
	}

	writeJSON(w, verification)
}

func (h *Handler) getEgressCanary(w http.ResponseWriter, r *http.Request) {
	if h.egress == nil {
		writeEgressDisabled(w)
		return
	}

	result, err := h.egress.CheckCanary(r.Context())
	if err != nil {
		writeEgressFailure(w, err)
		return
	}
	writeJSON(w, result)
}

func (h *Handler) getEgressHistory(w http.ResponseWriter, r *http.Request) {
	if h.egress == nil {
		writeEgressDisabled(w)
		return
	}

	query := r.URL.Query()

	limit := defaultEgressHistoryLimit
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.ParseUint(raw, 10, 16)
		if err != nil || parsed == 0 {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest,
				"limit must be a positive integer", nil, nil)
			return
		}
		limit = min(int(parsed), maxEgressHistoryLimit)
	}

	var since time.Time
	if raw := query.Get("since"); raw != "" {
		parsed, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest,
				"since must be an RFC3339 timestamp", nil, nil)
			return
		}
		since = parsed
	}

	verifications := h.egress.History(limit, since)
	items := make([]egressHistoryItem, len(verifications))
	for index, verification := range verifications {
		items[index] = newEgressHistoryItem(verification)
	}

	writeJSON(w, map[string]any{
		"items": items,
		"count": len(items),
	})
}

func parseEgressRequest(r *http.Request, defaultFresh bool) (
	request verify.Request, err error,
) {
	query := r.URL.Query()

	request.Fresh = defaultFresh
	if raw := query.Get("fresh"); raw != "" {
		request.Fresh, err = strconv.ParseBool(raw)
		if err != nil {
			return request, fmt.Errorf("fresh must be a boolean: %w", err)
		}
	}

	request.Quorum, err = positiveIntQuery(query, "quorum")
	if err != nil {
		return request, err
	}

	request.MinSources, err = positiveIntQuery(query, "min_sources")
	if err != nil {
		return request, err
	}

	if raw := query.Get("canary"); raw != "" {
		var canary bool
		canary, err = strconv.ParseBool(raw)
		if err != nil {
			return request, fmt.Errorf("canary must be a boolean: %w", err)
		}
		request.Canary = &canary
	}

	timeoutS, err := positiveIntQuery(query, "timeout_s")
	if err != nil {
		return request, err
	}
	if timeoutS > maxEgressTimeoutS {
		return request, fmt.Errorf("timeout_s must not exceed %d", maxEgressTimeoutS)
	}
	request.Timeout = time.Duration(timeoutS) * time.Second

	return request, nil
}

func positiveIntQuery(query url.Values, name string) (value int, err error) {
	raw := query.Get(name)
	if raw == "" {
		return 0, nil
	}
	parsed, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || parsed == 0 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return int(parsed), nil
}

func newEgressHistoryItem(verification egress.Verification) egressHistoryItem {
	item := egressHistoryItem{
		Verified:    verification.Verified,
		Reason:      verification.Reason,
		IP:          verification.IP,
		Family:      verification.Family,
		Quorum:      verification.Quorum,
		SourceCount: verification.SourceCount,
		Confidence:  verification.Confidence,
		Dissenters:  verification.Dissenters,
		Cached:      verification.Cached,
		VerifiedAt:  verification.VerifiedAt,
		TTLS:        verification.TTLS,
	}
	if verification.Canary != nil {
		ok := verification.Canary.OK
		item.CanaryOK = &ok
	}
	return item
}

func writeEgressDisabled(w http.ResponseWriter) {
	writeError(w, http.StatusBadRequest, CodeInvalidRequest,
		"egress verification is disabled", nil, nil)
}

func writeEgressFailure(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, verify.ErrCanaryDisabled):
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(), nil, nil)
	case errors.Is(err, verify.ErrTimeout):
		writeError(w, http.StatusServiceUnavailable, CodeNotReady,
			"egress verification timed out",
			map[string]any{"retry_after_ms": egressRetryAfterMS}, nil)
	default:
		writeError(w, http.StatusInternalServerError, CodeInternalError,
			"egress verification failed", nil, nil)
	}
}
