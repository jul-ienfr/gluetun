package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/qdm12/gluetun/internal/dns/ladder"
)

const (
	serverDNSProbePathIndex = 2
	maxProbeTimeout         = 30 * time.Second
)

type dnsProbeRequest struct {
	Tier     string  `json:"tier"`
	Domain   string  `json:"domain"`
	TimeoutS float64 `json:"timeout_s"`
	DryRun   bool    `json:"dry_run"`
}

type dnsTiersResponse struct {
	Ladder []ladder.TierType `json:"ladder"`
	Tiers  []ladder.Tier     `json:"tiers"`
}

func (h *Handler) getDNSState(w http.ResponseWriter, _ *http.Request) {
	if h.dns == nil {
		writeDNSNotReady(w)
		return
	}
	snapshot, available := h.dns.DNSState()
	if !available {
		writeDNSNotReady(w)
		return
	}
	writeJSON(w, snapshot)
}

func (h *Handler) getDNSTiers(w http.ResponseWriter, _ *http.Request) {
	if h.dns == nil {
		writeDNSNotReady(w)
		return
	}
	snapshot, available := h.dns.DNSState()
	if !available {
		writeDNSNotReady(w)
		return
	}
	writeJSON(w, dnsTiersResponse{
		Ladder: snapshot.Ladder,
		Tiers:  snapshot.Tiers,
	})
}

func (h *Handler) postDNSProbe(w http.ResponseWriter, r *http.Request) {
	if h.dns == nil {
		writeDNSNotReady(w)
		return
	}

	body, err := readJSONBody(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}
	var request dnsProbeRequest
	err = json.Unmarshal(body, &request)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"invalid request body: "+err.Error(), nil, nil)
		return
	}
	if request.Tier == "" {
		writeError(w, http.StatusBadRequest, CodeMissingField,
			"tier is required", nil, nil)
		return
	}

	var timeout time.Duration
	if request.TimeoutS > 0 {
		timeout = time.Duration(request.TimeoutS * float64(time.Second))
		if timeout > maxProbeTimeout {
			timeout = maxProbeTimeout
		}
	}

	result, err := h.dns.DNSProbe(r.Context(), request.Tier, request.Domain,
		timeout, request.DryRun)
	switch {
	case errors.Is(err, ladder.ErrUnknownTier):
		writeError(w, http.StatusUnprocessableEntity, CodeInvalidTarget,
			err.Error(), map[string]any{"tier": request.Tier}, nil)
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}

	writeJSON(w, result)
}

func writeDNSNotReady(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, CodeNotReady,
		"control plane DNS service is not available", nil, nil)
}
