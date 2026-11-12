package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/qdm12/gluetun/internal/control/jobs"
)

type rollbackRequest struct {
	To             string `json:"to"`
	Wait           bool   `json:"wait"`
	TimeoutS       *int   `json:"timeout_s"`
	IdempotencyKey string `json:"idempotency_key"`
}

func (h *Handler) postRollback(w http.ResponseWriter, r *http.Request) {
	if h.jobs == nil {
		writeNotReady(w)
		return
	}

	body, err := readJSONBody(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}

	var parsed rollbackRequest
	err = json.Unmarshal(body, &parsed)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"decoding JSON: "+err.Error(), nil, nil)
		return
	}

	to := strings.TrimSpace(parsed.To)
	if to == "" {
		to = "last_committed"
	}
	if to != "last_committed" {
		writeError(w, http.StatusUnprocessableEntity, CodeInvalidTarget,
			"only the last_committed snapshot can be restored", nil, nil)
		return
	}

	timeout, err := parseTimeout(parsed.TimeoutS, defaultRollbackWaitS)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}

	submission, err := h.jobs.SubmitRollback(r.Context(), jobs.RollbackRequest{
		RequestHash:    jobs.HashBody(body),
		IdempotencyKey: strings.TrimSpace(parsed.IdempotencyKey),
		RequestedBy:    "",
	})
	if err != nil {
		writeJobsError(w, err)
		return
	}

	if parsed.Wait {
		h.respondWithJob(w, r, submission, timeout)
		return
	}
	h.respondWithJob(w, r, submission, 0)
}
