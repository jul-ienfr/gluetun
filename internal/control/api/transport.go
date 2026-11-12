package api

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	transportpkg "github.com/qdm12/gluetun/internal/vpn/transport"
)

type transportPolicyResponse struct {
	Ladder []transportpkg.Transport `json:"ladder"`
}

type transportBreakerResponse struct {
	State    transportpkg.BreakerState `json:"state"`
	Failures int                       `json:"failures"`
	RetryAt  *time.Time                `json:"retry_at,omitempty"`
}

type transportAttemptResponse struct {
	Transport transportpkg.Transport     `json:"transport"`
	Server    string                     `json:"server,omitempty"`
	Result    transportpkg.AttemptResult `json:"result"`
	Reason    transportpkg.Reason        `json:"reason,omitempty"`
	LatencyMS int64                      `json:"latency_ms"`
	NextRetry *time.Time                 `json:"next_retry,omitempty"`
}

type transportStateResponse struct {
	ActiveTransport *transportpkg.Transport             `json:"active_transport"`
	Policy          transportPolicyResponse             `json:"policy"`
	Phase           transportpkg.Phase                  `json:"phase"`
	Cycle           int                                 `json:"cycle"`
	Breaker         map[string]transportBreakerResponse `json:"breaker"`
	Attempts        []transportAttemptResponse          `json:"attempts"`
	NextAttemptAt   *time.Time                          `json:"next_attempt_at"`
	UpdatedAt       time.Time                           `json:"updated_at"`
}

type transportResetRequest struct {
	Transport *transportpkg.Transport `json:"transport"`
}

type transportResetResponse struct {
	Transport string                    `json:"transport"`
	Breaker   transportpkg.BreakerState `json:"breaker"`
	Reset     bool                      `json:"reset"`
}

func (h *Handler) getTransportState(w http.ResponseWriter, _ *http.Request) {
	if h.transport == nil {
		writeTransportNotReady(w)
		return
	}
	state, available := h.transport.TransportState()
	if !available {
		writeTransportNotReady(w)
		return
	}
	policy := h.transport.TransportPolicy()

	response := transportStateResponse{
		ActiveTransport: state.Active,
		Policy: transportPolicyResponse{
			Ladder: append([]transportpkg.Transport(nil), policy.Ladder...),
		},
		Phase:     state.Phase,
		Cycle:     state.Cycle,
		Breaker:   make(map[string]transportBreakerResponse, len(policy.Ladder)),
		Attempts:  make([]transportAttemptResponse, 0, len(state.Attempts)),
		UpdatedAt: state.UpdatedAt,
	}
	if state.NextAt != nil {
		next := *state.NextAt
		response.NextAttemptAt = &next
	}

	for _, transport := range policy.Ladder {
		breaker := state.Breakers[transport]
		if breaker.State == "" {
			breaker.State = transportpkg.BreakerClosed
		}
		entry := transportBreakerResponse{
			State:    breaker.State,
			Failures: breaker.Failures,
		}
		if !breaker.RetryAt.IsZero() {
			retryAt := breaker.RetryAt
			entry.RetryAt = &retryAt
		}
		response.Breaker[string(transport)] = entry
	}

	for _, attempt := range state.Attempts {
		converted := transportAttemptResponse{
			Transport: attempt.Transport,
			Server:    attempt.Server,
			Result:    attempt.Result,
			Reason:    attempt.Reason,
			LatencyMS: attempt.Latency.Milliseconds(),
		}
		if !attempt.NextRetry.IsZero() {
			nextRetry := attempt.NextRetry
			converted.NextRetry = &nextRetry
		}
		response.Attempts = append(response.Attempts, converted)
	}

	writeJSON(w, response)
}

func (h *Handler) postTransportReset(w http.ResponseWriter, r *http.Request) {
	if h.transport == nil {
		writeTransportNotReady(w)
		return
	}

	var request transportResetRequest
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"reading body: "+err.Error(), nil, nil)
		return
	}
	if len(body) > 0 {
		err = json.Unmarshal(body, &request)
		if err != nil {
			writeError(w, http.StatusBadRequest, CodeInvalidRequest,
				"invalid request body: "+err.Error(), nil, nil)
			return
		}
	}

	if request.Transport != nil && !request.Transport.Valid() {
		writeError(w, http.StatusUnprocessableEntity, CodeInvalidTarget,
			"unknown transport", map[string]any{
				"transport": string(*request.Transport),
			}, nil)
		return
	}

	err = h.transport.ResetTransport(request.Transport)
	switch {
	case errors.Is(err, transportpkg.ErrInvalidPolicy):
		writeError(w, http.StatusUnprocessableEntity, CodeInvalidTarget,
			err.Error(), nil, nil)
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, CodeInternalError,
			err.Error(), nil, nil)
		return
	}

	name := "all"
	breaker := transportpkg.BreakerClosed
	if request.Transport != nil {
		name = string(*request.Transport)
	}
	writeJSON(w, transportResetResponse{
		Transport: name,
		Breaker:   breaker,
		Reset:     true,
	})
}

func writeTransportNotReady(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, CodeNotReady,
		"control plane transport service is not available", nil, nil)
}
