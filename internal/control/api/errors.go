package api

import (
	"encoding/json"
	"net/http"
)

// Error codes returned by the control plane API.
const (
	CodeInvalidRequest      = "invalid_request"
	CodeMissingField        = "missing_field"
	CodeUnauthorized        = "unauthorized"
	CodeForbiddenScope      = "forbidden_scope"
	CodeNotFound            = "not_found"
	CodeMethodNotAllowed    = "method_not_allowed"
	CodeUnsupportedMedia    = "unsupported_media_type"
	CodeActiveJob           = "active_job"
	CodeIdempotencyConflict = "idempotency_conflict"
	CodeNoSnapshot          = "no_snapshot"
	CodeUnknownTarget       = "unknown_target"
	CodeInvalidTarget       = "invalid_target"
	CodeEndpointIPMismatch  = "endpoint_ip_mismatch"
	CodeInsufficientSources = "insufficient_sources"
	CodeRateLimited         = "rate_limited"
	CodePayloadTooLarge     = "payload_too_large"
	CodeInternalError       = "internal_error"
	CodeNotReady            = "not_ready"
	CodeNotImplemented      = "not_implemented"
)

type errorBody struct {
	Error errorDetail `json:"error"`
}

type errorDetail struct {
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	JobID     *string        `json:"job_id"`
	Retryable bool           `json:"retryable"`
}

func writeError(w http.ResponseWriter, status int, code, message string,
	details map[string]any, jobID *string, //nolint:unparam // reserved for job-scoped errors
) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	body := errorBody{
		Error: errorDetail{
			Code:      code,
			Message:   message,
			Details:   details,
			JobID:     jobID,
			Retryable: status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable,
		},
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		return
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	writeJSONStatus(w, http.StatusOK, value)
}

func writeJSONStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}
