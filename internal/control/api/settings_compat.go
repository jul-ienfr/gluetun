package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/qdm12/gluetun/internal/control/jobs"
)

type settingsCompatRequest struct {
	Target          *switchTarget `json:"target"`
	DryRun          bool          `json:"dry_run"`
	Wait            bool          `json:"wait"`
	RequireVerified *bool         `json:"require_verified"`
	TimeoutS        *int          `json:"timeout_s"`
}

// IsControlledSettingsBody reports whether a PUT /v1/vpn/settings body uses the
// controlled mode fields. Legacy settings bodies keep the upstream behaviour.
func IsControlledSettingsBody(body []byte) bool {
	var fields map[string]json.RawMessage
	err := json.Unmarshal(body, &fields)
	if err != nil {
		return false
	}
	for _, field := range []string{"target", "dry_run", "wait",
		"require_verified"} {
		if _, ok := fields[field]; ok {
			return true
		}
	}
	return false
}

// ServeSettings handles the controlled mode of PUT /v1/vpn/settings. Legacy
// bodies are rejected here because the upstream handler owns them.
func (h *Handler) ServeSettings(w http.ResponseWriter, r *http.Request) {
	if h.jobs == nil {
		writeNotReady(w)
		return
	}
	contentType := r.Header.Get("Content-Type")
	if !strings.HasPrefix(contentType, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, CodeUnsupportedMedia,
			"content type must be application/json", nil, nil)
		return
	}

	body, err := readJSONBody(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}
	if !IsControlledSettingsBody(body) {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"legacy settings must use the upstream endpoint", nil, nil)
		return
	}

	var parsed settingsCompatRequest
	err = json.Unmarshal(body, &parsed)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			"decoding JSON: "+err.Error(), nil, nil)
		return
	}
	if parsed.Target == nil {
		writeError(w, http.StatusBadRequest, CodeMissingField,
			"target is required in controlled settings mode", nil, nil)
		return
	}

	target := jobs.SwitchTarget{
		Hostname: strings.TrimSpace(parsed.Target.Hostname),
	}
	if target.Hostname == "" {
		writeError(w, http.StatusBadRequest, CodeMissingField,
			"target.hostname is required", nil, nil)
		return
	}
	target.EndpointIP, err = parseOptionalAddr(parsed.Target.EndpointIP,
		"target.endpoint_ip")
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}
	target.ExpectedEgressIP, err = parseOptionalAddr(
		parsed.Target.ExpectedEgressIP, "target.expected_egress_ip")
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}

	timeout, err := parseTimeout(parsed.TimeoutS, defaultSwitchTimeoutS)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}

	request := jobs.SwitchRequest{
		Kind:   jobs.KindSwitch,
		Target: target,
		Options: jobs.SwitchOptions{
			DryRun:  parsed.DryRun,
			Wait:    parsed.Wait,
			Timeout: timeout,
		},
		RequestHash: jobs.HashBody(body),
	}

	if request.Options.DryRun {
		result, planErr := h.jobs.Plan(r.Context(), request)
		if planErr != nil {
			writeJobsError(w, planErr)
			return
		}
		writeJSON(w, plannedResponse{
			State:          "planned",
			Plan:           result.Plan,
			WouldCutTunnel: result.WouldCutTunnel,
		})
		return
	}

	submission, err := h.jobs.Submit(r.Context(), request)
	if err != nil {
		writeJobsError(w, err)
		return
	}
	if submission.Noop {
		writeJSON(w, noopResponse{State: "noop", Job: nil})
		return
	}
	if request.Options.Wait {
		h.respondWithJob(w, r, submission, request.Options.Timeout)
		return
	}
	h.respondWithJob(w, r, submission, 0)
}
