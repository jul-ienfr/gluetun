package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/qdm12/gluetun/internal/control/jobs"
	"github.com/qdm12/gluetun/internal/egress/verify"
)

type rotateRequest struct {
	Candidates     []rotateCandidate `json:"candidates"`
	Policy         *rotatePolicy     `json:"policy"`
	Constraints    rotateConstraints `json:"constraints"`
	Options        switchOptions     `json:"options"`
	IdempotencyKey string            `json:"idempotency_key"`
}

type rotateCandidate struct {
	Hostname         string `json:"hostname"`
	EndpointIP       string `json:"endpoint_ip"`
	ExpectedEgressIP string `json:"expected_egress_ip"`
}

type rotatePolicy struct {
	Countries  []string `json:"countries"`
	Regions    []string `json:"regions"`
	Cities     []string `json:"cities"`
	Categories []string `json:"categories"`
	Tiers      []string `json:"tiers"`
	FreeOnly   bool     `json:"free_only"`
	Mode       string   `json:"mode"`
}

type rotateConstraints struct {
	RequireNewIP     bool     `json:"require_new_ip"`
	RequireNewSubnet bool     `json:"require_new_subnet"`
	ExcludeHostnames []string `json:"exclude_hostnames"`
	ExcludeIPs       []string `json:"exclude_ips"`
	ExcludeSubnets   []string `json:"exclude_subnets"`
	ForbiddenIPs     []string `json:"forbidden_ips"`
	MaxCandidates    *int     `json:"max_candidates"`
	MaxAttempts      *int     `json:"max_attempts"`
}

func (h *Handler) postRotate(w http.ResponseWriter, r *http.Request) {
	if h.jobs == nil {
		writeNotReady(w)
		return
	}

	request, err := parseRotateRequest(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}

	submission, err := h.jobs.SubmitRotation(r.Context(), request)
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

func parseRotateRequest(w http.ResponseWriter, r *http.Request) (
	request jobs.RotationRequest, err error,
) {
	body, err := readJSONBody(w, r)
	if err != nil {
		return jobs.RotationRequest{}, err
	}

	var parsed rotateRequest
	err = json.Unmarshal(body, &parsed)
	if err != nil {
		return jobs.RotationRequest{}, fmt.Errorf("decoding JSON: %w", err)
	}
	if parsed.Options.DryRun {
		return jobs.RotationRequest{},
			errors.New("dry_run is not supported for rotate")
	}
	if parsed.Options.Supersede {
		return jobs.RotationRequest{},
			errors.New("supersede is not implemented")
	}

	candidates, err := parseRotateCandidates(parsed.Candidates)
	if err != nil {
		return jobs.RotationRequest{}, err
	}
	policy := parseRotatePolicy(parsed.Policy)

	constraints, err := parseRotateConstraints(parsed.Constraints)
	if err != nil {
		return jobs.RotationRequest{}, err
	}

	timeout, err := parseTimeout(parsed.Options.TimeoutS, defaultSwitchTimeoutS)
	if err != nil {
		return jobs.RotationRequest{}, err
	}
	transportPolicy, err := parseTransportPolicy(parsed.Options.TransportPolicy)
	if err != nil {
		return jobs.RotationRequest{}, err
	}
	drainTimeout, err := parseTimeout(parsed.Options.Drain.TimeoutS,
		defaultDrainTimeoutS)
	if err != nil {
		return jobs.RotationRequest{}, fmt.Errorf("drain: %w", err)
	}

	verifyRequest := verify.Request{
		Canary: parsed.Options.Verify.Canary,
	}
	if parsed.Options.Verify.Quorum != nil {
		verifyRequest.Quorum = *parsed.Options.Verify.Quorum
	}
	if parsed.Options.Verify.MinSources != nil {
		verifyRequest.MinSources = *parsed.Options.Verify.MinSources
	}

	return jobs.RotationRequest{
		Candidates:  candidates,
		Policy:      policy,
		Constraints: constraints,
		Options: jobs.SwitchOptions{
			Wait:            parsed.Options.Wait,
			Timeout:         timeout,
			TransportPolicy: transportPolicy,
			Drain: jobs.DrainOption{
				Enabled: parsed.Options.Drain.Enabled,
				Timeout: drainTimeout,
			},
			Verify: verifyRequest,
		},
		IdempotencyKey: strings.TrimSpace(parsed.IdempotencyKey),
		RequestHash:    jobs.HashBody(body),
	}, nil
}

func parseRotateCandidates(parsed []rotateCandidate) ([]jobs.RotationTarget,
	error,
) {
	candidates := make([]jobs.RotationTarget, 0, len(parsed))
	for index, candidate := range parsed {
		target := jobs.RotationTarget{
			Hostname: strings.TrimSpace(candidate.Hostname),
		}
		var err error
		target.EndpointIP, err = parseOptionalAddr(candidate.EndpointIP,
			fmt.Sprintf("candidates[%d].endpoint_ip", index))
		if err != nil {
			return nil, err
		}
		target.ExpectedEgressIP, err = parseOptionalAddr(
			candidate.ExpectedEgressIP,
			fmt.Sprintf("candidates[%d].expected_egress_ip", index))
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, target)
	}
	return candidates, nil
}

func parseRotatePolicy(parsed *rotatePolicy) *jobs.RotationPolicy {
	if parsed == nil {
		return nil
	}
	return &jobs.RotationPolicy{
		Countries:  cleanStrings(parsed.Countries),
		Regions:    cleanStrings(parsed.Regions),
		Cities:     cleanStrings(parsed.Cities),
		Categories: cleanStrings(parsed.Categories),
		Tiers:      cleanStrings(parsed.Tiers),
		FreeOnly:   parsed.FreeOnly,
		Mode:       strings.TrimSpace(parsed.Mode),
	}
}

func parseRotateConstraints(parsed rotateConstraints) (jobs.RotationConstraints,
	error,
) {
	constraints := jobs.RotationConstraints{
		RequireNewIP:     parsed.RequireNewIP,
		RequireNewSubnet: parsed.RequireNewSubnet,
		ExcludeHostnames: cleanStrings(parsed.ExcludeHostnames),
	}
	var err error
	constraints.ExcludeIPs, err = parseAddrList(parsed.ExcludeIPs,
		"exclude_ips")
	if err != nil {
		return jobs.RotationConstraints{}, err
	}
	constraints.ForbiddenIPs, err = parseAddrList(parsed.ForbiddenIPs,
		"forbidden_ips")
	if err != nil {
		return jobs.RotationConstraints{}, err
	}
	constraints.ExcludeSubnets, err = parsePrefixList(parsed.ExcludeSubnets,
		"exclude_subnets")
	if err != nil {
		return jobs.RotationConstraints{}, err
	}
	constraints.MaxCandidates, err = parsePositive(parsed.MaxCandidates,
		"max_candidates")
	if err != nil {
		return jobs.RotationConstraints{}, err
	}
	constraints.MaxAttempts, err = parsePositive(parsed.MaxAttempts,
		"max_attempts")
	if err != nil {
		return jobs.RotationConstraints{}, err
	}
	return constraints, nil
}

func parsePositive(value *int, field string) (int, error) {
	if value == nil {
		return 0, nil
	}
	if *value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", field)
	}
	return *value, nil
}

func cleanStrings(values []string) []string {
	cleaned := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			cleaned = append(cleaned, value)
		}
	}
	return cleaned
}
