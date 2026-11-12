package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/control/jobs"
	"github.com/qdm12/gluetun/internal/egress/verify"
)

const (
	maxSwitchTimeoutS     = 600
	defaultSwitchTimeoutS = 45
	defaultDrainTimeoutS  = 5
	defaultRollbackWaitS  = 45
	rollbackAllowance     = 120 * time.Second
)

type switchRequest struct {
	Target         switchTarget      `json:"target"`
	Constraints    switchConstraints `json:"constraints"`
	Options        switchOptions     `json:"options"`
	IdempotencyKey string            `json:"idempotency_key"`
}

type switchTarget struct {
	Hostname         string `json:"hostname"`
	EndpointIP       string `json:"endpoint_ip"`
	ExpectedEgressIP string `json:"expected_egress_ip"`
}

type switchConstraints struct {
	RequireNewIP     bool     `json:"require_new_ip"`
	RequireNewSubnet bool     `json:"require_new_subnet"`
	ExcludeIPs       []string `json:"exclude_ips"`
	ExcludeSubnets   []string `json:"exclude_subnets"`
	ForbiddenIPs     []string `json:"forbidden_ips"`
}

type switchOptions struct {
	DryRun          bool            `json:"dry_run"`
	Wait            bool            `json:"wait"`
	TimeoutS        *int            `json:"timeout_s"`
	TransportPolicy json.RawMessage `json:"transport_policy"`
	Drain           drainOption     `json:"drain"`
	Supersede       bool            `json:"supersede"`
	Verify          verifyOption    `json:"verify"`
}

type drainOption struct {
	Enabled  bool `json:"enabled"`
	TimeoutS *int `json:"timeout_s"`
}

type verifyOption struct {
	Quorum     *int  `json:"quorum"`
	MinSources *int  `json:"min_sources"`
	Canary     *bool `json:"canary"`
}

type plannedResponse struct {
	State          string    `json:"state"`
	Plan           jobs.Plan `json:"plan"`
	WouldCutTunnel bool      `json:"would_cut_tunnel"`
}

type noopResponse struct {
	State string    `json:"state"`
	Job   *jobs.Job `json:"job"`
}

func (h *Handler) postSwitch(w http.ResponseWriter, r *http.Request) {
	h.submitSwitch(w, r, jobs.KindSwitch)
}

func (h *Handler) submitSwitch(w http.ResponseWriter, r *http.Request,
	kind jobs.Kind,
) {
	if h.jobs == nil {
		writeNotReady(w)
		return
	}

	request, err := parseSwitchRequest(w, r, kind)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
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

func (h *Handler) respondWithJob(w http.ResponseWriter, r *http.Request,
	submission jobs.Submission, timeout time.Duration,
) {
	if submission.Replayed {
		w.Header().Set("Location", jobLocation(submission.Job.ID))
		writeJSONStatus(w, http.StatusOK, submission.Job)
		return
	}

	if timeout <= 0 {
		w.Header().Set("Location", jobLocation(submission.Job.ID))
		writeJSONStatus(w, http.StatusAccepted, submission.Job)
		return
	}

	job, completed := h.waitForJob(r.Context(), submission.Job.ID, timeout)
	if job.ID == "" {
		job = submission.Job
	}
	w.Header().Set("Location", jobLocation(job.ID))
	if completed && jobs.IsTerminal(job.State) {
		writeJSONStatus(w, http.StatusOK, job)
		return
	}
	writeJSONStatus(w, http.StatusAccepted, job)
}

func (h *Handler) waitForJob(ctx context.Context, id string,
	timeout time.Duration,
) (job jobs.Job, completed bool) {
	waitCtx, cancel := context.WithTimeout(ctx, timeout+rollbackAllowance)
	defer cancel()
	job, err := h.jobs.Wait(waitCtx, id)
	if err != nil {
		return job, false
	}
	return job, true
}

func parseSwitchRequest(w http.ResponseWriter, r *http.Request,
	kind jobs.Kind,
) (request jobs.SwitchRequest, err error) {
	body, err := readJSONBody(w, r)
	if err != nil {
		return jobs.SwitchRequest{}, err
	}

	var parsed switchRequest
	err = json.Unmarshal(body, &parsed)
	if err != nil {
		return jobs.SwitchRequest{}, fmt.Errorf("decoding JSON: %w", err)
	}
	if parsed.Options.Supersede {
		return jobs.SwitchRequest{},
			errors.New("supersede is not implemented")
	}

	target := jobs.SwitchTarget{
		Hostname: strings.TrimSpace(parsed.Target.Hostname),
	}
	target.EndpointIP, err = parseOptionalAddr(parsed.Target.EndpointIP,
		"endpoint_ip")
	if err != nil {
		return jobs.SwitchRequest{}, err
	}
	target.ExpectedEgressIP, err = parseOptionalAddr(
		parsed.Target.ExpectedEgressIP, "expected_egress_ip")
	if err != nil {
		return jobs.SwitchRequest{}, err
	}

	constraints, err := parseConstraints(parsed.Constraints)
	if err != nil {
		return jobs.SwitchRequest{}, err
	}

	timeout, err := parseTimeout(parsed.Options.TimeoutS, defaultSwitchTimeoutS)
	if err != nil {
		return jobs.SwitchRequest{}, err
	}

	policy, err := parseTransportPolicy(parsed.Options.TransportPolicy)
	if err != nil {
		return jobs.SwitchRequest{}, err
	}

	drainTimeout, err := parseTimeout(parsed.Options.Drain.TimeoutS,
		defaultDrainTimeoutS)
	if err != nil {
		return jobs.SwitchRequest{}, fmt.Errorf("drain: %w", err)
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

	return jobs.SwitchRequest{
		Kind:        kind,
		Target:      target,
		Constraints: constraints,
		Options: jobs.SwitchOptions{
			DryRun:          parsed.Options.DryRun,
			Wait:            parsed.Options.Wait,
			Timeout:         timeout,
			TransportPolicy: policy,
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

func parseConstraints(parsed switchConstraints) (jobs.SwitchConstraints,
	error,
) {
	constraints := jobs.SwitchConstraints{
		RequireNewIP:     parsed.RequireNewIP,
		RequireNewSubnet: parsed.RequireNewSubnet,
	}
	var err error
	constraints.ExcludeIPs, err = parseAddrList(parsed.ExcludeIPs, "exclude_ips")
	if err != nil {
		return jobs.SwitchConstraints{}, err
	}
	constraints.ForbiddenIPs, err = parseAddrList(parsed.ForbiddenIPs,
		"forbidden_ips")
	if err != nil {
		return jobs.SwitchConstraints{}, err
	}
	constraints.ExcludeSubnets, err = parsePrefixList(parsed.ExcludeSubnets,
		"exclude_subnets")
	if err != nil {
		return jobs.SwitchConstraints{}, err
	}
	return constraints, nil
}

func parseTransportPolicy(raw json.RawMessage) ([]jobs.Transport, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	var single string
	err := json.Unmarshal(raw, &single)
	if err == nil {
		if single == "" || single == "auto" {
			return nil, nil
		}
		return []jobs.Transport{jobs.Transport(single)}, nil
	}

	var list []string
	err = json.Unmarshal(raw, &list)
	if err != nil {
		return nil, errors.New(
			"transport_policy must be \"auto\", a transport or a list")
	}
	if len(list) == 0 {
		return nil, nil
	}
	policy := make([]jobs.Transport, len(list))
	for index, value := range list {
		if value == "auto" {
			return nil, errors.New(
				"transport_policy list cannot contain \"auto\"")
		}
		policy[index] = jobs.Transport(value)
	}
	return policy, nil
}

func parseTimeout(value *int, defaultValue int) (time.Duration, error) {
	seconds := defaultValue
	if value != nil {
		seconds = *value
	}
	if seconds <= 0 || seconds > maxSwitchTimeoutS {
		return 0, fmt.Errorf("timeout_s must be between 1 and %d",
			maxSwitchTimeoutS)
	}
	return time.Duration(seconds) * time.Second, nil
}

func parseOptionalAddr(value, field string) (netip.Addr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return netip.Addr{}, nil
	}
	address, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%s: %w", field, err)
	}
	return address.Unmap(), nil
}

func parseAddrList(values []string, field string) ([]netip.Addr, error) {
	if len(values) == 0 {
		return nil, nil
	}
	addresses := make([]netip.Addr, 0, len(values))
	for _, value := range values {
		address, err := parseOptionalAddr(value, field)
		if err != nil {
			return nil, err
		}
		if !address.IsValid() {
			return nil, fmt.Errorf("%s contains an empty address", field)
		}
		addresses = append(addresses, address)
	}
	return addresses, nil
}

func parsePrefixList(values []string, field string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, nil
	}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

func readJSONBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	reader := http.MaxBytesReader(w, r.Body, maxBodyBytes)
	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading body: %w", err)
	}
	if len(body) == 0 {
		return nil, errors.New("request body is empty")
	}
	return body, nil
}

func jobLocation(id string) string {
	return "/v1/vpn/jobs/" + id
}
