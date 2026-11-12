package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/qdm12/gluetun/internal/control/jobs"
)

const maxJobsLimit = 200

const jobIDPathIndex = 2

type jobsListResponse struct {
	Jobs       []jobs.Job `json:"jobs"`
	NextCursor string     `json:"next_cursor,omitempty"`
}

func (h *Handler) getJobs(w http.ResponseWriter, r *http.Request) {
	if h.jobs == nil {
		writeNotReady(w)
		return
	}

	filter, err := parseJobsFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}
	page, err := h.jobs.List(filter)
	if err != nil {
		writeJobsError(w, err)
		return
	}
	writeJSON(w, jobsListResponse{
		Jobs:       page.Jobs,
		NextCursor: page.NextCursor,
	})
}

func (h *Handler) getJob(w http.ResponseWriter, r *http.Request) {
	if h.jobs == nil {
		writeNotReady(w)
		return
	}
	id := requestPathSegment(r, jobIDPathIndex)
	if id == "" {
		writeError(w, http.StatusNotFound, CodeNotFound, "job not found",
			nil, nil)
		return
	}
	job, found := h.jobs.Get(id)
	if !found {
		writeError(w, http.StatusNotFound, CodeNotFound, "job "+id+" not found",
			nil, nil)
		return
	}
	writeJSON(w, job)
}

func (h *Handler) postJobCancel(w http.ResponseWriter, r *http.Request) {
	if h.jobs == nil {
		writeNotReady(w)
		return
	}
	id := requestPathSegment(r, jobIDPathIndex)
	if id == "" {
		writeError(w, http.StatusNotFound, CodeNotFound, "job not found",
			nil, nil)
		return
	}
	job, err := h.jobs.Cancel(id)
	if err != nil {
		writeJobsError(w, err)
		return
	}
	writeJSON(w, job)
}

func parseJobsFilter(r *http.Request) (filter jobs.Filter, err error) {
	query := r.URL.Query()
	filter.State = jobs.State(strings.TrimSpace(query.Get("state")))
	filter.Kind = jobs.Kind(strings.TrimSpace(query.Get("kind")))
	filter.Cursor = strings.TrimSpace(query.Get("cursor"))

	since := strings.TrimSpace(query.Get("since"))
	if since != "" {
		filter.Since, err = time.Parse(time.RFC3339, since)
		if err != nil {
			return jobs.Filter{}, fmt.Errorf("since: %w", err)
		}
	}

	limit := strings.TrimSpace(query.Get("limit"))
	if limit != "" {
		filter.Limit, err = strconv.Atoi(limit)
		if err != nil {
			return jobs.Filter{}, fmt.Errorf("limit: %w", err)
		}
		if filter.Limit <= 0 || filter.Limit > maxJobsLimit {
			return jobs.Filter{}, fmt.Errorf("limit must be between 1 and %d",
				maxJobsLimit)
		}
	}
	return filter, nil
}

func requestPathSegment(r *http.Request, index int) string {
	path := r.RequestURI
	if position := strings.IndexByte(path, '?'); position >= 0 {
		path = path[:position]
	}
	segments := strings.Split(strings.Trim(path, "/"), "/")
	if index < 0 || index >= len(segments) {
		return ""
	}
	return segments[index]
}

func writeNotReady(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, CodeNotReady,
		"control plane jobs service is not available", nil, nil)
}

func writeJobsError(w http.ResponseWriter, err error) {
	var active *jobs.ActiveJobError
	switch {
	case errors.As(err, &active):
		writeError(w, http.StatusConflict, CodeActiveJob,
			"another job is already active",
			map[string]any{"active_job_id": active.ID}, nil)
	case errors.Is(err, jobs.ErrIdempotencyConflict):
		writeError(w, http.StatusConflict, CodeIdempotencyConflict,
			"idempotency key was used with another body", nil, nil)
	case errors.Is(err, jobs.ErrInvalidIdempotencyKey):
		writeError(w, http.StatusBadRequest, CodeInvalidRequest,
			err.Error(), nil, nil)
	case errors.Is(err, jobs.ErrJobNotFound):
		writeError(w, http.StatusNotFound, CodeNotFound, err.Error(), nil, nil)
	case errors.Is(err, jobs.ErrNoSnapshot):
		writeError(w, http.StatusConflict, CodeNoSnapshot,
			"no committed snapshot is available to roll back to", nil, nil)
	case errors.Is(err, jobs.ErrUnknownTarget):
		writeError(w, http.StatusUnprocessableEntity, CodeUnknownTarget,
			err.Error(), nil, nil)
	case errors.Is(err, jobs.ErrEndpointIPMismatch):
		writeError(w, http.StatusUnprocessableEntity, CodeEndpointIPMismatch,
			err.Error(), nil, nil)
	case errors.Is(err, jobs.ErrInvalidTarget),
		errors.Is(err, jobs.ErrTargetExcluded),
		errors.Is(err, jobs.ErrInvalidSwitchRequest),
		errors.Is(err, jobs.ErrNoCandidates),
		errors.Is(err, jobs.ErrExcludedCandidate),
		errors.Is(err, jobs.ErrMissingCredentials),
		errors.Is(err, jobs.ErrTransportUnsupported),
		errors.Is(err, jobs.ErrResolutionFailed),
		errors.Is(err, jobs.ErrEndpointUnreachable):
		writeError(w, http.StatusUnprocessableEntity, CodeInvalidTarget,
			err.Error(), map[string]any{"reason": jobs.Reason(err)}, nil)
	case errors.Is(err, jobs.ErrJobTerminal),
		errors.Is(err, jobs.ErrInvalidTransition):
		writeError(w, http.StatusConflict, CodeInvalidRequest, err.Error(),
			nil, nil)
	default:
		writeError(w, http.StatusInternalServerError, CodeInternalError,
			"internal error", nil, nil)
	}
}
