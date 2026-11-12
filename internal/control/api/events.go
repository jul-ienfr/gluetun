package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/qdm12/gluetun/internal/control/events"
)

const (
	defaultEventsLimit = 100
	maxEventsLimit     = 500
)

func (h *Handler) getEvents(w http.ResponseWriter, r *http.Request) {
	if h.eventBus == nil {
		writeEventsNotReady(w)
		return
	}

	query := r.URL.Query()
	since, err := parseSequence(query.Get("since"))
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}
	limit, err := parseEventsLimit(query.Get("limit"))
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}

	page := h.eventBus.Recent(since, strings.TrimSpace(query.Get("type")),
		limit)
	writeJSON(w, page)
}

func (h *Handler) getEventsStream(w http.ResponseWriter, r *http.Request) {
	if h.eventBus == nil {
		writeEventsNotReady(w)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError, CodeInternalError,
			"streaming is not supported by this server", nil, nil)
		return
	}

	since, err := parseStreamSequence(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, CodeInvalidRequest, err.Error(),
			nil, nil)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	subscription := h.eventBus.Subscribe(since)
	defer subscription.Close()

	writer := &streamWriter{writer: w, flusher: flusher}
	_ = events.Stream(r.Context(), writer, subscription,
		events.DefaultHeartbeat)
}

func parseSequence(value string) (uint64, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}
	sequence, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errors.New("since must be a non-negative integer")
	}
	return sequence, nil
}

func parseStreamSequence(r *http.Request) (uint64, error) {
	lastEventID := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if lastEventID != "" {
		return parseSequence(lastEventID)
	}
	return parseSequence(r.URL.Query().Get("since"))
}

func parseEventsLimit(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultEventsLimit, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil || limit <= 0 {
		return 0, errors.New("limit must be a positive integer")
	}
	if limit > maxEventsLimit {
		return 0, errors.New("limit must not exceed 500")
	}
	return limit, nil
}

func writeEventsNotReady(w http.ResponseWriter) {
	writeError(w, http.StatusServiceUnavailable, CodeNotReady,
		"control plane event service is not available", nil, nil)
}

type streamWriter struct {
	writer  http.ResponseWriter
	flusher http.Flusher
}

func (s *streamWriter) Write(data []byte) (int, error) {
	return s.writer.Write(data)
}

func (s *streamWriter) Flush() {
	s.flusher.Flush()
}
