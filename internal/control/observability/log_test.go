package observability

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeSink struct {
	infos  []string
	errors []string
}

func (s *fakeSink) Infof(format string, args ...any) {
	s.infos = append(s.infos, fmt.Sprintf(format, args...))
}

func (s *fakeSink) Error(message string) {
	s.errors = append(s.errors, message)
}

func decodeEntry(t *testing.T, line string) map[string]any {
	t.Helper()
	var entry map[string]any
	err := json.Unmarshal([]byte(line), &entry)
	require.NoError(t, err)
	return entry
}

func Test_LoggerJob(t *testing.T) {
	t.Parallel()

	sink := &fakeSink{}
	logger := NewLogger(sink)

	logger.Job("job_01", "switch.started", map[string]any{
		"hostname": "nl-1",
		"password": "hunter2",
	})

	require.Len(t, sink.infos, 1)
	assert.Empty(t, sink.errors)

	entry := decodeEntry(t, sink.infos[0])
	assert.Equal(t, "job_01", entry["job_id"])
	assert.Equal(t, "switch.started", entry["event"])

	fields, ok := entry["fields"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "nl-1", fields["hostname"])
	assert.Equal(t, "***", fields["password"])
}

func Test_LoggerEvent(t *testing.T) {
	t.Parallel()

	sink := &fakeSink{}
	logger := NewLogger(sink)

	logger.Event("transport.cycle_exhausted", nil)

	require.Len(t, sink.infos, 1)
	entry := decodeEntry(t, sink.infos[0])
	assert.Equal(t, "transport.cycle_exhausted", entry["event"])
	assert.NotContains(t, entry, "job_id")
	assert.NotContains(t, entry, "fields")
}

func Test_LoggerScrubsNestedFields(t *testing.T) {
	t.Parallel()

	sink := &fakeSink{}
	logger := NewLogger(sink)

	url := "https://" + "user" + ":" + "pass" + "@example.com/ip"
	logger.Job("job_02", "egress.probe", map[string]any{
		"source": map[string]any{
			"url":     url,
			"api_key": "deadbeef",
		},
	})

	require.Len(t, sink.infos, 1)
	entry := decodeEntry(t, sink.infos[0])
	fields, ok := entry["fields"].(map[string]any)
	require.True(t, ok)
	source, ok := fields["source"].(map[string]any)
	require.True(t, ok)

	assert.Equal(t, "https://***@example.com/ip", source["url"])
	assert.Equal(t, "***", source["api_key"])
}

func Test_LoggerEncodingError(t *testing.T) {
	t.Parallel()

	sink := &fakeSink{}
	logger := NewLogger(sink)

	logger.Job("job_03", "bad.fields", map[string]any{
		"callback": func() {},
	})

	assert.Empty(t, sink.infos)
	require.Len(t, sink.errors, 1)
	assert.Equal(t, "encoding structured control log entry", sink.errors[0])
}

func Test_LoggerOutputStaysSingleLine(t *testing.T) {
	t.Parallel()

	sink := &fakeSink{}
	logger := NewLogger(sink)

	logger.Event("dns.fallback", map[string]any{
		"detail": "line one\nline two",
	})

	require.Len(t, sink.infos, 1)
	entry := decodeEntry(t, sink.infos[0])
	fields, ok := entry["fields"].(map[string]any)
	require.True(t, ok)
	assert.Contains(t, fields["detail"], "\n")
	assert.False(t, strings.Contains(sink.infos[0], "\n"))
}
