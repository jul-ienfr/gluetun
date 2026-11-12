package observability

import "encoding/json"

// Sink is the minimal logging interface used by the control plane.
type Sink interface {
	Infof(format string, args ...any)
	Error(s string)
}

// Logger emits structured control plane entries with secrets scrubbed.
type Logger struct {
	sink Sink
}

// NewLogger creates a structured logger writing to sink.
func NewLogger(sink Sink) *Logger {
	return &Logger{sink: sink}
}

// Job logs an entry tied to a job identifier.
func (l *Logger) Job(jobID, event string, fields map[string]any) {
	entry := map[string]any{
		"job_id": jobID,
		"event":  event,
	}
	l.write(entry, fields)
}

// Event logs a control plane entry without a job identifier.
func (l *Logger) Event(event string, fields map[string]any) {
	entry := map[string]any{"event": event}
	l.write(entry, fields)
}

func (l *Logger) write(entry map[string]any, fields map[string]any) {
	if len(fields) > 0 {
		entry["fields"] = ScrubMap(fields)
	}
	line, err := json.Marshal(entry)
	if err != nil {
		l.sink.Error("encoding structured control log entry")
		return
	}
	l.sink.Infof("%s", line)
}
