package events

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// DefaultHeartbeat is the SSE keepalive interval.
const DefaultHeartbeat = 15 * time.Second

// StreamWriter is an SSE-capable writer.
type StreamWriter interface {
	io.Writer
	Flush()
}

// WriteEvent writes one SSE frame.
func WriteEvent(w io.Writer, event Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n",
		event.Seq, event.Type, data)
	return err
}

// WriteHeartbeat writes an SSE comment keepalive.
func WriteHeartbeat(w io.Writer) error {
	_, err := io.WriteString(w, ": keepalive\n\n")
	return err
}

// WriteGap writes a stream.gap event telling the client to resynchronize.
func WriteGap(w io.Writer, from, to uint64) error {
	return WriteEvent(w, Event{
		Seq:      to,
		Time:     time.Now().UTC(),
		Type:     "stream.gap",
		Severity: SeverityWarning,
		Data: map[string]any{
			"from_seq": from,
			"to_seq":   to,
		},
	})
}

// Stream forwards subscription events to writer until the context ends or the
// subscription closes. A heartbeat comment is written every interval.
func Stream(ctx context.Context, writer StreamWriter, subscription *Subscription,
	heartbeat time.Duration,
) error {
	if heartbeat <= 0 {
		heartbeat = DefaultHeartbeat
	}
	ticker := time.NewTicker(heartbeat)
	defer ticker.Stop()

	if subscription.Gap() {
		err := WriteGap(writer, 0, subscription.bus.LastSeq())
		if err != nil {
			return err
		}
		writer.Flush()
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-subscription.C():
			if !ok {
				return nil
			}
			err := WriteEvent(writer, event)
			if err != nil {
				return err
			}
			writer.Flush()
		case <-ticker.C:
			err := WriteHeartbeat(writer)
			if err != nil {
				return err
			}
			writer.Flush()
		}
	}
}
