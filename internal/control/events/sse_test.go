package events

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type flushBuffer struct {
	bytes.Buffer
	flushes int
}

func (f *flushBuffer) Flush() {
	f.flushes++
}

func Test_WriteEvent(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	event := Event{
		Seq:      1042,
		Time:     fixedTime(),
		Type:     "job.committed",
		Severity: SeverityInfo,
	}
	err := WriteEvent(&buffer, event)
	if err != nil {
		t.Fatalf("write event: %v", err)
	}

	text := buffer.String()
	for _, want := range []string{
		"id: 1042\n",
		"event: job.committed\n",
		"data: {",
		"\n\n",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output %q is missing %q", text, want)
		}
	}
}

func Test_WriteGap(t *testing.T) {
	t.Parallel()

	var buffer bytes.Buffer
	err := WriteGap(&buffer, 10, 20)
	if err != nil {
		t.Fatalf("write gap: %v", err)
	}

	text := buffer.String()
	for _, want := range []string{
		"event: stream.gap\n",
		`"from_seq":10`,
		`"to_seq":20`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("output %q is missing %q", text, want)
		}
	}
}

func Test_StreamDeliversEventsAndHeartbeats(t *testing.T) {
	t.Parallel()

	bus := newTestBus(Options{SubscriberBuffer: 8})
	subscription := bus.Subscribe(0)
	defer subscription.Close()

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	writer := &flushBuffer{}
	done := make(chan error, 1)
	go func() {
		done <- Stream(ctx, writer, subscription, 10*time.Millisecond)
	}()

	bus.Publish(Event{Type: "job.committed"})

	err := <-done
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stream error = %v, want deadline exceeded", err)
	}

	output := writer.String()
	if !strings.Contains(output, "event: job.committed") {
		t.Errorf("output %q is missing the published event", output)
	}
	if !strings.Contains(output, ": keepalive") {
		t.Errorf("output %q is missing heartbeats", output)
	}
	if writer.flushes == 0 {
		t.Error("stream should flush after each write")
	}
}

func Test_StreamStopsWhenSubscriptionCloses(t *testing.T) {
	t.Parallel()

	bus := newTestBus(Options{})
	subscription := bus.Subscribe(0)
	writer := &flushBuffer{}
	done := make(chan error, 1)
	go func() {
		done <- Stream(t.Context(), writer, subscription, time.Hour)
	}()

	subscription.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stream error = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("stream did not stop after the subscription closed")
	}
}
