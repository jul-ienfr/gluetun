package events

import (
	"testing"
	"time"
)

func fixedTime() time.Time {
	return time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
}

func newTestBus(options Options) *Bus {
	options.Now = fixedTime
	return New(options)
}

func Test_Bus_MonotonicSequence(t *testing.T) {
	t.Parallel()

	bus := newTestBus(Options{})
	first := bus.Publish(Event{Type: "job.queued"})
	second := bus.Publish(Event{Type: "job.committed"})

	if first.Seq != 1 || second.Seq != 2 {
		t.Fatalf("sequences = %d, %d, want 1, 2", first.Seq, second.Seq)
	}
	if bus.LastSeq() != 2 {
		t.Fatalf("last sequence = %d, want 2", bus.LastSeq())
	}
	if !first.Time.Equal(fixedTime()) {
		t.Errorf("time = %s, want %s", first.Time, fixedTime())
	}
	if second.Severity != SeverityInfo {
		t.Errorf("severity = %q, want info", second.Severity)
	}
}

func Test_Bus_ReplaySince(t *testing.T) {
	t.Parallel()

	bus := newTestBus(Options{Buffer: 10, SubscriberBuffer: 10})
	for index := 0; index < 5; index++ {
		bus.Publish(Event{Type: "event"})
	}

	subscription := bus.Subscribe(2)
	defer subscription.Close()

	want := []uint64{3, 4, 5}
	for index, wantSeq := range want {
		select {
		case event := <-subscription.C():
			if event.Seq != wantSeq {
				t.Fatalf("event %d sequence = %d, want %d",
					index, event.Seq, wantSeq)
			}
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for event %d", index)
		}
	}
	if subscription.Gap() {
		t.Error("a fully retained replay must not report a gap")
	}
}

func Test_Bus_GapWhenReplayWindowMissed(t *testing.T) {
	t.Parallel()

	bus := newTestBus(Options{Buffer: 2, SubscriberBuffer: 10})
	for index := 0; index < 4; index++ {
		bus.Publish(Event{Type: "event"})
	}

	page := bus.Recent(1, "", 10)
	if !page.Gap {
		t.Error("page should report a gap when since is older than the buffer")
	}

	subscription := bus.Subscribe(1)
	defer subscription.Close()
	if !subscription.Gap() {
		t.Error("subscription should report a gap when since is older than the buffer")
	}

	fresh := bus.Subscribe(0)
	defer fresh.Close()
	if fresh.Gap() {
		t.Error("a fresh subscription must not report a gap")
	}
}

func Test_Bus_RecentFiltersAndPaginates(t *testing.T) {
	t.Parallel()

	bus := newTestBus(Options{})
	bus.Publish(Event{Type: "a"})
	bus.Publish(Event{Type: "b"})
	bus.Publish(Event{Type: "a"})
	bus.Publish(Event{Type: "a"})

	first := bus.Recent(0, "a", 1)
	if len(first.Items) != 1 || first.Items[0].Seq != 1 {
		t.Fatalf("first page = %+v", first.Items)
	}
	if first.NextSeq != 2 {
		t.Fatalf("first next_seq = %d, want 2", first.NextSeq)
	}

	second := bus.Recent(first.NextSeq, "a", 1)
	if len(second.Items) != 1 || second.Items[0].Seq != 3 {
		t.Fatalf("second page = %+v", second.Items)
	}
	if second.NextSeq != 4 {
		t.Fatalf("second next_seq = %d, want 4", second.NextSeq)
	}

	third := bus.Recent(second.NextSeq, "a", 1)
	if len(third.Items) != 1 || third.Items[0].Seq != 4 {
		t.Fatalf("third page = %+v", third.Items)
	}
	if third.NextSeq != 5 {
		t.Fatalf("third next_seq = %d, want 5", third.NextSeq)
	}

	empty := bus.Recent(third.NextSeq, "a", 1)
	if len(empty.Items) != 0 {
		t.Fatalf("empty page = %+v", empty.Items)
	}
	if empty.NextSeq != 5 {
		t.Fatalf("empty next_seq = %d, want 5", empty.NextSeq)
	}
}

func Test_Bus_RestoreSeedsReplayAndSequence(t *testing.T) {
	t.Parallel()

	bus := newTestBus(Options{Buffer: 4})
	bus.Restore([]Event{
		{Seq: 2, Type: "second"},
		{Seq: 1, Type: "first"},
		{Seq: 3, Type: "third"},
	})

	if bus.LastSeq() != 3 {
		t.Fatalf("last sequence = %d, want 3", bus.LastSeq())
	}
	page := bus.Recent(0, "", 10)
	want := []uint64{1, 2, 3}
	if len(page.Items) != len(want) {
		t.Fatalf("restored items = %+v", page.Items)
	}
	for index, wantSeq := range want {
		if page.Items[index].Seq != wantSeq {
			t.Fatalf("item %d sequence = %d, want %d",
				index, page.Items[index].Seq, wantSeq)
		}
	}

	published := bus.Publish(Event{Type: "fourth"})
	if published.Seq != 4 {
		t.Fatalf("published sequence = %d, want 4", published.Seq)
	}
}

func Test_Bus_SlowSubscriberDropsWithoutBlocking(t *testing.T) {
	t.Parallel()

	bus := newTestBus(Options{Buffer: 100, SubscriberBuffer: 1})
	subscription := bus.Subscribe(0)
	defer subscription.Close()

	bus.Publish(Event{Type: "first"})
	bus.Publish(Event{Type: "second"})

	if subscription.Dropped() != 1 {
		t.Fatalf("dropped = %d, want 1", subscription.Dropped())
	}
	if !subscription.Gap() {
		t.Error("a dropping subscriber should report a gap")
	}

	select {
	case event := <-subscription.C():
		if event.Seq != 1 {
			t.Fatalf("delivered sequence = %d, want 1", event.Seq)
		}
	default:
		t.Fatal("the first event should still be buffered")
	}
}

func Test_Bus_CloseClosesSubscriptions(t *testing.T) {
	t.Parallel()

	bus := newTestBus(Options{})
	subscription := bus.Subscribe(0)
	bus.Close()

	select {
	case _, ok := <-subscription.C():
		if ok {
			t.Fatal("subscription channel should be closed")
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for the channel to close")
	}

	bus.Publish(Event{Type: "ignored"})
	if bus.LastSeq() != 0 {
		t.Fatalf("last sequence = %d, want 0 after close", bus.LastSeq())
	}
}

func Test_Bus_CloseSubscriptionIsIdempotent(t *testing.T) {
	t.Parallel()

	bus := newTestBus(Options{})
	subscription := bus.Subscribe(0)
	subscription.Close()
	subscription.Close()

	bus.Publish(Event{Type: "after close"})
	if subscription.Dropped() != 0 {
		t.Fatalf("dropped = %d, want 0", subscription.Dropped())
	}
}
