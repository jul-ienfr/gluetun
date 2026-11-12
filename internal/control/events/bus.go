package events

import (
	"sync"
	"sync/atomic"
	"time"
)

// Event severities.
const (
	SeverityInfo    = "info"
	SeverityWarning = "warning"
	SeverityError   = "error"
)

// Default buffer sizes. The replay buffer lets a slow or reconnecting client
// catch up; the subscriber buffer bounds the memory used by live streaming.
const (
	DefaultBuffer           = 1024
	DefaultSubscriberBuffer = 64
)

// Event is one normalized control plane event.
type Event struct {
	Seq      uint64         `json:"seq"`
	Time     time.Time      `json:"ts"`
	Type     string         `json:"type"`
	Severity string         `json:"severity"`
	JobID    string         `json:"job_id,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

// Options configure a Bus.
type Options struct {
	// Buffer is the number of recent events kept for replay.
	Buffer int
	// SubscriberBuffer is the per-subscriber live buffer size.
	SubscriberBuffer int
	// Now overrides the clock. It is optional.
	Now func() time.Time
}

// Bus assigns monotonic sequence numbers and fans events out to subscribers.
//
// Drop policy: publishing never blocks. A subscriber whose buffer is full
// drops the newest event, increments its dropped counter and marks itself as
// having a gap. Such a subscriber is expected to reconnect with Last-Event-ID
// to replay the retained window.
type Bus struct {
	mutex       sync.Mutex
	seq         Sequencer
	now         func() time.Time
	buffer      []Event
	capacity    int
	subBuffer   int
	subscribers map[*Subscription]struct{}
	closed      bool
}

// New creates an event bus.
func New(options Options) *Bus {
	capacity := options.Buffer
	if capacity <= 0 {
		capacity = DefaultBuffer
	}
	subBuffer := options.SubscriberBuffer
	if subBuffer <= 0 {
		subBuffer = DefaultSubscriberBuffer
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	return &Bus{
		now:         now,
		capacity:    capacity,
		subBuffer:   subBuffer,
		subscribers: make(map[*Subscription]struct{}),
	}
}

// Publish assigns the next sequence number and delivers the event.
func (b *Bus) Publish(event Event) Event {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.closed {
		return Event{}
	}

	event.Seq = b.seq.Next()
	if event.Time.IsZero() {
		event.Time = b.now().UTC()
	}
	if event.Severity == "" {
		event.Severity = SeverityInfo
	}

	b.appendLocked(event)
	for subscription := range b.subscribers {
		subscription.offer(event)
	}
	return event
}

func (b *Bus) appendLocked(event Event) {
	if len(b.buffer) < b.capacity {
		b.buffer = append(b.buffer, event)
		return
	}
	copy(b.buffer, b.buffer[1:])
	b.buffer[len(b.buffer)-1] = event
}

// Subscribe registers a subscriber and replays every retained event with a
// sequence strictly greater than since.
func (b *Bus) Subscribe(since uint64) *Subscription {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	subscription := &Subscription{
		bus:    b,
		events: make(chan Event, b.subBuffer),
	}
	if b.closed {
		close(subscription.events)
		return subscription
	}

	if len(b.buffer) > 0 && since != 0 && since+1 < b.buffer[0].Seq {
		subscription.gap.Store(true)
	}
	for _, event := range b.buffer {
		if event.Seq <= since {
			continue
		}
		subscription.offer(event)
	}

	b.subscribers[subscription] = struct{}{}
	return subscription
}

// LastSeq returns the last sequence number published.
func (b *Bus) LastSeq() uint64 {
	return b.seq.Current()
}

// Page is one page of retained events.
type Page struct {
	Items   []Event `json:"items"`
	NextSeq uint64  `json:"next_seq"`
	Gap     bool    `json:"gap,omitempty"`
}

// Recent returns retained events after since, optionally filtered by type.
func (b *Bus) Recent(since uint64, eventType string, limit int) Page {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if limit <= 0 {
		limit = 100
	}

	page := Page{Items: make([]Event, 0, limit)}
	if len(b.buffer) > 0 && since != 0 && since < b.buffer[0].Seq {
		page.Gap = true
	}

	for _, event := range b.buffer {
		if event.Seq < since {
			continue
		}
		if eventType != "" && event.Type != eventType {
			continue
		}
		if len(page.Items) == limit {
			page.NextSeq = page.Items[len(page.Items)-1].Seq + 1
			return page
		}
		page.Items = append(page.Items, event)
	}

	page.NextSeq = b.seq.Current() + 1
	return page
}

// Close closes every subscription. Publishing after Close is a no-op.
func (b *Bus) Close() {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	if b.closed {
		return
	}
	b.closed = true
	for subscription := range b.subscribers {
		delete(b.subscribers, subscription)
		close(subscription.events)
	}
}

func (b *Bus) remove(subscription *Subscription) {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	_, ok := b.subscribers[subscription]
	if !ok {
		return
	}
	delete(b.subscribers, subscription)
	close(subscription.events)
}

// Subscription is one live event stream.
type Subscription struct {
	bus      *Bus
	events   chan Event
	closeOne sync.Once
	dropped  atomic.Uint64
	gap      atomic.Bool
}

// C returns the channel of live events.
func (s *Subscription) C() <-chan Event {
	return s.events
}

// Dropped returns the number of events dropped for this subscriber.
func (s *Subscription) Dropped() uint64 {
	return s.dropped.Load()
}

// Gap reports whether the subscriber missed events and should resynchronize.
func (s *Subscription) Gap() bool {
	return s.gap.Load()
}

// Close unregisters the subscription and closes its channel.
func (s *Subscription) Close() {
	s.closeOne.Do(func() {
		s.bus.remove(s)
	})
}

func (s *Subscription) offer(event Event) {
	select {
	case s.events <- event:
	default:
		s.dropped.Add(1)
		s.gap.Store(true)
	}
}
