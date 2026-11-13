package events

import "sync"

// Sequencer generates strictly increasing, gap-free sequence numbers.
type Sequencer struct {
	mutex sync.Mutex
	next  uint64
}

// Next returns the next sequence number.
func (s *Sequencer) Next() uint64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.next++
	return s.next
}

// Current returns the last sequence number handed out.
func (s *Sequencer) Current() uint64 {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	return s.next
}

// Restore moves the sequencer forward to a persisted sequence number. It never
// moves it backwards.
func (s *Sequencer) Restore(last uint64) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	if last > s.next {
		s.next = last
	}
}
