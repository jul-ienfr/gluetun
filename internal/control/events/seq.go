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
