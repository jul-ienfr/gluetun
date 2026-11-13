package transport

import "fmt"

type Service struct {
	ladder *Ladder
}

func NewService(ladder *Ladder) *Service {
	return &Service{ladder: ladder}
}

func (s *Service) TransportState() (state State, available bool) {
	if s == nil || s.ladder == nil {
		return State{}, false
	}
	return s.ladder.Snapshot(), true
}

func (s *Service) TransportPolicy() Policy {
	if s == nil || s.ladder == nil {
		return Policy{}
	}
	return s.ladder.Policy()
}

func (s *Service) ResetTransport(target *Transport) error {
	if s == nil || s.ladder == nil {
		return fmt.Errorf("transport service is not available")
	}
	return s.ladder.Reset(target)
}

// SetEventSink forwards transport events to the control plane bus.
func (s *Service) SetEventSink(sink EventSink) {
	if s == nil || s.ladder == nil {
		return
	}
	s.ladder.SetEventSink(sink)
}
