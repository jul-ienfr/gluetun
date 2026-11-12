// Package consensus turns independent egress observations into a verified IP.
package consensus

import (
	"net/netip"
	"slices"
	"time"

	"github.com/qdm12/gluetun/internal/egress"
)

type candidate struct {
	ip      netip.Addr
	indexes []int
}

// Evaluate applies hard rejections and k-of-n consensus by exact IP value.
func Evaluate(observations []egress.Observation, options Options,
	now time.Time,
) egress.Verification {
	verification := egress.Verification{
		Family:       options.Family,
		SourceCount:  len(observations),
		Observations: slices.Clone(observations),
		VerifiedAt:   now.UTC(),
		Dissenters:   []string{},
	}
	for index := range verification.Observations {
		verification.Observations[index].Accepted = false
		verification.Observations[index].RejectionReason = nil
	}

	if options.Quorum < 1 {
		options.Quorum = 1
	}
	minSources := options.MinSources
	if options.AllowSingle && options.Quorum == 1 && minSources > 1 {
		minSources = 1
	}
	if minSources < 1 {
		minSources = 1
	}

	if len(observations) < minSources || len(observations) < options.Quorum {
		verification.Reason = reasonPointer(egress.ReasonInsufficientSources)
		return verification
	}

	groups := make(map[netip.Addr][]int, len(observations))
	for index := range verification.Observations {
		observation := &verification.Observations[index]
		if observation.Error != nil {
			observation.RejectionReason = reasonPointer(observation.Error.Reason)
			continue
		}
		reason := RejectionReason(observation.IP, options)
		if reason != "" {
			observation.RejectionReason = reasonPointer(reason)
			continue
		}
		observation.Accepted = true
		observation.RejectionReason = nil
		groups[observation.IP] = append(groups[observation.IP], index)
	}

	winner := winningCandidate(groups, options.Quorum, verification.Observations)
	if winner == nil || onlyPublicIP(verification.Observations, winner.indexes) {
		verification.Reason = reasonPointer(egress.ReasonNoQuorum)
		return verification
	}

	verification.IP = winner.ip
	verification.Quorum = len(winner.indexes)
	verification.Verified = true
	verification.SingleSource = len(observations) == 1 && options.AllowSingle

	for _, observation := range verification.Observations {
		if !observation.Accepted || observation.IP != winner.ip {
			if !slices.Contains(verification.Dissenters, observation.Source) {
				verification.Dissenters = append(verification.Dissenters,
					observation.Source)
			}
		}
	}

	switch {
	case verification.SingleSource:
		verification.Confidence = egress.ConfidenceLow
	case len(verification.Dissenters) == 0:
		verification.Confidence = egress.ConfidenceHigh
	case len(verification.Dissenters) == 1:
		verification.Confidence = egress.ConfidenceMedium
	default:
		verification.Confidence = egress.ConfidenceLow
	}

	return verification
}

func winningCandidate(groups map[netip.Addr][]int, quorum int,
	observations []egress.Observation,
) *candidate {
	var winner *candidate
	for ip, indexes := range groups {
		if len(indexes) < quorum {
			continue
		}
		current := &candidate{ip: ip, indexes: indexes}
		if winner == nil || better(current, winner, observations) {
			winner = current
		}
	}
	return winner
}

func better(left, right *candidate, observations []egress.Observation) bool {
	if len(left.indexes) != len(right.indexes) {
		return len(left.indexes) > len(right.indexes)
	}
	if hasDNS(left.indexes, observations) != hasDNS(right.indexes, observations) {
		return hasDNS(left.indexes, observations)
	}
	return left.ip.Compare(right.ip) < 0
}

func hasDNS(indexes []int, observations []egress.Observation) bool {
	for _, index := range indexes {
		if observations[index].Kind == egress.KindDNS {
			return true
		}
	}
	return false
}

func onlyPublicIP(observations []egress.Observation, indexes []int) bool {
	for _, index := range indexes {
		if observations[index].Kind != egress.KindPublicIP {
			return false
		}
	}
	return true
}

func reasonPointer(reason egress.Reason) *egress.Reason {
	return &reason
}
