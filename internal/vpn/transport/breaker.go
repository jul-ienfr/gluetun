package transport

import (
	"time"
)

type BreakerState string

const (
	BreakerClosed   BreakerState = "closed"
	BreakerOpen     BreakerState = "open"
	BreakerHalfOpen BreakerState = "half_open"
)

type Breaker struct {
	State    BreakerState `json:"state"`
	Failures int          `json:"failures"`
	RetryAt  time.Time    `json:"retry_at,omitempty"`
	cooldown time.Duration
}

func NewBreaker() Breaker {
	return Breaker{State: BreakerClosed}
}

func (b *Breaker) Allow(now time.Time) (allowed, halfOpen bool) {
	switch b.State {
	case BreakerOpen:
		if now.Before(b.RetryAt) {
			return false, false
		}
		b.State = BreakerHalfOpen
		return true, true
	case BreakerHalfOpen:
		return true, true
	default:
		return true, false
	}
}

func (b *Breaker) Success() {
	b.State = BreakerClosed
	b.Failures = 0
	b.RetryAt = time.Time{}
	b.cooldown = 0
}

func (b *Breaker) Failure(now time.Time, threshold int,
	baseCooldown, maxCooldown time.Duration,
) (opened bool) {
	b.Failures++
	switch b.State {
	case BreakerClosed:
		if b.Failures < threshold {
			return false
		}
		b.cooldown = baseCooldown
		b.State = BreakerOpen
		b.RetryAt = now.Add(b.cooldown)
		return true
	case BreakerHalfOpen:
		if b.cooldown <= 0 {
			b.cooldown = baseCooldown
		} else {
			b.cooldown *= 2
		}
		if b.cooldown > maxCooldown {
			b.cooldown = maxCooldown
		}
		b.State = BreakerOpen
		b.RetryAt = now.Add(b.cooldown)
		return true
	default:
		b.RetryAt = now.Add(b.cooldown)
		return false
	}
}

func (b *Breaker) Reset() {
	b.State = BreakerClosed
	b.Failures = 0
	b.RetryAt = time.Time{}
	b.cooldown = 0
}

func (b Breaker) RetryTime() (time.Time, bool) {
	if b.State != BreakerOpen {
		return time.Time{}, false
	}
	return b.RetryAt, true
}
