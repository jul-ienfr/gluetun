package transport

import (
	"testing"
	"time"
)

func TestBreakerOpensAfterThreshold(t *testing.T) {
	t.Parallel()

	breaker := NewBreaker()
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	const threshold = 3
	cooldown := 120 * time.Second
	maxCooldown := 900 * time.Second

	for i := 1; i < threshold; i++ {
		opened := breaker.Failure(now, threshold, cooldown, maxCooldown)
		if opened {
			t.Fatalf("breaker opened prematurely at failure %d", i)
		}
		if breaker.State != BreakerClosed {
			t.Fatalf("state at failure %d: %s", i, breaker.State)
		}
	}

	opened := breaker.Failure(now, threshold, cooldown, maxCooldown)
	if !opened {
		t.Fatal("breaker did not open at threshold")
	}
	if breaker.State != BreakerOpen {
		t.Fatalf("state: expected %s, got %s", BreakerOpen, breaker.State)
	}
	if !breaker.RetryAt.Equal(now.Add(cooldown)) {
		t.Fatalf("retry at: expected %s, got %s", now.Add(cooldown), breaker.RetryAt)
	}

	allowed, halfOpen := breaker.Allow(now.Add(cooldown - time.Second))
	if allowed || halfOpen {
		t.Fatal("breaker allowed before retry time")
	}

	allowed, halfOpen = breaker.Allow(now.Add(cooldown))
	if !allowed || !halfOpen {
		t.Fatal("breaker did not allow half-open probe")
	}
	if breaker.State != BreakerHalfOpen {
		t.Fatalf("state: expected %s, got %s", BreakerHalfOpen, breaker.State)
	}
}

func TestBreakerHalfOpenFailureDoublesCooldown(t *testing.T) {
	t.Parallel()

	breaker := NewBreaker()
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	cooldown := 120 * time.Second
	maxCooldown := 300 * time.Second

	breaker.Failure(now, 1, cooldown, maxCooldown)
	allowed, _ := breaker.Allow(now.Add(cooldown))
	if !allowed {
		t.Fatal("half-open probe not allowed")
	}

	breaker.Failure(now.Add(cooldown), 1, cooldown, maxCooldown)
	if breaker.State != BreakerOpen {
		t.Fatalf("state: expected %s, got %s", BreakerOpen, breaker.State)
	}
	expected := 240 * time.Second
	if !breaker.RetryAt.Equal(now.Add(cooldown).Add(expected)) {
		t.Fatalf("retry at: expected %s, got %s",
			now.Add(cooldown).Add(expected), breaker.RetryAt)
	}

	secondRetry := breaker.RetryAt
	breaker.Allow(secondRetry)
	breaker.Failure(secondRetry, 1, cooldown, maxCooldown)
	if !breaker.RetryAt.Equal(secondRetry.Add(maxCooldown)) {
		t.Fatalf("capped retry at: expected %s, got %s",
			secondRetry.Add(maxCooldown), breaker.RetryAt)
	}
}

func TestBreakerSuccessAndReset(t *testing.T) {
	t.Parallel()

	breaker := NewBreaker()
	now := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	breaker.Failure(now, 1, time.Minute, time.Hour)
	if breaker.State != BreakerOpen {
		t.Fatalf("state: expected %s, got %s", BreakerOpen, breaker.State)
	}

	breaker.Success()
	if breaker.State != BreakerClosed || breaker.Failures != 0 ||
		!breaker.RetryAt.IsZero() {
		t.Fatalf("breaker not reset after success: %+v", breaker)
	}

	breaker.Failure(now, 1, time.Minute, time.Hour)
	breaker.Reset()
	if breaker.State != BreakerClosed || breaker.Failures != 0 ||
		!breaker.RetryAt.IsZero() {
		t.Fatalf("breaker not reset: %+v", breaker)
	}
}
