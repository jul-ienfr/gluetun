package catalog

import (
	"testing"
	"time"
)

func Test_Cooldown_Backoff(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	cooldown := NewCooldown(CooldownOptions{
		Base: time.Minute,
		Max:  4 * time.Minute,
	})

	if !cooldown.Available("nl-1.nordvpn.com", now) {
		t.Fatal("new hostname should be available")
	}

	until := cooldown.RecordFailure("nl-1.nordvpn.com", now)
	if want := now.Add(time.Minute); !until.Equal(want) {
		t.Fatalf("first cooldown = %s, want %s", until, want)
	}
	if cooldown.Available("nl-1.nordvpn.com", now.Add(30*time.Second)) {
		t.Fatal("hostname should be cooling down")
	}
	if !cooldown.Available("nl-1.nordvpn.com", now.Add(time.Minute)) {
		t.Fatal("hostname should be available at the deadline")
	}

	until = cooldown.RecordFailure("nl-1.nordvpn.com", now)
	if want := now.Add(2 * time.Minute); !until.Equal(want) {
		t.Fatalf("second cooldown = %s, want %s", until, want)
	}

	until = cooldown.RecordFailure("nl-1.nordvpn.com", now)
	if want := now.Add(4 * time.Minute); !until.Equal(want) {
		t.Fatalf("third cooldown = %s, want %s", until, want)
	}

	until = cooldown.RecordFailure("nl-1.nordvpn.com", now)
	if want := now.Add(4 * time.Minute); !until.Equal(want) {
		t.Fatalf("capped cooldown = %s, want %s", until, want)
	}

	coolingUntil, cooling := cooldown.Until("nl-1.nordvpn.com")
	if !cooling || !coolingUntil.Equal(now.Add(4*time.Minute)) {
		t.Fatalf("until = %s, cooling = %t", coolingUntil, cooling)
	}

	cooldown.RecordSuccess("NL-1.nordvpn.com")
	if !cooldown.Available("nl-1.nordvpn.com", now) {
		t.Fatal("success should clear the cooldown")
	}
	if _, cooling := cooldown.Until("nl-1.nordvpn.com"); cooling {
		t.Fatal("until should be cleared after success")
	}
}

func Test_Cooldown_HostnamesAreIndependent(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	cooldown := NewCooldown(CooldownOptions{})

	cooldown.RecordFailure("a.example.com", now)
	if cooldown.Available("a.example.com", now) {
		t.Fatal("a.example.com should be cooling down")
	}
	if !cooldown.Available("b.example.com", now) {
		t.Fatal("b.example.com should be available")
	}
}

func Test_Cooldown_NilAndEmpty(t *testing.T) {
	t.Parallel()

	var cooldown *Cooldown
	if !cooldown.Available("a.example.com", time.Now()) {
		t.Fatal("nil cooldown should allow every hostname")
	}
	if until, cooling := cooldown.Until("a.example.com"); cooling ||
		!until.IsZero() {
		t.Fatal("nil cooldown should not report a deadline")
	}
	if until := cooldown.RecordFailure("a.example.com", time.Now()); !until.IsZero() {
		t.Fatal("nil cooldown should not store a deadline")
	}
	cooldown.RecordSuccess("a.example.com")

	cooldown = NewCooldown(CooldownOptions{})
	if cooldown.Available("", time.Now()) {
		t.Fatal("empty hostname should not be available")
	}
}
