package ratelimit

import (
	"context"
	"testing"
	"time"
)

// TestRateLimiter_Reset_clears_account_window targets the conditional-negation
// mutant on Reset's `if username != ""` guard (ratelimit.go L160). The existing
// Reset tests use DefaultConfig, where blocking comes from the per-IP window
// (which Reset always clears), so they do not exercise the account branch.
//
// Here the IP limit is set high enough that only the account window can block,
// so clearing the account window is the sole thing that re-permits the request.
func TestRateLimiter_Reset_clears_account_window(t *testing.T) {
	t.Parallel()

	// given a limiter where only the per-account window can block
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		IPLimit:       1000,
		IPWindow:      15 * time.Minute,
		AcctLimit:     3,
		AcctWindow:    time.Hour,
		PruneInterval: time.Hour,
		MaxEntries:    100,
	}
	rl := NewRateLimiter(context.Background(), cfg)
	defer rl.Stop()
	rl.nowFunc = func() time.Time { return now }

	const ip, user = "10.0.0.1", "alice"
	for range cfg.AcctLimit {
		rl.Record(ip, user)
	}
	if allowed, _ := rl.Allow(ip, user); allowed {
		t.Fatal("Allow() = true before Reset, want false (account window at limit)")
	}

	// when the account is reset (non-empty username)
	rl.Reset(ip, user)

	// then the account window is cleared and the request is allowed again
	if allowed, _ := rl.Allow(ip, user); !allowed {
		t.Fatal("Allow() = false after Reset, want true (account window cleared)")
	}
}
