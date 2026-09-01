package ratelimit

import (
	"context"
	"testing"
	"time"
)

func FuzzRateLimiterAllow(f *testing.F) {
	f.Add("192.168.1.1", "admin")
	f.Add("", "")
	f.Add("\x00\x00\x00", "user\x00null")
	f.Add("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "日本語ユーザー")
	f.Add("::1", "a]b[c")
	f.Add("", "loneuser")
	f.Add("10.0.0.1", "")

	f.Fuzz(func(t *testing.T, ip, username string) {
		cfg := Config{
			IPLimit:       3,
			IPWindow:      time.Second,
			AcctLimit:     3,
			AcctWindow:    time.Second,
			PruneInterval: time.Hour,
			MaxEntries:    100,
		}
		rl := New(t.Context(), cfg)
		defer rl.Shutdown(context.Background())

		// Freeze the clock so the 1s windows cannot elapse between the Record
		// calls and the Allow check. With the real clock (New
		// defaults nowFunc to time.Now), a slow runner or GC pause can push
		// Allow past the window, age the recorded attempts out, and flake the
		// "blocked after limit" assertion.
		now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
		rl.nowFunc = func() time.Time { return now }

		for range cfg.IPLimit {
			rl.Record(ClientIP(ip), Username(username))
		}

		// After the limit is reached, Allow must return false -- but only when at
		// least one dimension is actually tracked. An empty ip AND an empty
		// username are both skipped (a missing key carries no per-client signal),
		// so nothing is recorded and Allow always allows; that is the intended
		// empty-key behavior, not a limit breach.
		allowed, _ := rl.Allow(ClientIP(ip), Username(username))
		if (ip != "" || username != "") && allowed {
			t.Fatal("Allow returned true after limit reached")
		}

		rl.muIP.Lock()
		ipLen := len(rl.ipWindows)
		rl.muIP.Unlock()
		rl.muAcct.Lock()
		acctLen := len(rl.acctWindows)
		rl.muAcct.Unlock()

		if ipLen > cfg.MaxEntries {
			t.Fatalf("IP map cardinality %d exceeds max %d", ipLen, cfg.MaxEntries)
		}
		if acctLen > cfg.MaxEntries {
			t.Fatalf("acct map cardinality %d exceeds max %d", acctLen, cfg.MaxEntries)
		}
	})
}
