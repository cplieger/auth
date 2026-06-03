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

	f.Fuzz(func(t *testing.T, ip, username string) {
		cfg := Config{
			IPLimit:       3,
			IPWindow:      time.Second,
			AcctLimit:     3,
			AcctWindow:    time.Second,
			PruneInterval: time.Hour, // don't prune during test
			MaxEntries:    100,
		}
		rl := NewRateLimiter(context.Background(), cfg)
		defer rl.Stop()

		// Record up to limit
		for i := 0; i < cfg.IPLimit; i++ {
			rl.Record(ip, username)
		}

		// After limit reached, Allow must return false
		allowed, _ := rl.Allow(ip, username)
		if allowed {
			t.Fatal("Allow returned true after limit reached")
		}

		// Map cardinality bounded by MaxEntries
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
