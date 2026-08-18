package ratelimit

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"pgregory.net/rapid"
)

// Property: Rate limiter sliding window
func TestProperty_RateLimiterSlidingWindow(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		ip := ClientIP(fmt.Sprintf("%d.%d.%d.%d",
			rapid.IntRange(1, 255).Draw(t, "ip1"),
			rapid.IntRange(0, 255).Draw(t, "ip2"),
			rapid.IntRange(0, 255).Draw(t, "ip3"),
			rapid.IntRange(1, 254).Draw(t, "ip4"),
		))
		username := Username(rapid.StringN(3, 32, -1).Draw(t, "username"))

		now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

		rl := New(t.Context(), DefaultConfig())
		defer rl.Shutdown(context.Background())
		rl.nowFunc = func() time.Time { return now }

		for i := range rl.ipLimit {
			allowed, _ := rl.Allow(ip, username)
			if !allowed {
				t.Fatalf("attempt %d: should be allowed (under IP limit)", i+1)
			}
			rl.Record(ip, username)
		}

		allowed, retryAfter := rl.Allow(ip, username)
		if allowed {
			t.Fatal("attempt 11: should be blocked (IP limit exceeded)")
		}
		if retryAfter <= 0 {
			t.Fatalf("retryAfter should be positive, got %v", retryAfter)
		}

		now = now.Add(rl.ipWindow + time.Second)
		allowed, _ = rl.Allow(ip, username)
		if !allowed {
			t.Fatal("after IP window elapsed: should be allowed again")
		}

		now = time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
		rl2 := New(t.Context(), DefaultConfig())
		defer rl2.Shutdown(context.Background())
		rl2.nowFunc = func() time.Time { return now }

		for i := range rl2.acctLimit {
			diffIP := ClientIP(fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256+1))
			allowed, _ := rl2.Allow(diffIP, username)
			if !allowed {
				t.Fatalf("account attempt %d: should be allowed (under account limit)", i+1)
			}
			rl2.Record(diffIP, username)
		}

		freshIP := ClientIP("172.16.0.1")
		allowed, retryAfter = rl2.Allow(freshIP, username)
		if allowed {
			t.Fatal("account attempt 101: should be blocked (account limit exceeded)")
		}
		if retryAfter <= 0 {
			t.Fatalf("account retryAfter should be positive, got %v", retryAfter)
		}

		now = now.Add(rl2.acctWindow + time.Second)
		allowed, _ = rl2.Allow(freshIP, username)
		if !allowed {
			t.Fatal("after account window elapsed: should be allowed again")
		}

		now = time.Date(2025, 9, 1, 12, 0, 0, 0, time.UTC)
		rl3 := New(t.Context(), DefaultConfig())
		defer rl3.Shutdown(context.Background())
		rl3.nowFunc = func() time.Time { return now }

		for range rl3.ipLimit {
			rl3.Record(ip, username)
		}

		allowed, _ = rl3.Allow(ip, username)
		if allowed {
			t.Fatal("after ipLimit failures without Record: should still be blocked")
		}
	})
}

func TestRateLimiter_prune_removes_stale_entries(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	rl := New(t.Context(), DefaultConfig())
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	rl.Record("10.0.0.1", "alice")
	rl.Record("10.0.0.2", "bob")

	now = now.Add(2 * time.Hour)
	rl.prune()

	rl.muIP.Lock()
	ipCount := len(rl.ipWindows)
	rl.muIP.Unlock()

	rl.muAcct.Lock()
	acctCount := len(rl.acctWindows)
	rl.muAcct.Unlock()

	if ipCount != 0 {
		t.Errorf("prune() left %d IP windows, want 0", ipCount)
	}
	if acctCount != 0 {
		t.Errorf("prune() left %d account windows, want 0", acctCount)
	}
}

func TestRateLimiter_prune_keeps_active_entries(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	rl := New(t.Context(), DefaultConfig())
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	rl.Record("10.0.0.1", "alice")

	now = now.Add(10 * time.Minute)
	rl.prune()

	rl.muIP.Lock()
	ipCount := len(rl.ipWindows)
	rl.muIP.Unlock()

	if ipCount != 1 {
		t.Errorf("prune() removed active IP window: got %d, want 1", ipCount)
	}
}

func TestRateLimiter_empty_username_skips_account_tracking(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	rl := New(t.Context(), DefaultConfig())
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	rl.Record("10.0.0.1", "")

	rl.muIP.Lock()
	ipCount := len(rl.ipWindows)
	rl.muIP.Unlock()

	rl.muAcct.Lock()
	acctCount := len(rl.acctWindows)
	rl.muAcct.Unlock()

	if ipCount != 1 {
		t.Errorf("Record(ip, \"\") IP windows = %d, want 1", ipCount)
	}
	if acctCount != 0 {
		t.Errorf("Record(ip, \"\") account windows = %d, want 0", acctCount)
	}

	allowed, _ := rl.Allow("10.0.0.1", "")
	if !allowed {
		t.Error("Allow(ip, \"\") = false after 1 attempt, want true (under IP limit)")
	}
}

func TestRateLimiter_Record_caps_ip_entries(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	rl := New(t.Context(), DefaultConfig())
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	for i := range rl.maxEntries {
		ip := ClientIP(fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256+1))
		rl.Record(ip, "")
	}

	rl.muIP.Lock()
	ipCount := len(rl.ipWindows)
	rl.muIP.Unlock()

	if ipCount != rl.maxEntries {
		t.Fatalf("Record() IP windows = %d, want %d", ipCount, rl.maxEntries)
	}

	rl.Record("192.168.99.99", "")

	rl.muIP.Lock()
	ipCountAfter := len(rl.ipWindows)
	rl.muIP.Unlock()

	if ipCountAfter != rl.maxEntries {
		t.Fatalf("Record() IP windows after cap = %d, want %d (should not grow)", ipCountAfter, rl.maxEntries)
	}

	allowed, _ := rl.Allow("10.0.0.1", "")
	if !allowed {
		t.Fatal("Allow() for existing IP after cap = false, want true (only 1 attempt)")
	}
}

func TestRateLimiter_Record_caps_account_entries(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	rl := New(t.Context(), DefaultConfig())
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	for i := range rl.maxEntries {
		username := Username(fmt.Sprintf("user%d", i))
		rl.Record("10.0.0.1", username)
	}

	rl.muAcct.Lock()
	acctCount := len(rl.acctWindows)
	rl.muAcct.Unlock()

	if acctCount != rl.maxEntries {
		t.Fatalf("Record() account windows = %d, want %d", acctCount, rl.maxEntries)
	}

	rl.Record("10.0.0.2", "overflow-user")

	rl.muAcct.Lock()
	acctCountAfter := len(rl.acctWindows)
	rl.muAcct.Unlock()

	if acctCountAfter != rl.maxEntries {
		t.Fatalf("Record() account windows after cap = %d, want %d (should not grow)", acctCountAfter, rl.maxEntries)
	}

	allowed, _ := rl.Allow("172.16.0.1", "user0")
	if !allowed {
		t.Fatal("Allow() for existing account after cap = false, want true (only 1 attempt)")
	}
}

func TestRateLimiter_retryAfter_returns_correct_duration(t *testing.T) {
	t.Parallel()

	start := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	now := start

	rl := New(t.Context(), DefaultConfig())
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	ip := ClientIP("10.0.0.1")

	for range rl.ipLimit {
		rl.Record(ip, "")
	}

	now = start.Add(5 * time.Minute)

	allowed, retryAfter := rl.Allow(ip, "")
	if allowed {
		t.Fatal("Allow() = true, want false (IP limit exceeded)")
	}

	want := start.Add(rl.ipWindow).Sub(now)
	if retryAfter != want {
		t.Errorf("Allow() retryAfter = %v, want %v", retryAfter, want)
	}
}

func TestProperty_SlidingWindowCountPrunesCorrectly(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		window := time.Duration(rapid.IntRange(1, 3600).Draw(t, "windowSec")) * time.Second
		now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC).Add(
			time.Duration(rapid.IntRange(0, 86400).Draw(t, "offsetSec")) * time.Second)

		n := rapid.IntRange(0, 50).Draw(t, "numEntries")
		offsets := make([]int, n)
		for i := range n {
			offsets[i] = rapid.IntRange(0, int(2*window/time.Second)).Draw(t, fmt.Sprintf("offset%d", i))
		}
		slices.Sort(offsets)

		w := &slidingWindow{}
		for i := range n {
			w.add(now.Add(-time.Duration(offsets[n-1-i]) * time.Second))
		}

		count := w.count(now, window)
		cutoff := now.Add(-window)

		if count != len(w.timestamps) {
			t.Fatalf("count() = %d but len(timestamps) = %d", count, len(w.timestamps))
		}

		for i, ts := range w.timestamps {
			if ts.Before(cutoff) {
				t.Fatalf("timestamps[%d] = %v is before cutoff %v", i, ts, cutoff)
			}
		}
	})
}

func TestAllow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		setup   func(rl *RateLimiter, now *time.Time)
		ip      ClientIP
		user    Username
		allowed bool
	}{
		{
			name:    "first attempt always allowed",
			setup:   func(_ *RateLimiter, _ *time.Time) {},
			ip:      "10.0.0.1",
			user:    "alice",
			allowed: true,
		},
		{
			name: "under limit all allowed",
			setup: func(rl *RateLimiter, _ *time.Time) {
				for range rl.ipLimit - 1 {
					rl.Record("10.0.0.1", "alice")
				}
			},
			ip:      "10.0.0.1",
			user:    "alice",
			allowed: true,
		},
		{
			name: "at limit blocked",
			setup: func(rl *RateLimiter, _ *time.Time) {
				for range rl.ipLimit {
					rl.Record("10.0.0.1", "alice")
				}
			},
			ip:      "10.0.0.1",
			user:    "alice",
			allowed: false,
		},
		{
			name: "different IPs independent counters",
			setup: func(rl *RateLimiter, _ *time.Time) {
				for range rl.ipLimit {
					rl.Record("10.0.0.1", "alice")
				}
			},
			ip:      "10.0.0.2",
			user:    "alice",
			allowed: true,
		},
		{
			name: "after cooldown reset and allowed",
			setup: func(rl *RateLimiter, now *time.Time) {
				for range rl.ipLimit {
					rl.Record("10.0.0.1", "alice")
				}
				*now = now.Add(rl.ipWindow + time.Second)
			},
			ip:      "10.0.0.1",
			user:    "alice",
			allowed: true,
		},
		{
			name: "account limit reached all IPs blocked",
			setup: func(rl *RateLimiter, _ *time.Time) {
				for i := range rl.acctLimit {
					ip := ClientIP(fmt.Sprintf("10.%d.%d.%d", i/65536%256, i/256%256, i%256+1))
					rl.Record(ip, "alice")
				}
			},
			ip:      "172.16.0.1",
			user:    "alice",
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
			rl := New(t.Context(), DefaultConfig())
			defer rl.Shutdown(context.Background())
			rl.nowFunc = func() time.Time { return now }

			tt.setup(rl, &now)

			allowed, retryAfter := rl.Allow(tt.ip, tt.user)
			if allowed != tt.allowed {
				t.Errorf("Allow(%q, %q) = %v, want %v", tt.ip, tt.user, allowed, tt.allowed)
			}
			if !allowed && retryAfter <= 0 {
				t.Errorf("Allow() blocked but retryAfter = %v, want > 0", retryAfter)
			}
			if allowed && retryAfter != 0 {
				t.Errorf("Allow() allowed but retryAfter = %v, want 0", retryAfter)
			}
		})
	}
}

func TestRateLimiter_prune_concurrent(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	var mu sync.Mutex

	rl := New(t.Context(), DefaultConfig())
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return now
	}

	var wg sync.WaitGroup

	for i := range 4 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := ClientIP(fmt.Sprintf("10.0.%d.1", id))
			user := Username(fmt.Sprintf("user-%d", id))
			for range 200 {
				rl.Record(ip, user)
			}
		}(i)
	}

	for i := range 2 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := ClientIP(fmt.Sprintf("10.0.%d.1", id))
			user := Username(fmt.Sprintf("user-%d", id))
			for range 200 {
				allowed, retryAfter := rl.Allow(ip, user)
				if !allowed && retryAfter <= 0 {
					t.Errorf("Allow returned blocked with non-positive retryAfter")
				}
			}
		}(i)
	}

	wg.Go(func() {
		for range 10 {
			mu.Lock()
			now = now.Add(20 * time.Minute)
			mu.Unlock()
			rl.prune()
		}
	})

	wg.Wait()
}

func TestRateLimiter_Reset_clears_counters(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	rl := New(t.Context(), DefaultConfig())
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	ip := ClientIP("10.0.0.1")
	username := Username("alice")

	// Fill up to the limit
	for range rl.ipLimit {
		rl.Record(ip, username)
	}

	// Should be blocked
	allowed, _ := rl.Allow(ip, username)
	if allowed {
		t.Fatal("Allow() = true before Reset, want false")
	}

	// Reset on successful login
	rl.Reset(ip, username)

	// Should be allowed again
	allowed, _ = rl.Allow(ip, username)
	if !allowed {
		t.Fatal("Allow() = false after Reset, want true")
	}
}

func TestRateLimiter_Reset_empty_username(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	rl := New(t.Context(), DefaultConfig())
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	ip := ClientIP("10.0.0.1")
	for range rl.ipLimit {
		rl.Record(ip, "")
	}

	rl.Reset(ip, "")

	allowed, _ := rl.Allow(ip, "")
	if !allowed {
		t.Fatal("Allow() = false after Reset with empty username, want true")
	}
}

func TestRateLimiter_Reset_clears_account_window(t *testing.T) {
	t.Parallel()

	// Reset must clear the per-account window, not only the per-IP window. The
	// IP limit is set high enough that only the account window can block, so the
	// request is re-permitted solely because Reset cleared the account window.
	// The other Reset tests use DefaultConfig, where the per-IP window does the
	// blocking, so they never isolate the account branch.
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		IPLimit:       1000,
		IPWindow:      15 * time.Minute,
		AcctLimit:     3,
		AcctWindow:    time.Hour,
		PruneInterval: time.Hour,
		MaxEntries:    100,
	}
	rl := New(t.Context(), cfg)
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	const ip, user = "10.0.0.1", "alice"
	for range cfg.AcctLimit {
		rl.Record(ip, user)
	}
	if allowed, _ := rl.Allow(ip, user); allowed {
		t.Fatal("Allow() = true before Reset, want false (account window at limit)")
	}

	rl.Reset(ip, user)

	if allowed, _ := rl.Allow(ip, user); !allowed {
		t.Fatal("Allow() = false after Reset, want true (account window cleared)")
	}
}

func BenchmarkRateLimiter_parallel(b *testing.B) {
	rl := New(b.Context(), DefaultConfig())
	defer rl.Shutdown(context.Background())

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := ClientIP(fmt.Sprintf("10.0.%d.%d", (i/256)%256, i%256+1))
			user := Username(fmt.Sprintf("user-%d", i%100))
			rl.Allow(ip, user)
			rl.Record(ip, user)
			i++
		}
	})
}

func TestSlidingWindow_count_boundary(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	const window = time.Minute
	tests := []struct {
		name    string
		offsets []time.Duration // age of each timestamp before now, ascending
		want    int
	}{
		{"empty", nil, 0},
		{"all within window", []time.Duration{0, 30 * time.Second, 59 * time.Second}, 3},
		{"boundary kept", []time.Duration{time.Minute}, 1},
		{"all expired", []time.Duration{2 * time.Minute, 3 * time.Minute}, 0},
		{"mixed", []time.Duration{10 * time.Second, 30 * time.Second, 90 * time.Second}, 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			w := &slidingWindow{}
			// Insert oldest first so timestamps are ascending, matching the
			// monotonic insertion order count() assumes in production.
			for _, off := range slices.Backward(tt.offsets) {
				w.add(now.Add(-off))
			}
			got := w.count(now, window)
			if got != tt.want {
				t.Errorf("count(window=%v) = %d, want %d", window, got, tt.want)
			}
		})
	}
}

func TestNormalizeConfig(t *testing.T) {
	t.Parallel()
	def := DefaultConfig()
	tests := []struct {
		name string
		in   Config
		want Config
	}{
		{
			name: "valid config passes through unchanged",
			in:   def,
			want: def,
		},
		{
			name: "non-positive PruneInterval replaced with default",
			in:   Config{IPLimit: 10, IPWindow: time.Minute, AcctLimit: 20, AcctWindow: time.Hour, PruneInterval: 0, MaxEntries: 5},
			want: Config{IPLimit: 10, IPWindow: time.Minute, AcctLimit: 20, AcctWindow: time.Hour, PruneInterval: def.PruneInterval, MaxEntries: 5},
		},
		{
			name: "negative IPWindow replaced with default",
			in:   Config{IPLimit: 10, IPWindow: -time.Second, AcctLimit: 20, AcctWindow: time.Hour, PruneInterval: time.Minute, MaxEntries: 5},
			want: Config{IPLimit: 10, IPWindow: def.IPWindow, AcctLimit: 20, AcctWindow: time.Hour, PruneInterval: time.Minute, MaxEntries: 5},
		},
		{
			name: "zero AcctWindow replaced with default",
			in:   Config{IPLimit: 10, IPWindow: time.Minute, AcctLimit: 20, AcctWindow: 0, PruneInterval: time.Minute, MaxEntries: 5},
			want: Config{IPLimit: 10, IPWindow: time.Minute, AcctLimit: 20, AcctWindow: def.AcctWindow, PruneInterval: time.Minute, MaxEntries: 5},
		},
		{
			name: "non-positive MaxEntries replaced with default",
			in:   Config{IPLimit: 10, IPWindow: time.Minute, AcctLimit: 20, AcctWindow: time.Hour, PruneInterval: time.Minute, MaxEntries: -1},
			want: Config{IPLimit: 10, IPWindow: time.Minute, AcctLimit: 20, AcctWindow: time.Hour, PruneInterval: time.Minute, MaxEntries: def.MaxEntries},
		},
		{
			name: "non-positive limits left as supplied (guarded at use site)",
			in:   Config{IPLimit: 0, IPWindow: time.Minute, AcctLimit: -5, AcctWindow: time.Hour, PruneInterval: time.Minute, MaxEntries: 5},
			want: Config{IPLimit: 0, IPWindow: time.Minute, AcctLimit: -5, AcctWindow: time.Hour, PruneInterval: time.Minute, MaxEntries: 5},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeConfig(tt.in)
			if got != tt.want {
				t.Errorf("normalizeConfig(%+v) = %+v, want %+v", tt.in, got, tt.want)
			}
		})
	}
}

func TestRateLimiter_nonpositive_IPLimit_fails_closed(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		IPLimit:       0,
		IPWindow:      time.Minute,
		AcctLimit:     100,
		AcctWindow:    time.Hour,
		PruneInterval: time.Hour,
		MaxEntries:    100,
	}
	rl := New(t.Context(), cfg)
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	if allowed, _ := rl.Allow("10.0.0.1", ""); !allowed {
		t.Fatal("Allow before any Record = false, want true (empty window is always allowed)")
	}

	rl.Record("10.0.0.1", "")
	allowed, retryAfter := rl.Allow("10.0.0.1", "")
	if allowed {
		t.Fatal("Allow after one Record with IPLimit<=0 = true, want false (must fail closed)")
	}
	if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want > 0 when blocked", retryAfter)
	}
}

func TestRateLimiter_eviction_drops_least_recently_active(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		IPLimit:       10,
		IPWindow:      time.Hour,
		AcctLimit:     100,
		AcctWindow:    time.Hour,
		PruneInterval: time.Hour,
		MaxEntries:    2,
	}
	rl := New(t.Context(), cfg)
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	rl.Record("stale", "")
	now = now.Add(time.Minute)
	rl.Record("active", "")
	now = now.Add(time.Minute)
	rl.Record("active", "")
	now = now.Add(time.Minute)

	rl.Record("new", "")

	rl.muIP.Lock()
	_, staleKept := rl.ipWindows["stale"]
	_, activeKept := rl.ipWindows["active"]
	_, newKept := rl.ipWindows["new"]
	n := len(rl.ipWindows)
	rl.muIP.Unlock()

	if n != cfg.MaxEntries {
		t.Fatalf("ipWindows size = %d, want %d", n, cfg.MaxEntries)
	}
	if staleKept {
		t.Error("least-recently-active \"stale\" was retained, want evicted")
	}
	if !activeKept {
		t.Error("most-recently-active \"active\" was evicted, want retained")
	}
	if !newKept {
		t.Error("new key \"new\" was not admitted after eviction")
	}
}

func TestRateLimiter_eviction_protects_at_limit_entry(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		IPLimit:       2,
		IPWindow:      time.Hour,
		AcctLimit:     100,
		AcctWindow:    time.Hour,
		PruneInterval: time.Hour,
		MaxEntries:    2,
	}
	rl := New(t.Context(), cfg)
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	// "blocked" reaches the limit at t0, giving it the oldest last-activity
	// timestamp, so pure LRU would evict it first. "fresh" is recorded once a
	// minute later and stays under the limit.
	rl.Record("blocked", "")
	rl.Record("blocked", "")
	now = now.Add(time.Minute)
	rl.Record("fresh", "")
	now = now.Add(time.Minute)

	if allowed, _ := rl.Allow("blocked", ""); allowed {
		t.Fatal("precondition: \"blocked\" should be at limit before eviction")
	}

	// Admitting "new" forces an eviction. The at-limit "blocked" entry must be
	// protected; the not-at-limit "fresh" entry is the victim instead.
	rl.Record("new", "")

	rl.muIP.Lock()
	_, blockedKept := rl.ipWindows["blocked"]
	_, freshKept := rl.ipWindows["fresh"]
	_, newKept := rl.ipWindows["new"]
	n := len(rl.ipWindows)
	rl.muIP.Unlock()

	if n != cfg.MaxEntries {
		t.Fatalf("ipWindows size = %d, want %d", n, cfg.MaxEntries)
	}
	if !blockedKept {
		t.Error("at-limit \"blocked\" was evicted, want retained (its block must survive)")
	}
	if freshKept {
		t.Error("not-at-limit \"fresh\" was retained, want evicted")
	}
	if !newKept {
		t.Error("new key \"new\" was not admitted after eviction")
	}
	if allowed, _ := rl.Allow("blocked", ""); allowed {
		t.Error("Allow(\"blocked\") = true after eviction, want false (block must persist)")
	}
}

func TestRateLimiter_eviction_all_at_limit_falls_back_to_lru(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		IPLimit:       1,
		IPWindow:      time.Hour,
		AcctLimit:     100,
		AcctWindow:    time.Hour,
		PruneInterval: time.Hour,
		MaxEntries:    2,
	}
	rl := New(t.Context(), cfg)
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	// With IPLimit=1 a single Record puts each key at its limit, so no harmless
	// (not-at-limit) victim exists. Eviction must then fall back to pure
	// least-recently-active ordering, evicting the oldest entry.
	rl.Record("old", "")
	now = now.Add(time.Minute)
	rl.Record("recent", "")
	now = now.Add(time.Minute)

	rl.Record("new", "")

	rl.muIP.Lock()
	_, oldKept := rl.ipWindows["old"]
	_, recentKept := rl.ipWindows["recent"]
	_, newKept := rl.ipWindows["new"]
	n := len(rl.ipWindows)
	rl.muIP.Unlock()

	if n != cfg.MaxEntries {
		t.Fatalf("ipWindows size = %d, want %d", n, cfg.MaxEntries)
	}
	if oldKept {
		t.Error("least-recently-active \"old\" was retained, want evicted (all-at-limit LRU fallback)")
	}
	if !recentKept {
		t.Error("most-recently-active \"recent\" was evicted, want retained")
	}
	if !newKept {
		t.Error("new key \"new\" was not admitted after eviction")
	}
}

func TestRateLimiter_pruneLoop_prunes_stale_on_tick(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		cfg := Config{
			IPLimit:       10,
			IPWindow:      time.Second,
			AcctLimit:     100,
			AcctWindow:    time.Second,
			PruneInterval: time.Minute,
			MaxEntries:    100,
		}
		rl := New(t.Context(), cfg)

		rl.Record("10.0.0.1", "alice")

		time.Sleep(2 * cfg.PruneInterval)
		synctest.Wait()

		rl.muIP.Lock()
		ipN := len(rl.ipWindows)
		rl.muIP.Unlock()
		rl.muAcct.Lock()
		acctN := len(rl.acctWindows)
		rl.muAcct.Unlock()
		if ipN != 0 || acctN != 0 {
			t.Errorf("pruneLoop tick left ip=%d acct=%d windows, want 0,0", ipN, acctN)
		}

		// Shutdown must signal the prune goroutine AND wait for its exit: a nil
		// return here is the C20 contract that "stopped" means the goroutine is
		// gone, which is what lets a test assert the component went quiet.
		if err := rl.Shutdown(t.Context()); err != nil {
			t.Errorf("Shutdown() = %v, want nil (prune goroutine must have exited)", err)
		}
		// Witness the blocking half of the contract: after Shutdown returns,
		// done must already be closed. A Shutdown that only signalled and
		// returned nil without waiting would leave done open here.
		select {
		case <-rl.done:
		default:
			t.Error("prune loop still running after Shutdown returned")
		}
		synctest.Wait()
	})
}

func TestRateLimiter_capWarning_logs_once_per_episode(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		IPLimit:       10,
		IPWindow:      time.Hour,
		AcctLimit:     100,
		AcctWindow:    time.Hour,
		PruneInterval: time.Hour,
		MaxEntries:    2,
	}
	rl := New(t.Context(), cfg)
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	// Four distinct keys with MaxEntries=2 force two evictions in one
	// saturation episode; the edge-triggered warning must fire only once.
	rl.Record("a", "")
	rl.Record("b", "")
	rl.Record("c", "")
	rl.Record("d", "")

	if got := strings.Count(buf.String(), "entry cap reached"); got != 1 {
		t.Errorf("cap-reached warnings = %d, want 1 (edge-triggered: one warn per saturation episode)", got)
	}
}

func TestRateLimiter_capWarning_rearms_after_prune_below_cap(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		IPLimit:       10,
		IPWindow:      time.Second,
		AcctLimit:     100,
		AcctWindow:    time.Second,
		PruneInterval: time.Hour,
		MaxEntries:    2,
	}
	rl := New(t.Context(), cfg)
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	// First saturation episode: the third key evicts and warns once.
	rl.Record("a", "")
	rl.Record("b", "")
	rl.Record("c", "")

	// Age every entry out and prune below the cap so the warning re-arms.
	now = now.Add(2 * time.Second)
	rl.prune()

	// Second episode: the sixth key evicts and must warn again.
	rl.Record("d", "")
	rl.Record("e", "")
	rl.Record("f", "")

	if got := strings.Count(buf.String(), "entry cap reached"); got != 2 {
		t.Errorf("cap-reached warnings = %d, want 2 (warn re-arms after prune drops below cap)", got)
	}
}

func TestRateLimiter_nonpositive_IPLimit_expired_window_reallows(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		IPLimit:       0,
		IPWindow:      time.Minute,
		AcctLimit:     100,
		AcctWindow:    time.Hour,
		PruneInterval: time.Hour,
		MaxEntries:    100,
	}
	rl := New(t.Context(), cfg)
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	// One recorded attempt blocks under a non-positive IPLimit (fail-closed).
	rl.Record("10.0.0.1", "")

	// Age the attempt out: the window is now empty but still present in the map
	// (prune has not run). The next Allow reaches retryAfter with n==0 and a
	// non-positive limit, the only state where the "|| n == 0" guard decides the
	// result: without it, n < limit is false and the w.timestamps[0] read panics.
	now = now.Add(2 * time.Minute)
	allowed, retryAfter := rl.Allow("10.0.0.1", "")
	if !allowed {
		t.Fatalf("Allow on an aged-out window with IPLimit<=0 = false, want true (attempts expired); retryAfter=%v", retryAfter)
	}
	if retryAfter != 0 {
		t.Errorf("retryAfter = %v, want 0 (window empty)", retryAfter)
	}
}

func TestRateLimiter_eviction_drops_emptied_window_first(t *testing.T) {
	t.Parallel()
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		IPLimit:       10,
		IPWindow:      time.Minute,
		AcctLimit:     100,
		AcctWindow:    time.Hour,
		PruneInterval: time.Hour,
		MaxEntries:    2,
	}
	rl := New(t.Context(), cfg)
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	rl.Record("emptied", "")
	rl.Record("kept", "")

	// Age both windows past IPWindow, then Allow("emptied") so count() reslices
	// its window to length 0 while it stays in the map. At eviction time
	// "emptied" has a zero-value last timestamp (the len(w.timestamps) > 0 guard
	// leaves last unset), so it sorts oldest and is dropped first; "kept" still
	// carries its recorded timestamp.
	now = now.Add(2 * time.Minute)
	rl.Allow("emptied", "")

	rl.Record("new", "") // map at MaxEntries: admitting "new" forces an eviction

	rl.muIP.Lock()
	_, emptiedKept := rl.ipWindows["emptied"]
	_, keptKept := rl.ipWindows["kept"]
	_, newKept := rl.ipWindows["new"]
	n := len(rl.ipWindows)
	rl.muIP.Unlock()

	if n != cfg.MaxEntries {
		t.Fatalf("ipWindows size = %d, want %d", n, cfg.MaxEntries)
	}
	if emptiedKept {
		t.Error("emptied window was retained, want evicted first (zero-value last timestamp sorts oldest)")
	}
	if !keptKept {
		t.Error("\"kept\" was evicted, want retained")
	}
	if !newKept {
		t.Error("new key \"new\" was not admitted after eviction")
	}
}

func TestProperty_EvictionAdmitsNewKeyUnderCapPressure(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		maxEntries := rapid.IntRange(1, 6).Draw(t, "maxEntries")
		ipLimit := rapid.IntRange(1, 4).Draw(t, "ipLimit")
		numKeys := rapid.IntRange(0, 30).Draw(t, "numKeys")

		now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
		cfg := Config{
			IPLimit:       ipLimit,
			IPWindow:      time.Hour,
			AcctLimit:     1000,
			AcctWindow:    time.Hour,
			PruneInterval: time.Hour,
			MaxEntries:    maxEntries,
		}
		rl := New(t.Context(), cfg)
		defer rl.Shutdown(context.Background())
		rl.nowFunc = func() time.Time { return now }

		// Each new key is filled to its limit under a deliberately small entry cap,
		// forcing evictLeastRecentlyActive on every admission past the cap. The
		// security contract: a new key is always admitted and retained, never
		// silently dropped, so the key just filled is blocked immediately after.
		// Dropping new keys when full (the pre-eviction behavior) lets an attacker
		// pin the map so an untracked target fails open.
		for i := range numKeys {
			key := ClientIP(fmt.Sprintf("key-%d", i))
			for range ipLimit {
				rl.Record(key, "")
			}
			allowed, retryAfter := rl.Allow(key, "")
			if allowed {
				t.Fatalf("key %q allowed right after filling to limit (maxEntries=%d, ipLimit=%d): a new key must be admitted and retained", key, maxEntries, ipLimit)
			}
			if retryAfter <= 0 {
				t.Fatalf("key %q blocked but retryAfter=%v, want > 0", key, retryAfter)
			}
			rl.muIP.Lock()
			n := len(rl.ipWindows)
			rl.muIP.Unlock()
			if n > maxEntries {
				t.Fatalf("ipWindows size %d exceeds MaxEntries %d", n, maxEntries)
			}
		}
	})
}

// TestRateLimiter_empty_ip_skips_ip_tracking mirrors the empty-username guard:
// an empty ip carries no per-client signal, so it must not create an IP window
// (which would lump every unknown-IP caller into one shared bucket). The account
// dimension still tracks when a username is supplied.
func TestRateLimiter_empty_ip_skips_ip_tracking(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	rl := New(t.Context(), DefaultConfig())
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	rl.Record("", "alice")

	rl.muIP.Lock()
	ipCount := len(rl.ipWindows)
	rl.muIP.Unlock()

	rl.muAcct.Lock()
	acctCount := len(rl.acctWindows)
	rl.muAcct.Unlock()

	if ipCount != 0 {
		t.Errorf("Record(\"\", user) IP windows = %d, want 0 (empty ip skips IP tracking)", ipCount)
	}
	if acctCount != 1 {
		t.Errorf("Record(\"\", user) account windows = %d, want 1", acctCount)
	}

	if allowed, _ := rl.Allow("", "alice"); !allowed {
		t.Error("Allow(\"\", user) = false after 1 attempt, want true (under account limit)")
	}

	// Reset with an empty ip must clear only the account dimension and not panic.
	rl.Reset("", "alice")
	rl.muAcct.Lock()
	acctAfter := len(rl.acctWindows)
	rl.muAcct.Unlock()
	if acctAfter != 0 {
		t.Errorf("Reset(\"\", user) account windows = %d, want 0", acctAfter)
	}
}

func TestRateLimiter_empty_ip_account_dimension_still_blocks(t *testing.T) {
	t.Parallel()

	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		IPLimit:       1000,
		IPWindow:      15 * time.Minute,
		AcctLimit:     3,
		AcctWindow:    time.Hour,
		PruneInterval: time.Hour,
		MaxEntries:    100,
	}
	rl := New(t.Context(), cfg)
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	// An empty ip skips the IP dimension on every call, so only the account
	// window for the username accumulates. Once it reaches AcctLimit, Allow
	// must block on the account dimension alone even though no IP is tracked.
	for range cfg.AcctLimit {
		rl.Record("", "alice")
	}

	allowed, retryAfter := rl.Allow("", "alice")
	if allowed {
		t.Fatal("Allow with empty ip allowed after account limit reached, want blocked (account dimension must apply)")
	}
	if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want > 0 when blocked", retryAfter)
	}

	rl.muIP.Lock()
	ipCount := len(rl.ipWindows)
	rl.muIP.Unlock()
	if ipCount != 0 {
		t.Errorf("ipWindows = %d, want 0 (empty ip must never create an IP window)", ipCount)
	}
}

func TestRateLimiter_zeroIPWindowNormalizedSoLimitStillBlocks(t *testing.T) {
	t.Parallel()
	// A zero IPWindow is non-positive, so normalizeConfig must replace it with
	// the default window. Left at zero, the cutoff equals now and every recorded
	// attempt is treated as in-window with a zero retry-after, so the IP limit
	// can never block. Recording up to the limit and then checking Allow proves
	// the window was normalized: the request is denied only because the recorded
	// attempts are still counted within a positive window.
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		IPLimit:       3,
		IPWindow:      0,
		AcctLimit:     100,
		AcctWindow:    time.Hour,
		PruneInterval: time.Hour,
		MaxEntries:    100,
	}
	rl := New(t.Context(), cfg)
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	for range cfg.IPLimit {
		rl.Record("10.0.0.1", "")
	}

	allowed, retryAfter := rl.Allow("10.0.0.1", "")
	if allowed {
		t.Fatal("Allow at the IP limit = true, want false (zero IPWindow must normalize to the default so the limit still applies)")
	}
	if retryAfter <= 0 {
		t.Errorf("retryAfter = %v, want > 0 when blocked", retryAfter)
	}
}

func TestRateLimiter_zeroMaxEntriesNormalizedSoDistinctKeysCoexist(t *testing.T) {
	t.Parallel()
	// A zero MaxEntries is non-positive, so normalizeConfig must replace it with
	// the default. Left at zero, the entry cap is reached on every new key, so
	// recording a second IP evicts the first -- clearing an already-blocked IP's
	// window and letting it through again. With the cap normalized, the two IPs
	// coexist and the first stays blocked.
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	cfg := Config{
		IPLimit:       3,
		IPWindow:      time.Hour,
		AcctLimit:     100,
		AcctWindow:    time.Hour,
		PruneInterval: time.Hour,
		MaxEntries:    0,
	}
	rl := New(t.Context(), cfg)
	defer rl.Shutdown(context.Background())
	rl.nowFunc = func() time.Time { return now }

	for range cfg.IPLimit {
		rl.Record("10.0.0.1", "")
	}
	if allowed, _ := rl.Allow("10.0.0.1", ""); allowed {
		t.Fatal("precondition: first IP should be blocked at its limit")
	}

	// Recording a different IP must not evict the already-blocked one.
	rl.Record("10.0.0.2", "")

	if allowed, _ := rl.Allow("10.0.0.1", ""); allowed {
		t.Fatal("first IP allowed after a different IP was recorded; zero MaxEntries must normalize to the default so distinct keys coexist")
	}
}
