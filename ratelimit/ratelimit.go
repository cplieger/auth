// Package ratelimit implements a dual sliding-window rate limiter for
// authentication attempts (per-IP and per-account). Callers (typically an
// HTTP server's auth handlers) consume it via the Checker interface.
package ratelimit

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Config groups all rate-limit tuning parameters into a single
// inspectable value. Use DefaultConfig() for production defaults.
type Config struct {
	IPLimit       int
	IPWindow      time.Duration
	AcctLimit     int
	AcctWindow    time.Duration
	PruneInterval time.Duration
	MaxEntries    int
}

// DefaultConfig returns the production rate-limit configuration:
//   - Per-IP: 10 attempts / 15 minutes
//   - Per-account: 100 attempts / 1 hour
//   - Max tracked entries: 10000
func DefaultConfig() Config {
	return Config{
		IPLimit:       10,
		IPWindow:      15 * time.Minute,
		AcctLimit:     100,
		AcctWindow:    time.Hour,
		PruneInterval: 5 * time.Minute,
		MaxEntries:    10000,
	}
}

// normalizeConfig substitutes DefaultConfig values for non-positive
// PruneInterval, IPWindow, AcctWindow, and MaxEntries, logging a warning per
// substitution. A non-positive PruneInterval otherwise panics time.NewTicker
// in the prune goroutine and crashes the consumer process; a non-positive
// MaxEntries disables all tracking (fail-open). Limits (IPLimit/AcctLimit) are
// left as supplied -- a caller may legitimately set them -- and guarded at the
// use site in slidingWindow.retryAfter.
func normalizeConfig(cfg Config) Config {
	def := DefaultConfig()
	if cfg.PruneInterval <= 0 {
		slog.Warn("auth/ratelimit: non-positive PruneInterval replaced with default", "default", def.PruneInterval)
		cfg.PruneInterval = def.PruneInterval
	}
	if cfg.IPWindow <= 0 {
		slog.Warn("auth/ratelimit: non-positive IPWindow replaced with default", "default", def.IPWindow)
		cfg.IPWindow = def.IPWindow
	}
	if cfg.AcctWindow <= 0 {
		slog.Warn("auth/ratelimit: non-positive AcctWindow replaced with default", "default", def.AcctWindow)
		cfg.AcctWindow = def.AcctWindow
	}
	if cfg.MaxEntries <= 0 {
		slog.Warn("auth/ratelimit: non-positive MaxEntries replaced with default", "default", def.MaxEntries)
		cfg.MaxEntries = def.MaxEntries
	}
	if cfg.IPLimit <= 0 {
		slog.Warn("auth/ratelimit: non-positive IPLimit blocks every request after the first recorded attempt", "ip_limit", cfg.IPLimit)
	}
	if cfg.AcctLimit <= 0 {
		slog.Warn("auth/ratelimit: non-positive AcctLimit blocks every request after the first recorded attempt", "acct_limit", cfg.AcctLimit)
	}
	return cfg
}

// ClientIP is the per-client IP dimension key of the limiter. It is a
// distinct type so an IP and a username — both strings — cannot be swapped
// silently at a call site: the two dimensions have different windows and
// different limits, so a swap would quietly change the security posture.
type ClientIP string

// Username is the per-account dimension key of the limiter. See [ClientIP]
// for why the two key types are distinct.
type Username string

// Checker is the narrow interface consumed by callers (e.g. HTTP auth handlers).
// It decouples request handling from the concrete sliding-window implementation.
type Checker interface {
	Allow(ip ClientIP, username Username) (allowed bool, retryAfter time.Duration)
	Record(ip ClientIP, username Username)
	Reset(ip ClientIP, username Username)
}

// Compile-time assertion that *RateLimiter satisfies Checker.
var _ Checker = (*RateLimiter)(nil)

// RateLimiter tracks failed authentication attempts per IP and per account
// using dual sliding windows (OWASP ASVS 2.2.1). A RateLimiter must be
// created with [New]: the zero value has nil window maps (Record panics), no
// prune goroutine, and a nil cancel func (Shutdown panics dereferencing it).
type RateLimiter struct {
	ipWindows     map[string]*slidingWindow
	acctWindows   map[string]*slidingWindow
	nowFunc       func() time.Time
	cancel        context.CancelFunc
	done          chan struct{}
	ipWindow      time.Duration
	acctWindow    time.Duration
	pruneInterval time.Duration
	ipLimit       int
	acctLimit     int
	maxEntries    int
	muIP          sync.Mutex
	muAcct        sync.Mutex
	ipCapWarned   bool
	acctCapWarned bool
}

type slidingWindow struct {
	timestamps []time.Time
}

// New creates a rate limiter with the given configuration.
// A background goroutine prunes stale entries at cfg.PruneInterval.
// The goroutine stops when ctx is cancelled; call [RateLimiter.Shutdown] to
// stop it explicitly and wait for it to exit.
func New(ctx context.Context, cfg Config) *RateLimiter {
	cfg = normalizeConfig(cfg)
	ctx, cancel := context.WithCancel(ctx)
	rl := &RateLimiter{
		ipWindows:     make(map[string]*slidingWindow),
		acctWindows:   make(map[string]*slidingWindow),
		ipLimit:       cfg.IPLimit,
		ipWindow:      cfg.IPWindow,
		acctLimit:     cfg.AcctLimit,
		acctWindow:    cfg.AcctWindow,
		maxEntries:    cfg.MaxEntries,
		pruneInterval: cfg.PruneInterval,
		cancel:        cancel,
		done:          make(chan struct{}),
		nowFunc:       time.Now,
	}
	go rl.pruneLoop(ctx)
	return rl
}

// Allow checks both IP and account windows. Both must be within limits
// for the request to proceed. Returns false with a retry-after duration
// if either limit is exceeded. An empty ip or username skips that dimension
// (a missing key carries no per-client signal and would otherwise lump
// unrelated callers into one shared bucket); callers should supply a real
// per-client IP so the IP dimension applies.
func (rl *RateLimiter) Allow(ip ClientIP, username Username) (allowed bool, retryAfter time.Duration) {
	now := rl.nowFunc()

	var ipRetry, acctRetry time.Duration

	if ip != "" {
		rl.muIP.Lock()
		if w, ok := rl.ipWindows[string(ip)]; ok {
			ipRetry = w.retryAfter(now, rl.ipWindow, rl.ipLimit)
		}
		rl.muIP.Unlock()
	}

	if username != "" {
		rl.muAcct.Lock()
		if w, ok := rl.acctWindows[string(username)]; ok {
			acctRetry = w.retryAfter(now, rl.acctWindow, rl.acctLimit)
		}
		rl.muAcct.Unlock()
	}

	if ipRetry > 0 || acctRetry > 0 {
		ra := max(ipRetry, acctRetry)
		return false, ra
	}

	return true, 0
}

// Record records a failed authentication attempt in the IP and account
// sliding windows. An empty ip or username skips that dimension, mirroring
// Allow and Reset.
func (rl *RateLimiter) Record(ip ClientIP, username Username) {
	now := rl.nowFunc()

	if ip != "" {
		rl.muIP.Lock()
		rl.recordLocked(rl.ipWindows, string(ip), now, rl.ipWindow, rl.ipLimit, "per-IP", &rl.ipCapWarned)
		rl.muIP.Unlock()
	}

	if username != "" {
		rl.muAcct.Lock()
		rl.recordLocked(rl.acctWindows, string(username), now, rl.acctWindow, rl.acctLimit, "per-account", &rl.acctCapWarned)
		rl.muAcct.Unlock()
	}
}

// recordLocked appends now to key's sliding window, creating it if absent.
// When the map is already at maxEntries and key is new, it evicts an existing
// entry (preferring one not currently at its limit) to make room instead of
// silently dropping the new key. Dropping new keys lets a distributed attacker
// pin the map full with throwaway keys so Allow fails open for an
// as-yet-untracked target, disabling the limit this window exists to enforce.
// The first eviction of each saturation episode emits an edge-triggered warning
// through warned (reset in prune once the map falls back below the cap) so
// operators can observe sustained entry-cap pressure. window and limit are the
// scope's tuning values, forwarded to the evictor so it can avoid dropping a
// still-blocking entry. The caller holds the relevant mutex.
func (rl *RateLimiter) recordLocked(windows map[string]*slidingWindow, key string, now time.Time, window time.Duration, limit int, scope string, warned *bool) {
	if w, ok := windows[key]; ok {
		w.add(now)
		return
	}
	if len(windows) >= rl.maxEntries {
		if !*warned {
			*warned = true
			slog.Warn("auth/ratelimit: entry cap reached; evicting entries to admit new keys",
				"scope", scope, "max_entries", rl.maxEntries)
		}
		evictLeastRecentlyActive(windows, now, window, limit)
	}
	w := &slidingWindow{}
	w.add(now)
	windows[key] = w
}

// evictLeastRecentlyActive deletes one entry to admit a new key. It first
// targets entries that are not currently at their limit (count < limit),
// evicting the one whose most recent timestamp is oldest. An empty window
// has a zero-value last timestamp; a fully-expired window still carries its
// newest (already-expired) timestamp until count reslices it -- older than
// any live entry's -- so both sort oldest and are dropped first.
// Only when every entry is at its limit, leaving no harmless victim, does it
// fall back to evicting the least-recently-active entry overall. Protecting
// at-limit entries keeps a still-blocking account from having its accumulated
// count silently reset, which would lift the block and weaken the per-account
// OWASP ASVS 2.2.1 cap; it also makes eviction consistent with prune, which
// deletes only fully-expired windows. The caller holds the owning map's mutex;
// count mutates each window's timestamps.
func evictLeastRecentlyActive(windows map[string]*slidingWindow, now time.Time, window time.Duration, limit int) {
	var (
		victim       string // oldest entry that is not at its limit
		victimLast   time.Time
		haveVictim   bool
		fallback     string // oldest entry overall, used when all are at-limit
		fallbackLast time.Time
		haveFallback bool
	)
	for k, w := range windows {
		var last time.Time
		if n := len(w.timestamps); n > 0 {
			last = w.timestamps[n-1]
		}
		if !haveFallback || last.Before(fallbackLast) {
			fallback, fallbackLast, haveFallback = k, last, true
		}
		// count is read after last so the reslice it performs cannot invalidate
		// the timestamps[n-1] index above.
		if w.count(now, window) >= limit {
			continue // at-limit: protected unless no other victim exists
		}
		if !haveVictim || last.Before(victimLast) {
			victim, victimLast, haveVictim = k, last, true
		}
	}
	switch {
	case haveVictim:
		delete(windows, victim)
	case haveFallback:
		delete(windows, fallback)
	}
}

// Shutdown stops the background prune goroutine and blocks until it has
// exited or ctx expires, returning nil in the first case and ctx.Err() in the
// second (in which case the goroutine is still winding down). Completion is
// consulted before the context — the stdlib [net/http.Server.Shutdown] shape —
// so once the goroutine has exited, Shutdown returns nil deterministically
// even when ctx is already expired. It is safe to call more than once.
func (rl *RateLimiter) Shutdown(ctx context.Context) error {
	rl.cancel()
	select {
	case <-rl.done:
		return nil
	default:
	}
	select {
	case <-rl.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Reset clears the sliding window entries for the given IP and username.
// Call after a successful authentication to prevent permanent soft-lockout
// (OWASP ASVS 2.2.1).
func (rl *RateLimiter) Reset(ip ClientIP, username Username) {
	if ip != "" {
		rl.muIP.Lock()
		delete(rl.ipWindows, string(ip))
		rl.muIP.Unlock()
	}

	if username != "" {
		rl.muAcct.Lock()
		delete(rl.acctWindows, string(username))
		rl.muAcct.Unlock()
	}
}

// pruneLoop removes stale entries at the configured prune interval. On exit
// it closes done, which is what [RateLimiter.Shutdown] waits on.
func (rl *RateLimiter) pruneLoop(ctx context.Context) {
	defer close(rl.done)
	ticker := time.NewTicker(rl.pruneInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rl.prune()
		}
	}
}

// prune removes windows whose entries have all expired and, once a map falls
// back below maxEntries, clears that scope's cap-warning flag so a later
// saturation episode re-warns (the reset half of recordLocked's edge-triggered
// warning). It locks each map's mutex in turn.
func (rl *RateLimiter) prune() {
	now := rl.nowFunc()

	rl.muIP.Lock()
	for k, w := range rl.ipWindows {
		if w.count(now, rl.ipWindow) == 0 {
			delete(rl.ipWindows, k)
		}
	}
	if len(rl.ipWindows) < rl.maxEntries {
		rl.ipCapWarned = false
	}
	rl.muIP.Unlock()

	rl.muAcct.Lock()
	for k, w := range rl.acctWindows {
		if w.count(now, rl.acctWindow) == 0 {
			delete(rl.acctWindows, k)
		}
	}
	if len(rl.acctWindows) < rl.maxEntries {
		rl.acctCapWarned = false
	}
	rl.muAcct.Unlock()
}

// slidingWindow methods

// add appends now to the window's timestamps. Caller must hold the
// owning map's mutex (muIP or muAcct); this mutates w.timestamps.
func (w *slidingWindow) add(now time.Time) {
	w.timestamps = append(w.timestamps, now)
}

// count returns the number of timestamps within the window, pruning expired
// ones. Caller must hold the owning map's mutex (muIP or muAcct): despite the
// query-like name this mutates w.timestamps (it reslices off expired entries),
// which is why the read-looking Allow->retryAfter path also takes the lock.
func (w *slidingWindow) count(now time.Time, window time.Duration) int {
	cutoff := now.Add(-window)
	i := 0
	for i < len(w.timestamps) && w.timestamps[i].Before(cutoff) {
		i++
	}
	if i > 0 {
		w.timestamps = w.timestamps[i:]
	}
	return len(w.timestamps)
}

// retryAfter returns the duration until the oldest relevant entry expires,
// if the window is at or over the limit. Returns 0 if under the limit.
// Caller must hold the owning map's mutex (muIP or muAcct); mutates
// w.timestamps transitively through count.
func (w *slidingWindow) retryAfter(now time.Time, window time.Duration, limit int) time.Duration {
	n := w.count(now, window)
	// n == 0 short-circuits the limit <= 0 case: normalizeConfig leaves a
	// caller-supplied non-positive IPLimit/AcctLimit as-is, so an empty window
	// satisfies n >= limit and the w.timestamps[0] read below would panic.
	if n < limit || n == 0 {
		return 0
	}
	oldest := w.timestamps[0]
	expires := oldest.Add(window)
	ra := expires.Sub(now)
	if ra < 0 {
		return 0
	}
	return ra
}
