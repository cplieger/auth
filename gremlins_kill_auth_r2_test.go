package auth

import (
	"fmt"
	"testing"
	"time"
)

// gremlins_kill_auth_r2_test.go — unit auth-r2.
//
// Round-2 survivors and their dispositions (see the UNIT report for detail):
//   session_verifier.go:128:17  `if now.Sub(t) >= d`           — killed below.
//   ratelimit/ratelimit.go:214:7  `if i > 0`                   — equivalent
//       (no-op reslice at i==0; documented in ratelimit's round-1 file).
//   ratelimit/ratelimit.go:230:8  `if ra < 0`                  — equivalent
//       (both branches return Duration(0) at ra==0; ra is also provably >= 0).
//   token.go:93:25  `time.Since(created) > maxAge`             — needs a clock
//       seam (forbidden): the only differing input is elapsed == maxAge exactly,
//       and time.Since reads the real wall clock with no injectable now.

// --- session_verifier.go:128:17 — `if now.Sub(t) >= d` (CONDITIONALS_BOUNDARY >= -> >) ---
//
// pruneActivityLocked deletes lastActivity entries whose age is at least the
// throttle window d. The original (`age >= d`) deletes an entry aged exactly d;
// the mutant (`age > d`) keeps it. The round-1 prune tests only use entries far
// past d (age 1h vs d=1min), where `>=` and `>` agree, so they never reach this
// boundary.
//
// We seed exactly activityPruneThreshold entries so the len-guard on line 124
// lets the prune loop run, with one entry aged exactly d (now-d, no monotonic
// component, so now.Sub(t) == d exactly). Asserting that entry is removed
// distinguishes the original (deletes) from the mutant (keeps).
func TestGkAuthR2_PruneActivityLocked_AgeExactlyThrottle_Deleted(t *testing.T) {
	t.Parallel()

	const d = time.Minute
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

	const boundaryKey = "gk_auth_r2_boundary"
	m := make(map[string]time.Time, activityPruneThreshold)
	m[boundaryKey] = now.Add(-d) // age exactly d: now.Sub(t) == d
	for i := range activityPruneThreshold - 1 {
		m[fmt.Sprintf("gk_auth_r2_old%d", i)] = now.Add(-time.Hour) // clearly stale
	}
	if len(m) != activityPruneThreshold {
		t.Fatalf("setup: len(map) = %d, want %d (need >= threshold so the prune loop runs)",
			len(m), activityPruneThreshold)
	}

	v := &SessionVerifier{lastActivity: m, cfg: authConfig{activityThrottle: d}}
	v.activityMu.Lock()
	v.pruneActivityLocked(now, d)
	v.activityMu.Unlock()

	if _, ok := v.lastActivity[boundaryKey]; ok {
		t.Errorf("pruneActivityLocked kept the entry aged exactly d; " +
			"original deletes at `now.Sub(t) >= d`, mutant keeps at `> d`")
	}
}
