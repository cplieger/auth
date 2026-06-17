package auth

import (
	"fmt"
	"testing"
	"time"
)

// gremlins_kill_auth_u1_test.go — unit auth-u1.
//
// These tests pin the exact boundary/branch input for surviving gremlins
// CONDITIONALS_* mutants so the original and mutated operator yield a
// different observable result. One mutant cannot be killed by tests alone:
//
//   token.go:93:25  CONDITIONALS_BOUNDARY  `time.Since(created) > maxAge` -> `>=`
//     needs-prod-change. The only input where `>` and `>=` differ is
//     elapsed == maxAge exactly. VerifyCSRFToken computes elapsed via
//     time.Since(created), which reads the real wall clock, and the function
//     exposes no injectable nowFunc seam, so that exact boundary is
//     unreachable deterministically. `>` and `>=` agree on every reachable
//     input. Killable only by adding a clock seam (e.g. a nowFunc field).

// --- hasher.go:85:22 — `if len(hcfg.pepper) > 0` (CONDITIONALS_BOUNDARY > -> >=) ---
//
// With no pepper option, len(hcfg.pepper) == 0. The original (`> 0`) is false,
// so NewHasher leaves the pepper field as the nil zero value. The mutant
// (`>= 0`) is always true, so it runs `p = make([]byte, 0)` and stores a
// non-nil empty slice. Asserting the field is nil distinguishes them; the
// value depends directly on whether the `> 0` branch is taken.
func TestGkAuthU1_HasherNoPepper_FieldIsNil(t *testing.T) {
	t.Parallel()

	h, err := NewHasher(DefaultArgon2Params())
	if err != nil {
		t.Fatalf("NewHasher(default, no pepper) error = %v, want nil", err)
	}
	if h.pepper != nil {
		t.Errorf("NewHasher(no pepper): h.pepper = %v (len %d), want nil", h.pepper, len(h.pepper))
	}
}

// --- session_verifier.go:105:7 — `if d <= 0` (CONDITIONALS_BOUNDARY <= -> <) ---
//
// At the boundary d == 0 (the default throttle) the original (`d <= 0`) takes
// the early-return path and writes nothing to lastActivity. The mutant
// (`d < 0`) is false at d == 0, so it falls through, locks, and records the
// hash in lastActivity. Both return true, so the discriminating observable is
// the map side effect: original leaves it empty, mutant adds one entry.
func TestGkAuthU1_ShouldWriteActivity_ZeroThrottle_NoMapWrite(t *testing.T) {
	t.Parallel()

	v := &SessionVerifier{
		lastActivity: make(map[string]time.Time),
		cfg:          authConfig{activityThrottle: 0},
	}

	got := v.shouldWriteActivity("gk_auth_u1_hash", time.Now())

	if !got {
		t.Errorf("shouldWriteActivity(throttle=0) = false, want true")
	}
	if n := len(v.lastActivity); n != 0 {
		t.Errorf("shouldWriteActivity(throttle=0) wrote %d lastActivity entries, want 0 (early-return path, no map write)", n)
	}
}

// --- session_verifier.go:110:59 — `... && now.Sub(last) < d` (CONDITIONALS_BOUNDARY < -> <=) ---
//
// With a recorded entry and elapsed exactly == throttle d, the original
// (`elapsed < d`) is false, so the write is NOT throttled and the function
// returns true. The mutant (`elapsed <= d`) is true at equality, throttling
// the write and returning false. d > 0 keeps the line-105 early return out of
// the picture.
func TestGkAuthU1_ShouldWriteActivity_ElapsedEqualsThrottle_Writes(t *testing.T) {
	t.Parallel()

	const d = 30 * time.Minute
	t0 := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	v := &SessionVerifier{
		lastActivity: map[string]time.Time{"gk_auth_u1_hash": t0},
		cfg:          authConfig{activityThrottle: d},
	}

	got := v.shouldWriteActivity("gk_auth_u1_hash", t0.Add(d)) // elapsed == d exactly

	if !got {
		t.Errorf("shouldWriteActivity(elapsed == throttle) = false, want true (boundary uses <, not <=)")
	}
}

// --- session_verifier.go:124:25 — `if len(v.lastActivity) < activityPruneThreshold`
// CONDITIONALS_BOUNDARY (< -> <=). At len == threshold the original (`<`) is
// false, so pruning runs; the `<=` mutant is true and takes the early return,
// skipping pruning. (The `>=` negation mutant is also true at the boundary, so
// this case kills it too.) A map holding exactly threshold all-stale entries
// is pruned to empty by the original and left full by the mutant.
func TestGkAuthU1_PruneActivityLocked_AtThreshold_Prunes(t *testing.T) {
	t.Parallel()

	const d = time.Minute
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	stale := now.Add(-time.Hour) // now.Sub(stale) == 1h >= d, so prunable

	m := make(map[string]time.Time, activityPruneThreshold)
	for i := range activityPruneThreshold {
		m[fmt.Sprintf("gk_auth_u1_k%d", i)] = stale
	}
	if len(m) != activityPruneThreshold {
		t.Fatalf("setup: len(map) = %d, want %d", len(m), activityPruneThreshold)
	}

	v := &SessionVerifier{lastActivity: m, cfg: authConfig{activityThrottle: d}}
	v.activityMu.Lock()
	v.pruneActivityLocked(now, d)
	v.activityMu.Unlock()

	if n := len(v.lastActivity); n != 0 {
		t.Errorf("pruneActivityLocked(len == threshold, all stale) left %d entries, want 0 (original prunes at the boundary)", n)
	}
}

// --- session_verifier.go:124:25 — `if len(v.lastActivity) < activityPruneThreshold`
// CONDITIONALS_NEGATION (< -> >=). Below the threshold the original (`<`) is
// true and returns early WITHOUT pruning, so a stale entry survives. The
// negation mutant (`>=`) is false below the threshold, so it falls through and
// prunes the stale entry. Asserting nothing is removed below the threshold
// distinguishes original (keeps both) from the negation mutant (drops stale).
func TestGkAuthU1_PruneActivityLocked_BelowThreshold_NoPrune(t *testing.T) {
	t.Parallel()

	const d = time.Minute
	now := time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	stale := now.Add(-time.Hour) // would be removed IF the prune loop ran

	m := map[string]time.Time{
		"gk_auth_u1_stale": stale,
		"gk_auth_u1_fresh": now,
	}
	v := &SessionVerifier{lastActivity: m, cfg: authConfig{activityThrottle: d}}
	v.activityMu.Lock()
	v.pruneActivityLocked(now, d)
	v.activityMu.Unlock()

	if n := len(v.lastActivity); n != 2 {
		t.Errorf("pruneActivityLocked(below threshold) left %d entries, want 2 (must early-return without pruning)", n)
	}
}
