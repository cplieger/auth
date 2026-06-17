package ratelimit

// gremlins_kill_auth_u1_test.go — unit auth-u1.
//
// Both gremlins mutants assigned to this package are EQUIVALENT: no test can
// observe a behavioral difference between the original and the mutant, so no
// kill tests are added here (a test that passed regardless of the mutation
// would not be a real kill).
//
//   ratelimit.go:214:7  CONDITIONALS_BOUNDARY  `if i > 0` -> `if i >= 0`
//     In slidingWindow.count, the guarded statement is
//     `w.timestamps = w.timestamps[i:]`. i is the count of leading stale
//     timestamps, always >= 0. The mutation only changes the i == 0 case,
//     where the mutant runs `w.timestamps = w.timestamps[0:]` — a no-op
//     reslice with identical pointer, len, cap, and contents. count's return
//     value (len(w.timestamps)) and the window's post-state are therefore
//     unchanged for every reachable input.
//
//   ratelimit.go:230:8  CONDITIONALS_BOUNDARY  `if ra < 0` -> `if ra <= 0`
//     In slidingWindow.retryAfter, the two operators only differ at ra == 0:
//     the original falls through to `return ra` (which is 0), while the mutant
//     takes `return 0`. Both yield time.Duration(0), so retryAfter returns the
//     same value for ra < 0, ra == 0, and ra > 0 — i.e. for every input.
