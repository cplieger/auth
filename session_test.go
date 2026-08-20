package auth

import (
	"encoding/hex"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func TestProperty_SessionTokenUniquenessAndEntropy(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 20).Draw(t, "n")
		tokens := make(map[string]struct{}, n)
		hashes := make(map[string]struct{}, n)

		for i := range n {
			plaintext, hash := GenerateSessionToken()

			raw, err := hex.DecodeString(plaintext)
			if err != nil {
				t.Fatalf("token is not valid hex: %v", err)
			}
			if len(raw) < 32 {
				t.Fatalf("token raw length %d < 32", len(raw))
			}
			if plaintext == hash {
				t.Fatalf("hash equals plaintext")
			}
			if _, dup := tokens[plaintext]; dup {
				t.Fatalf("duplicate token at index %d", i)
			}
			tokens[plaintext] = struct{}{}
			if _, dup := hashes[hash]; dup {
				t.Fatalf("duplicate hash at index %d", i)
			}
			hashes[hash] = struct{}{}
		}
	})
}

func TestProperty_SessionExpiryEnforcement(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		idleTimeout := time.Duration(rapid.Int64Range(int64(time.Minute), int64(30*24*time.Hour)).Draw(t, "idleTimeout"))
		absTimeout := time.Duration(rapid.Int64Range(int64(time.Minute), int64(30*24*time.Hour)).Draw(t, "absTimeout"))

		now := time.Now()
		lastActivityAge := time.Duration(rapid.Int64Range(0, int64(60*24*time.Hour)).Draw(t, "lastActivityAge"))
		createdAge := time.Duration(rapid.Int64Range(0, int64(60*24*time.Hour)).Draw(t, "createdAge"))

		if createdAge < lastActivityAge {
			createdAge, lastActivityAge = lastActivityAge, createdAge
		}

		sess := &Session{
			CreatedAt:    now.Add(-createdAge),
			LastActivity: now.Add(-lastActivityAge),
		}

		hasOIDC := rapid.Bool().Draw(t, "hasOIDC")
		var oidcExpired bool
		if hasOIDC {
			oidcOffset := time.Duration(rapid.Int64Range(int64(-30*24*time.Hour), int64(30*24*time.Hour)).Draw(t, "oidcOffset"))
			expiry := now.Add(oidcOffset)
			sess.OIDCExpiry = expiry
			oidcExpired = now.After(expiry)
		}

		idleExpired := lastActivityAge > idleTimeout
		absExpired := createdAge > absTimeout

		err := ValidateSession(sess, SessionTimeouts{Idle: idleTimeout, Absolute: absTimeout}, now)

		if idleExpired || absExpired || oidcExpired {
			if err == nil {
				t.Fatalf("expected ErrSessionExpired")
			}
		} else {
			if err != nil {
				t.Fatalf("expected valid session, got: %v", err)
			}
		}
	})
}

func TestProperty_SessionCleanupCompleteness(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(rt *rapid.T) {
		db := newFakeSessionStore()
		ctx := t.Context()

		idleTimeout := time.Duration(rapid.Int64Range(int64(10*time.Minute), int64(24*time.Hour)).Draw(rt, "idleTimeout"))
		absTimeout := time.Duration(rapid.Int64Range(int64(10*time.Minute), int64(7*24*time.Hour)).Draw(rt, "absTimeout"))

		now := time.Now()

		user := &User{Username: "testuser", PasswordHash: "dummy", Role: "admin", Enabled: true}
		if err := db.CreateUser(ctx, user); err != nil {
			rt.Fatalf("CreateUser: %v", err)
		}

		nSessions := rapid.IntRange(1, 15).Draw(rt, "nSessions")
		var validHashes []string

		for i := range nSessions {
			expired := rapid.Bool().Draw(rt, "expired")

			var createdAt, lastActivity time.Time
			if expired {
				triggerIdle := rapid.Bool().Draw(rt, "triggerIdle")
				if triggerIdle {
					extra := time.Duration(rapid.Int64Range(int64(time.Second), int64(24*time.Hour)).Draw(rt, "idleExtra"))
					lastActivity = now.Add(-idleTimeout - extra)
					createdAt = lastActivity.Add(-time.Duration(rapid.Int64Range(0, int64(24*time.Hour)).Draw(rt, "createdBefore")))
				} else {
					extra := time.Duration(rapid.Int64Range(int64(time.Second), int64(24*time.Hour)).Draw(rt, "absExtra"))
					createdAt = now.Add(-absTimeout - extra)
					lastActivity = now.Add(-time.Duration(rapid.Int64Range(0, int64(idleTimeout/4)).Draw(rt, "recentActivity")))
				}
			} else {
				maxAge := max(min(idleTimeout/2, absTimeout/2), time.Second)
				age := time.Duration(rapid.Int64Range(0, int64(maxAge)).Draw(rt, "validAge"))
				lastActivity = now.Add(-age)
				createdAt = now.Add(-age)
			}

			_, hash := GenerateSessionToken()

			if err := db.CreateSession(ctx, &Session{
				TokenHash: hash, UserID: user.ID, AuthMethod: "password",
				IPAddress: "127.0.0.1", CreatedAt: createdAt, LastActivity: lastActivity,
			}); err != nil {
				rt.Fatalf("CreateSession[%d]: %v", i, err)
			}

			if !expired {
				validHashes = append(validHashes, hash)
			}
		}

		if _, err := db.CleanupExpiredSessions(ctx, now, SessionTimeouts{Idle: idleTimeout, Absolute: absTimeout}); err != nil {
			rt.Fatalf("CleanupExpiredSessions: %v", err)
		}

		for _, h := range validHashes {
			s, _, err := db.SessionByHash(ctx, h)
			if err != nil {
				rt.Fatalf("SessionByHash(%s): %v", h, err)
			}
			if s == nil {
				rt.Fatalf("valid session %s was deleted", h)
			}
		}

		deleted2, err := db.CleanupExpiredSessions(ctx, now, SessionTimeouts{Idle: idleTimeout, Absolute: absTimeout})
		if err != nil {
			rt.Fatalf("second cleanup: %v", err)
		}
		if deleted2 != 0 {
			rt.Fatalf("second cleanup deleted %d (expected 0)", deleted2)
		}
	})
}

// TestValidateSession_timeoutBoundaries pins the idle and absolute expiry
// boundaries: expiry triggers strictly past the timeout, so a session aged
// exactly at the limit is still valid, and a zero timeout expires immediately.
func TestValidateSession_timeoutBoundaries(t *testing.T) {
	t.Parallel()
	const (
		idle = time.Hour
		abs  = 24 * time.Hour
	)
	now := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)

	cases := []struct {
		name         string
		idle, abs    time.Duration
		lastActivity time.Time
		createdAt    time.Time
		wantErr      bool
	}{
		{"idle exactly at timeout", idle, abs, now.Add(-idle), now, false},
		{"idle just past timeout", idle, abs, now.Add(-idle - time.Nanosecond), now, true},
		{"idle just under timeout", idle, abs, now.Add(-idle + time.Nanosecond), now, false},
		{"absolute exactly at timeout", idle, abs, now, now.Add(-abs), false},
		{"absolute just past timeout", idle, abs, now, now.Add(-abs - time.Nanosecond), true},
		{"zero idle expires immediately", 0, abs, now.Add(-time.Nanosecond), now, true},
		{"zero absolute expires immediately", idle, 0, now, now.Add(-time.Nanosecond), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			sess := &Session{LastActivity: tc.lastActivity, CreatedAt: tc.createdAt}
			err := ValidateSession(sess, SessionTimeouts{Idle: tc.idle, Absolute: tc.abs}, now)
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidateSession(idle=%v, abs=%v, lastActivity %v ago, created %v ago) = %v, wantErr=%v",
					tc.idle, tc.abs, now.Sub(tc.lastActivity), now.Sub(tc.createdAt), err, tc.wantErr)
			}
		})
	}
}
