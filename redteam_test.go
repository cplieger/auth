package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ===== (1) COOKIE POSTURE ATTACKS =====

// Attack: HTTP downgrade should not strip Secure flag from PostureSecure cookies.
func TestRedteam_PostureSecure_HTTPDowngradeKeepsSecure(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureSecure, Name: "s"}
	r := httptest.NewRequest(http.MethodGet, "http://localhost/", nil) // plain HTTP
	w := httptest.NewRecorder()
	cfg.SetCookie(w, r, "token123", 3600)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected 1 cookie, got %d", len(cookies))
	}
	if !cookies[0].Secure {
		t.Fatal("DEFECT: PostureSecure cookie lost Secure flag on HTTP request")
	}
	if cookies[0].Name != "__Host-s" {
		t.Fatalf("DEFECT: expected __Host-s, got %q", cookies[0].Name)
	}
}

// Attack: Verify no dual-cookie problem — only ONE cookie name regardless of scheme.
func TestRedteam_NoDualCookieProblem(t *testing.T) {
	t.Parallel()
	for _, posture := range []CookiePosture{PostureSecure, PostureInsecureLAN, PostureForceSecure} {
		cfg := CookieConfig{Posture: posture, Name: "sess"}
		names := make(map[string]struct{})
		for i := range 50 {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			switch i % 3 {
			case 0:
				r.Header.Set("X-Forwarded-Proto", "https")
			case 1:
				r.Header.Set("X-Forwarded-Proto", "http")
			}
			names[cfg.CookieName(r)] = struct{}{}
		}
		if len(names) != 1 {
			t.Fatalf("DEFECT: posture %d produced %d distinct cookie names: %v", posture, len(names), names)
		}
	}
}

// Attack: Session fixation — attacker sets non-prefixed cookie.
func TestRedteam_SessionFixation_StableName(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{Posture: PostureSecure, Name: "sess"}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "sess", Value: "attacker-token"})
	token := cfg.ReadCookie(r)
	if token == "attacker-token" {
		t.Fatal("DEFECT: ReadCookie read attacker's non-prefixed cookie — session fixation!")
	}
	if token != "" {
		t.Fatalf("DEFECT: ReadCookie returned unexpected value %q", token)
	}
}

// Attack: Cache-Control header must be set on every SetCookie response.
func TestRedteam_CacheControlOnSetCookie(t *testing.T) {
	t.Parallel()
	for _, posture := range []CookiePosture{PostureSecure, PostureInsecureLAN, PostureForceSecure} {
		cfg := CookieConfig{Posture: posture, Name: "s"}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		cfg.SetCookie(w, r, "tok", 3600)
		cc := w.Header().Get("Cache-Control")
		if cc != "no-store" {
			t.Fatalf("DEFECT: posture %d missing Cache-Control: no-store, got %q", posture, cc)
		}
	}
}

// Attack: HttpOnly must always be set.
func TestRedteam_CookieAlwaysHttpOnly(t *testing.T) {
	t.Parallel()
	for _, posture := range []CookiePosture{PostureSecure, PostureInsecureLAN, PostureForceSecure} {
		cfg := CookieConfig{Posture: posture, Name: "s"}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		w := httptest.NewRecorder()
		cfg.SetCookie(w, r, "tok", 3600)
		c := w.Result().Cookies()[0]
		if !c.HttpOnly {
			t.Fatalf("DEFECT: posture %d cookie missing HttpOnly", posture)
		}
	}
}

// ===== (2) X-FORWARDED-PROTO SPOOFING =====

func TestRedteam_XForwardedProto_UntrustedIgnored(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{TrustForwardedHeaders: false}
	spoofValues := []string{"https", "HTTPS", "Https", "https, http"}
	for _, val := range spoofValues {
		r := httptest.NewRequest(http.MethodGet, "http://victim.com/", nil)
		r.Header.Set("X-Forwarded-Proto", val)
		if cfg.isHTTPS(r) {
			t.Fatalf("DEFECT: TrustForwardedHeaders=false but isHTTPS=true for spoofed value %q", val)
		}
	}
}

func TestRedteam_XForwardedProto_TrustedStrictMatch(t *testing.T) {
	t.Parallel()
	cfg := CookieConfig{TrustForwardedHeaders: true}
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Forwarded-Proto", "https")
	if !cfg.isHTTPS(r) {
		t.Fatal("DEFECT: TrustForwardedHeaders=true should detect 'https'")
	}
	// Should NOT work with variations
	falseValues := []string{"HTTPS", "Https", "https ", " https", "https,http", "http"}
	for _, v := range falseValues {
		r2 := httptest.NewRequest(http.MethodGet, "/", nil)
		r2.Header.Set("X-Forwarded-Proto", v)
		if cfg.isHTTPS(r2) {
			t.Fatalf("DEFECT: isHTTPS should be false for non-exact value %q", v)
		}
	}
}

// ===== (3) CSRF TOKEN ATTACKS =====

func TestRedteam_CSRFToken_ExpiryEnforced(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	rand.Read(key)
	tok, err := CSRFToken(key, "session1")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCSRFToken(key, "session1", tok, time.Hour); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	// Zero maxAge: token was just created, time.Since is ~0, which is > 0 duration
	if err := VerifyCSRFToken(key, "session1", tok, 0); err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired with maxAge=0, got %v", err)
	}
	if err := VerifyCSRFToken(key, "session1", tok, -time.Second); err != ErrTokenExpired {
		t.Fatalf("expected ErrTokenExpired with negative maxAge, got %v", err)
	}
}

func TestRedteam_CSRFToken_CrossSession(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	rand.Read(key)
	tok, err := CSRFToken(key, "victim-session-hash")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCSRFToken(key, "attacker-session-hash", tok, time.Hour); err == nil {
		t.Fatal("DEFECT: CSRF token accepted for different session!")
	}
}

func TestRedteam_CSRFToken_DifferentKey(t *testing.T) {
	t.Parallel()
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	rand.Read(key1)
	rand.Read(key2)
	tok, err := CSRFToken(key1, "sess")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCSRFToken(key2, "sess", tok, time.Hour); err == nil {
		t.Fatal("DEFECT: CSRF token verified with different key!")
	}
}

func TestRedteam_CSRFToken_BitFlipTampering(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	rand.Read(key)
	tok, err := CSRFToken(key, "sess")
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(tok)
	for i := range raw {
		tampered := make([]byte, len(raw))
		copy(tampered, raw)
		tampered[i] ^= 0x01
		encoded := base64.RawURLEncoding.EncodeToString(tampered)
		if err := VerifyCSRFToken(key, "sess", encoded, time.Hour); err == nil {
			t.Fatalf("DEFECT: CSRF token with flipped byte at pos %d still verifies!", i)
		}
	}
}

func TestRedteam_CSRFToken_EmptyKey(t *testing.T) {
	t.Parallel()
	_, err := CSRFToken(nil, "sess")
	if err == nil {
		t.Fatal("DEFECT: CSRFToken should reject nil key")
	}
	_, err = CSRFToken([]byte{}, "sess")
	if err == nil {
		t.Fatal("DEFECT: CSRFToken should reject empty key")
	}
	if err := VerifyCSRFToken(nil, "sess", "anything", time.Hour); err == nil {
		t.Fatal("DEFECT: VerifyCSRFToken should reject nil key")
	}
}

func TestRedteam_CSRFToken_10KUnique(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	rand.Read(key)
	seen := make(map[string]struct{}, 10000)
	for range 10000 {
		tok, err := CSRFToken(key, "same-session")
		if err != nil {
			t.Fatal(err)
		}
		if _, dup := seen[tok]; dup {
			t.Fatal("DEFECT: CSRF token collision in 10000 samples!")
		}
		seen[tok] = struct{}{}
	}
}

func TestRedteam_CSRFToken_FutureTimestamp(t *testing.T) {
	t.Parallel()
	key := make([]byte, 32)
	rand.Read(key)
	sessHash := "test-sess"
	nonce := make([]byte, 16)
	rand.Read(nonce)
	expiry := make([]byte, 8)
	futureTime := time.Now().Add(time.Hour).Unix()
	binary.BigEndian.PutUint64(expiry, uint64(futureTime))

	mac := hmac.New(sha256.New, key)
	mac.Write(nonce)
	mac.Write([]byte(sessHash))
	mac.Write(expiry)
	sig := mac.Sum(nil)

	token := make([]byte, 0, csrfTokenLen)
	token = append(token, nonce...)
	token = append(token, expiry...)
	token = append(token, sig...)
	encoded := base64.RawURLEncoding.EncodeToString(token)

	// Future timestamp: time.Since(future) is negative, which is <= maxAge, so it should pass
	err := VerifyCSRFToken(key, sessHash, encoded, time.Hour)
	if err != nil {
		t.Logf("Future-timestamp token rejected: %v (acceptable — depends on impl)", err)
	}
	// The key test: it must not panic
}

// ===== (4) SESSION TIMEOUT ATTACKS =====

func TestRedteam_SessionTimeout_ZeroIdle(t *testing.T) {
	t.Parallel()
	now := time.Now()
	sess := &Session{CreatedAt: now, LastActivity: now}
	err := ValidateSession(sess, 0, 24*time.Hour, now.Add(time.Nanosecond))
	if err == nil {
		t.Fatal("DEFECT: zero idle timeout should expire session instantly")
	}
}

func TestRedteam_SessionTimeout_ZeroAbsolute(t *testing.T) {
	t.Parallel()
	now := time.Now()
	sess := &Session{CreatedAt: now, LastActivity: now}
	err := ValidateSession(sess, time.Hour, 0, now.Add(time.Nanosecond))
	if err == nil {
		t.Fatal("DEFECT: zero absolute timeout should expire session instantly")
	}
}

func TestRedteam_SessionTimeout_BoundaryIdle(t *testing.T) {
	t.Parallel()
	now := time.Now()
	sess := &Session{CreatedAt: now, LastActivity: now}
	idle := time.Hour
	err := ValidateSession(sess, idle, 24*time.Hour, now.Add(idle+time.Nanosecond))
	if err == nil {
		t.Fatal("DEFECT: session at idle+1ns should be expired")
	}
	err = ValidateSession(sess, idle, 24*time.Hour, now.Add(idle-time.Nanosecond))
	if err != nil {
		t.Fatalf("session before idle boundary should be valid, got: %v", err)
	}
}

func TestRedteam_SessionRotation_OldTokenDies(t *testing.T) {
	t.Parallel()
	oldPlain, _, err := GenerateSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	newPlain, newHash, oldHash, err := RotateSessionToken(oldPlain)
	if err != nil {
		t.Fatal(err)
	}
	if newPlain == oldPlain {
		t.Fatal("DEFECT: rotation produced same token")
	}
	if newHash == oldHash {
		t.Fatal("DEFECT: rotation produced same hash")
	}
	if SessionHash(newPlain) != newHash {
		t.Fatal("DEFECT: new hash doesn't match new plaintext")
	}
}

func TestRedteam_SessionVerifier_TimeoutOptions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFakeSessionStore()

	user := &User{Username: "timeuser", PasswordHash: "x", Role: RoleUser, Enabled: true}
	store.CreateUser(ctx, user)

	plain, hash, _ := GenerateSessionToken()
	past := time.Now().Add(-2 * time.Hour)
	store.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: MethodPassword,
		IPAddress: "1.2.3.4", CreatedAt: past, LastActivity: past,
	})

	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
	sv := NewSessionVerifier(store, WithCookie(cfg), WithIdleTimeout(time.Hour))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "s", Value: plain})
	u, _, _ := sv.Verify(ctx, r)
	if u != nil {
		t.Fatal("DEFECT: expired session should not authenticate")
	}

	sv2 := NewSessionVerifier(store, WithCookie(cfg), WithIdleTimeout(3*time.Hour))
	u2, _, _ := sv2.Verify(ctx, r)
	if u2 == nil {
		t.Fatal("session should be valid with 3h idle timeout")
	}
}

// Attack: Disabled user should not authenticate even with valid session.
func TestRedteam_DisabledUserSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := newFakeSessionStore()

	user := &User{Username: "disabled", PasswordHash: "x", Role: RoleUser, Enabled: false}
	store.CreateUser(ctx, user)

	plain, hash, _ := GenerateSessionToken()
	now := time.Now()
	store.CreateSession(ctx, &Session{
		TokenHash: hash, UserID: user.ID, AuthMethod: MethodPassword,
		IPAddress: "1.2.3.4", CreatedAt: now, LastActivity: now,
	})

	cfg := CookieConfig{Posture: PostureInsecureLAN, Name: "s"}
	sv := NewSessionVerifier(store, WithCookie(cfg))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "s", Value: plain})
	u, _, _ := sv.Verify(ctx, r)
	if u != nil {
		t.Fatal("DEFECT: disabled user should not authenticate via session")
	}
}

// ===== (5) DEP DAG — compile-time assertions =====

func TestRedteam_CoreTypesNoWebauthnOIDC(t *testing.T) {
	t.Parallel()
	var _ SessionReader = (*fakeSessionStore)(nil)
	var _ SessionWriter = (*fakeSessionStore)(nil)
	var _ UserReader = (*fakeSessionStore)(nil)
	var _ APIKeyReader = (*fakeSessionStore)(nil)
	var _ AuthStore = (*fakeSessionStore)(nil)
}

// ===== (6) ARGON2 BOUNDS & parsePHC PANICS =====

func TestRedteam_ParsePHC_NoPanic(t *testing.T) {
	t.Parallel()
	malicious := []string{
		"",
		"$",
		"$$$$$$",
		"$argon2id$v=19$m=0,t=0,p=0$$",
		"$argon2id$v=19$m=19456,t=2,p=1$" + strings.Repeat("A", 10000) + "$BBBB",
		"$argon2id$v=19$m=19456,t=2,p=1$AAAA$" + strings.Repeat("B", 10000),
		"$argon2id$v=19$m=4294967295,t=4294967295,p=255$AAAA$BBBB",
		"$argon2id$v=19$m=-1,t=2,p=1$AAAA$BBBB",
		"$argon2id$v=19$m=19456,t=2,p=1$!!!invalid-base64!!!$BBBB",
		"$argon2id$v=19$m=19456,t=2,p=1$AAAA$!!!invalid-base64!!!",
		"$argon2id$v=0$m=19456,t=2,p=1$AAAA$BBBB",
		"$argon2id$v=19$m=19456,t=0,p=1$AAAA$BBBB",
		"$argon2id$v=19$m=19456,t=2,p=0$AAAA$BBBB",
		"$argon2id$v=19$m=19456,t=2,p=1$$BBBB",
		"$argon2id$v=19$m=19456,t=2,p=1$AAAA$",
		"$notargon2id$v=19$m=19456,t=2,p=1$AAAA$BBBB",
	}
	for _, input := range malicious {
		_, _ = parsePHC(input)
	}
}

func TestRedteam_Argon2Params_Boundaries(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		p       Argon2Params
		wantErr bool
	}{
		{"memory below min", Argon2Params{Memory: 1023, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}, true},
		{"memory at min", Argon2Params{Memory: 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}, false},
		{"memory above max", Argon2Params{Memory: 4*1024*1024 + 1, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}, true},
		{"iterations 0", Argon2Params{Memory: 19456, Iterations: 0, Parallelism: 1, SaltLength: 16, KeyLength: 32}, true},
		{"iterations 101", Argon2Params{Memory: 19456, Iterations: 101, Parallelism: 1, SaltLength: 16, KeyLength: 32}, true},
		{"parallelism 0", Argon2Params{Memory: 19456, Iterations: 2, Parallelism: 0, SaltLength: 16, KeyLength: 32}, true},
		{"salt too short", Argon2Params{Memory: 19456, Iterations: 2, Parallelism: 1, SaltLength: 7, KeyLength: 32}, true},
		{"key too short", Argon2Params{Memory: 19456, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 15}, true},
		{"max uint32 memory", Argon2Params{Memory: math.MaxUint32, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.p.Validate()
			if (err != nil) != tc.wantErr {
				t.Fatalf("Validate() error=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestRedteam_NewHasher_RejectsInvalid(t *testing.T) {
	t.Parallel()
	_, err := NewHasher(Argon2Params{Memory: 0, Iterations: 0, Parallelism: 0, SaltLength: 0, KeyLength: 0})
	if err == nil {
		t.Fatal("DEFECT: NewHasher accepted all-zero params")
	}
}

// Attack: VerifyPassword should not panic on any valid PHC with crafted m/t/p=0.
func TestRedteam_VerifyPassword_CraftedPHC(t *testing.T) {
	t.Parallel()
	// These should return errors, not panics
	cases := []string{
		"$argon2id$v=19$m=19456,t=0,p=1$c29tZXNhbHQ$c29tZWhhc2g",
		"$argon2id$v=19$m=19456,t=2,p=0$c29tZXNhbHQ$c29tZWhhc2g",
	}
	for _, h := range cases {
		ok, err := VerifyPassword("test", h)
		if ok {
			t.Fatalf("should not verify for crafted hash %q", h)
		}
		if err == nil {
			t.Fatalf("expected error for crafted hash %q", h)
		}
	}
}
