package auth

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// These tests target conditional-boundary mutants on security-critical
// comparisons. Each pins the exact boundary value so that an off-by-one
// mutation (< → <=, > → >=) becomes observable through the public API.

// --- cookie_config.go L186: if r < 0x20 || r == 0x7f ---

func TestCookieConfig_Validate_accepts_space_in_path(t *testing.T) {
	t.Parallel()

	// given a Path containing a space (0x20), the exact boundary of the
	// control-character check (r < 0x20)
	cfg := CookieConfig{Path: "/a b"}

	// when validated
	err := cfg.Validate()
	// then the space is accepted (0x20 is not a control character)
	if err != nil {
		t.Errorf("Validate() with space (0x20) in Path = %v, want nil", err)
	}
}

// --- hasher.go L57 (SaltLength < 8) and L60 (KeyLength < 16) ---

func TestArgon2Params_Validate_accepts_exact_lower_bounds(t *testing.T) {
	t.Parallel()

	// given params at the exact minimum salt (8) and key (16) lengths
	p := Argon2Params{
		Memory:      1024,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  8,
		KeyLength:   16,
	}

	// when validated
	err := p.Validate()
	// then the minimum lengths are accepted
	if err != nil {
		t.Errorf("Validate() at SaltLength=8, KeyLength=16 = %v, want nil", err)
	}
}

// --- middleware.go L114: if len(uri) < 2 || ... ---

func TestValidateRedirectURI_accepts_two_char_path(t *testing.T) {
	t.Parallel()

	// given a relative path of length exactly 2 (the boundary)
	const uri = "/a"

	// when validated
	got := ValidateRedirectURI(uri)

	// then it is returned unchanged (length 2 is acceptable)
	if got != "/a" {
		t.Errorf("ValidateRedirectURI(%q) = %q, want %q", uri, got, "/a")
	}
}

// --- password.go L139: if p.keyLen < 1 ---

func TestVerifyPassword_accepts_single_byte_key(t *testing.T) {
	t.Parallel()

	// given a well-formed PHC hash whose key is exactly 1 byte (base64 "AA"),
	// the exact lower bound of the key-length check
	const hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2Fs$AA"

	// when verifying any password against it
	ok, err := VerifyPassword("whatever", hash)
	// then parsing succeeds (no error); the password simply does not match
	if err != nil {
		t.Errorf("VerifyPassword(_, 1-byte-key hash) returned parse error %v, want nil", err)
	}
	if ok {
		t.Errorf("VerifyPassword(_, 1-byte-key hash) = true, want false")
	}
}

// --- password_validate.go L37: if runeLen > PasswordMaxLength ---

func TestValidatePasswordLength_accepts_exactly_max(t *testing.T) {
	t.Parallel()

	// given a password of exactly PasswordMaxLength (128) runes
	pw := strings.Repeat("a", PasswordMaxLength)

	// when validated (multi-factor minimum applies)
	err := ValidatePasswordLength(pw, false)
	// then exactly-max length is accepted
	if err != nil {
		t.Errorf("ValidatePasswordLength(len=%d, false) = %v, want nil", PasswordMaxLength, err)
	}
}

// --- password_validate.go L59: if len(username) >= 4 && ... ---

func TestValidatePasswordContext_rejects_four_char_username(t *testing.T) {
	t.Parallel()

	// given a username of length exactly 4 that appears in the password,
	// the exact boundary of the username-substring check
	err := ValidatePasswordContext("myuserlongpassword", "user", nil)

	// then the password is rejected
	if err == nil {
		t.Error("ValidatePasswordContext(password-containing-4char-username) = nil, want error")
	}
}

// --- session.go L43 (idle) and L46 (absolute) timeout boundaries ---

func TestValidateSession_idle_exactly_at_timeout_is_valid(t *testing.T) {
	t.Parallel()

	// given a session whose last activity is exactly idleTimeout ago
	idle := time.Hour
	abs := 24 * time.Hour
	now := time.Now()
	sess := &Session{LastActivity: now.Add(-idle), CreatedAt: now}

	// when validated
	err := ValidateSession(sess, idle, abs, now)
	// then it is still valid (expiry triggers strictly past the timeout)
	if err != nil {
		t.Errorf("ValidateSession(now-LastActivity == idleTimeout) = %v, want nil", err)
	}
}

func TestValidateSession_absolute_exactly_at_timeout_is_valid(t *testing.T) {
	t.Parallel()

	// given a session created exactly absTimeout ago with recent activity
	idle := time.Hour
	abs := 24 * time.Hour
	now := time.Now()
	sess := &Session{LastActivity: now, CreatedAt: now.Add(-abs)}

	// when validated
	err := ValidateSession(sess, idle, abs, now)
	// then it is still valid (expiry triggers strictly past the timeout)
	if err != nil {
		t.Errorf("ValidateSession(now-CreatedAt == absTimeout) = %v, want nil", err)
	}
}

// --- session_verifier.go L64 and L73: conditional-negation mutants on
// logging branches. These are observable only through emitted log records,
// so a capturing slog handler is injected via WithLogger. ---

// recordingHandler captures every slog.Record regardless of level.
type recordingHandler struct {
	records []slog.Record
	mu      sync.Mutex
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}

func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// countMsg returns how many captured records have a message containing sub.
func (h *recordingHandler) countMsg(sub string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, r := range h.records {
		if strings.Contains(r.Message, sub) {
			n++
		}
	}
	return n
}

// newVerifierRequest builds a request carrying the session cookie for the
// default cookie configuration.
func newVerifierRequest(t *testing.T, plaintext string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	cfg := DefaultCookieConfig()
	r.AddCookie(&http.Cookie{Name: cfg.EffectiveName(), Value: plaintext})
	return r
}

func TestSessionVerifier_successful_activity_update_logs_no_warning(t *testing.T) {
	t.Parallel()

	// given an enabled user with a live session (activity update succeeds)
	h := &recordingHandler{}
	store := newFakeSessionStore()
	ctx := context.Background()
	user := &User{Username: "alice", Role: RoleAdmin, Enabled: true}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	plaintext, hash, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	now := time.Now()
	if err := store.CreateSession(ctx, &Session{TokenHash: hash, UserID: user.ID, CreatedAt: now, LastActivity: now}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	v := NewSessionVerifier(store, WithLogger(slog.New(h)), WithCookie(DefaultCookieConfig()))

	// when verifying the request
	gotUser, _, err := v.Verify(ctx, newVerifierRequest(t, plaintext))

	// then the user is returned and no activity-update warning is logged
	if err != nil || gotUser == nil {
		t.Fatalf("Verify() = (%v, %v), want a valid user and nil error", gotUser, err)
	}
	if n := h.countMsg("session activity update failed"); n != 0 {
		t.Errorf("Verify() with successful activity update logged %d activity-update warnings, want 0", n)
	}
}

func TestSessionVerifier_disabled_user_logs_debug(t *testing.T) {
	t.Parallel()

	// given a disabled user with an otherwise-valid session
	h := &recordingHandler{}
	store := newFakeSessionStore()
	ctx := context.Background()
	user := &User{Username: "alice", Role: RoleAdmin, Enabled: false}
	if err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	plaintext, hash, err := GenerateSessionToken()
	if err != nil {
		t.Fatalf("GenerateSessionToken: %v", err)
	}
	now := time.Now()
	if err := store.CreateSession(ctx, &Session{TokenHash: hash, UserID: user.ID, CreatedAt: now, LastActivity: now}); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}

	v := NewSessionVerifier(store, WithLogger(slog.New(h)), WithCookie(DefaultCookieConfig()))

	// when verifying the request
	gotUser, _, err := v.Verify(ctx, newVerifierRequest(t, plaintext))
	// then authentication is refused and the disabled-user attempt is logged
	if err != nil {
		t.Fatalf("Verify() error = %v, want nil", err)
	}
	if gotUser != nil {
		t.Fatalf("Verify() = %v, want nil (disabled user)", gotUser)
	}
	if n := h.countMsg("disabled user attempted session auth"); n != 1 {
		t.Errorf("Verify() with disabled user logged %d disabled-user debug records, want 1", n)
	}
}
