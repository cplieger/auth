package auth

import "testing"

// TestNilOption_InSlice_NoPanic regression: nil Option in variadic must not panic.
func TestNilOption_InSlice_NoPanic(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic with nil Option in slice: %v", r)
		}
	}()
	a := mustAuthenticator(t, newFakeSessionStore(), nil, WithLoginPath("/x"), nil)
	if a.cfg.idleTimeout != DefaultIdleTimeout {
		t.Errorf("defaults not applied after nil option: %v", a.cfg.idleTimeout)
	}
	if a.cfg.loginPath != "/x" {
		t.Errorf("non-nil option not applied: loginPath = %q", a.cfg.loginPath)
	}
}

// TestNilOption_SessionVerifier_NoPanic regression: nil Option must not panic.
func TestNilOption_SessionVerifier_NoPanic(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic with nil Option: %v", r)
		}
	}()
	v := mustSessionVerifier(t, newFakeSessionStore(), nil)
	if v.cfg.idleTimeout != DefaultIdleTimeout {
		t.Errorf("defaults not applied: %v", v.cfg.idleTimeout)
	}
}

// TestNilHasherOption_NoPanic regression: nil HasherOption must not panic.
func TestNilHasherOption_NoPanic(t *testing.T) {
	t.Parallel()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic with nil HasherOption: %v", r)
		}
	}()
	h, err := NewHasher(DefaultArgon2Params(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if h == nil {
		t.Fatal("Hasher is nil")
	}
}
