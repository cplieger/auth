package auth

import "testing"

func TestVerifyPassword_NoPanicOnMalformedParams(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		hash string
	}{
		{"empty key", "$argon2id$v=19$m=19456,t=2,p=1$AAAA$"},
		{"zero iterations", "$argon2id$v=19$m=19456,t=0,p=1$AAAA$BBBB"},
		{"zero parallelism", "$argon2id$v=19$m=19456,t=2,p=0$AAAA$BBBB"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ok, err := VerifyPassword("test", tc.hash)
			if ok {
				t.Fatal("expected ok=false for malformed hash")
			}
			if err == nil {
				t.Fatal("expected error for malformed hash")
			}
		})
	}
}

func TestHasherVerify_NoPanicOnMalformedParams(t *testing.T) {
	t.Parallel()
	h, err := NewHasher(DefaultArgon2Params())
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		hash string
	}{
		{"empty key", "$argon2id$v=19$m=19456,t=2,p=1$AAAA$"},
		{"zero iterations", "$argon2id$v=19$m=19456,t=0,p=1$AAAA$BBBB"},
		{"zero parallelism", "$argon2id$v=19$m=19456,t=2,p=0$AAAA$BBBB"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ok, verifyErr := h.Verify("test", tc.hash)
			if ok {
				t.Fatal("expected ok=false for malformed hash")
			}
			if verifyErr == nil {
				t.Fatal("expected error for malformed hash")
			}
		})
	}
}
