package auth

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestProperty_PasswordHashRoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		password := rapid.StringN(8, 128, -1).Draw(t, "password")

		hash := HashPassword(password)

		ok, err := VerifyPassword(password, hash)
		if err != nil {
			t.Fatalf("VerifyPassword(same) error: %v", err)
		}
		if !ok {
			t.Fatalf("VerifyPassword(same) = false")
		}

		other := password + "x"
		ok, err = VerifyPassword(other, hash)
		if err != nil {
			t.Fatalf("VerifyPassword(different) error: %v", err)
		}
		if ok {
			t.Fatalf("VerifyPassword(different) = true")
		}
	})
}

func TestProperty_UniqueSaltPerHash(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		password := rapid.StringN(1, 128, -1).Draw(t, "password")

		hash1 := HashPassword(password)
		hash2 := HashPassword(password)
		if hash1 == hash2 {
			t.Fatalf("two hashes identical (salt reuse)")
		}
	})
}

func TestProperty_PasswordLengthValidation(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		short := rapid.StringN(0, 7, -1).Draw(t, "short")
		if err := ValidateMultiFactorPasswordLength(short); err == nil {
			t.Fatalf("ValidateMultiFactorPasswordLength(%q) = nil", short)
		}

		valid := rapid.StringN(8, 128, -1).Draw(t, "valid")
		if err := ValidateMultiFactorPasswordLength(valid); err != nil {
			t.Fatalf("ValidateMultiFactorPasswordLength(%q) = %v", valid, err)
		}

		shortSolo := rapid.StringN(0, 14, -1).Draw(t, "shortSolo")
		if err := ValidateSoloPasswordLength(shortSolo); err == nil {
			t.Fatalf("ValidateSoloPasswordLength(%q) = nil", shortSolo)
		}

		validSolo := rapid.StringN(15, 128, -1).Draw(t, "validSolo")
		if err := ValidateSoloPasswordLength(validSolo); err != nil {
			t.Fatalf("ValidateSoloPasswordLength(%q) = %v", validSolo, err)
		}

		// Max length enforcement
		tooLong := rapid.StringN(129, 256, -1).Draw(t, "tooLong")
		if err := ValidateMultiFactorPasswordLength(tooLong); err == nil {
			t.Fatalf("ValidateMultiFactorPasswordLength(len=%d) = nil, want error", len([]rune(tooLong)))
		}
	})
}

func TestVerifyPassword_rejects_malformed_hashes(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		hash string
	}{
		{"empty_string", ""},
		{"wrong_algorithm", "$argon2i$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"},
		{"too_few_parts", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA"},
		{"bad_version", "$argon2id$v=abc$m=19456,t=2,p=1$c2FsdA$aGFzaA"},
		{"bad_params", "$argon2id$v=19$garbage$c2FsdA$aGFzaA"},
		{"bad_salt_base64", "$argon2id$v=19$m=19456,t=2,p=1$!!!invalid!!!$aGFzaA"},
		{"bad_key_base64", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$!!!invalid!!!"},
		{"wrong_version_number", "$argon2id$v=18$m=19456,t=2,p=1$c2FsdA$aGFzaA"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ok, err := VerifyPassword("anything", tc.hash)
			if err == nil {
				t.Fatalf("VerifyPassword(_, %q) = (%v, nil), want error", tc.hash, ok)
			}
			if ok {
				t.Fatalf("VerifyPassword(_, %q) = (true, _), want false", tc.hash)
			}
		})
	}
}

func TestNeedsRehash(t *testing.T) {
	t.Parallel()

	// Current params → false
	hash := HashPassword("test-password")
	if NeedsRehash(hash) {
		t.Error("current params should not need rehash")
	}

	for _, tc := range []struct {
		name string
		hash string
		want bool
	}{
		{"different memory", "$argon2id$v=19$m=65536,t=2,p=1$c2FsdHNhbHRzYWx0c2Fs$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA", true},
		{"different iterations", "$argon2id$v=19$m=19456,t=3,p=1$c2FsdHNhbHRzYWx0c2Fs$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaA", true},
		{"different key length", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2Fs$c2hvcnQ", true},
		{"invalid hash", "not-a-valid-hash", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := NeedsRehash(tc.hash); got != tc.want {
				t.Errorf("NeedsRehash(%q) = %v, want %v", tc.hash, got, tc.want)
			}
		})
	}
}

func TestVerifyPassword_oneByteKey_parsesButDoesNotMatch(t *testing.T) {
	t.Parallel()
	// A well-formed PHC hash whose key is exactly one byte (base64 "AA") is the
	// lower bound of the key-length check: parsing must succeed (no error) and
	// the password simply must not match.
	const hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2Fs$AA"
	ok, err := VerifyPassword("whatever", hash)
	if err != nil {
		t.Errorf("VerifyPassword(_, 1-byte-key hash) error = %v, want nil", err)
	}
	if ok {
		t.Errorf("VerifyPassword(_, 1-byte-key hash) = true, want false")
	}
}

func TestValidateMultiFactorPasswordLength_exactlyMax_accepted(t *testing.T) {
	t.Parallel()
	// A password of exactly PasswordMaxLength runes is accepted; rejection
	// begins strictly past the maximum.
	pw := strings.Repeat("a", PasswordMaxLength)
	if err := ValidateMultiFactorPasswordLength(pw); err != nil {
		t.Errorf("ValidateMultiFactorPasswordLength(len=%d) = %v, want nil", PasswordMaxLength, err)
	}
}

func TestDummyHash_isVerifiableCurrentParamsHash(t *testing.T) {
	t.Parallel()
	// DummyHash exists so the login handler can run a real verification for
	// unknown users and avoid a user-enumeration timing oracle (H2). The
	// returned value must therefore be a well-formed, current-parameter
	// Argon2id hash that VerifyPassword can process without error.
	h := DummyHash()
	if h == "" {
		t.Fatal("DummyHash() = empty string, want a PHC Argon2id hash")
	}
	ok, err := VerifyPassword("not-the-dummy-password", h)
	if err != nil {
		t.Errorf("VerifyPassword(_, DummyHash()) error = %v, want nil (hash must be parseable)", err)
	}
	if ok {
		t.Error("VerifyPassword(arbitrary, DummyHash()) = true, want false")
	}
	if NeedsRehash(h) {
		t.Error("NeedsRehash(DummyHash()) = true, want false (dummy must use current OWASP params)")
	}
	if h2 := DummyHash(); h2 != h {
		t.Error("DummyHash() returned different values across calls, want a stable cached hash")
	}
}
