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

		hash, err := HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword(%q) error: %v", password, err)
		}

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

		hash1, err := HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword(1) error: %v", err)
		}
		hash2, err := HashPassword(password)
		if err != nil {
			t.Fatalf("HashPassword(2) error: %v", err)
		}
		if hash1 == hash2 {
			t.Fatalf("two hashes identical (salt reuse)")
		}
	})
}

func TestProperty_PasswordLengthValidation(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		short := rapid.StringN(0, 7, -1).Draw(t, "short")
		if err := ValidatePasswordLength(short, false); err == nil {
			t.Fatalf("ValidatePasswordLength(%q, false) = nil", short)
		}

		valid := rapid.StringN(8, 128, -1).Draw(t, "valid")
		if err := ValidatePasswordLength(valid, false); err != nil {
			t.Fatalf("ValidatePasswordLength(%q, false) = %v", valid, err)
		}

		shortSolo := rapid.StringN(0, 14, -1).Draw(t, "shortSolo")
		if err := ValidatePasswordLength(shortSolo, true); err == nil {
			t.Fatalf("ValidatePasswordLength(%q, true) = nil", shortSolo)
		}

		validSolo := rapid.StringN(15, 128, -1).Draw(t, "validSolo")
		if err := ValidatePasswordLength(validSolo, true); err != nil {
			t.Fatalf("ValidatePasswordLength(%q, true) = %v", validSolo, err)
		}

		// Max length enforcement
		tooLong := rapid.StringN(129, 256, -1).Draw(t, "tooLong")
		if err := ValidatePasswordLength(tooLong, false); err == nil {
			t.Fatalf("ValidatePasswordLength(len=%d, false) = nil, want error", len([]rune(tooLong)))
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
	hash, err := HashPassword("test-password")
	if err != nil {
		t.Fatal(err)
	}
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

func TestValidatePasswordLength_exactlyMax_accepted(t *testing.T) {
	t.Parallel()
	// A password of exactly PasswordMaxLength runes is accepted; rejection
	// begins strictly past the maximum.
	pw := strings.Repeat("a", PasswordMaxLength)
	if err := ValidatePasswordLength(pw, false); err != nil {
		t.Errorf("ValidatePasswordLength(len=%d, false) = %v, want nil", PasswordMaxLength, err)
	}
}
