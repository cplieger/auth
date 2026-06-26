package auth

import (
	"strings"
	"testing"
)

func FuzzValidatePasswordLength(f *testing.F) {
	f.Add("short", true)
	f.Add("a]valid-password!!", false)
	f.Add(strings.Repeat("あ", 129), true)
	f.Add("pass\x00word\x00null", false)
	f.Add("", true)

	f.Fuzz(func(t *testing.T, pw string, passwordOnly bool) {
		err := ValidatePasswordLength(pw, passwordOnly)
		if err != nil {
			return
		}
		runeLen := len([]rune(pw))
		minLen := PasswordMinLengthMultiFactor
		if passwordOnly {
			minLen = PasswordMinLengthSolo
		}
		if runeLen < minLen || runeLen > PasswordMaxLength {
			t.Errorf("nil error but rune length %d outside [%d, %d]", runeLen, minLen, PasswordMaxLength)
		}
	})
}

func FuzzValidatePasswordContext(f *testing.F) {
	f.Add("MyP@ssword123", "user", "company")
	f.Add("contains-admin-word", "admin", "admin")
	f.Add("", "", "")
	f.Add("héllo世界", "世界", "")

	f.Fuzz(func(t *testing.T, pw, username, forbiddenWord string) {
		var forbidden []string
		if forbiddenWord != "" {
			forbidden = []string{forbiddenWord}
		}
		err := ValidatePasswordContext(pw, username, forbidden)
		if err != nil {
			return
		}
		lower := strings.ToLower(pw)
		if len(username) >= 4 && strings.Contains(lower, strings.ToLower(username)) {
			t.Errorf("nil error but password contains username %q", username)
		}
		if forbiddenWord != "" && strings.Contains(lower, strings.ToLower(forbiddenWord)) {
			t.Errorf("nil error but password contains forbidden word %q", forbiddenWord)
		}
	})
}

func FuzzVerifyPassword(f *testing.F) {
	f.Add("test-password-long-enough")
	f.Add("short")
	f.Add("")

	f.Fuzz(func(t *testing.T, pw string) {
		hash, err := HashPassword(pw)
		if err != nil {
			t.Skipf("HashPassword error: %v", err)
		}
		ok, err := VerifyPassword(pw, hash)
		if err != nil {
			t.Fatalf("VerifyPassword(correct) error: %v", err)
		}
		if !ok {
			t.Fatal("VerifyPassword(correct) returned false")
		}
		ok, err = VerifyPassword(pw+"x", hash)
		if err != nil {
			t.Fatalf("VerifyPassword(wrong) error: %v", err)
		}
		if ok {
			t.Fatal("VerifyPassword(wrong) returned true")
		}
	})
}

// FuzzParsePHC drives untrusted PHC hash strings through the parser. Beyond not
// panicking (the parser feeds argon2.IDKey, which panics on zero params), it
// pins the invariant that a successful parse always yields params safe for
// argon2: iterations, parallelism, and key length are all >= 1.
func FuzzParsePHC(f *testing.F) {
	seeds := []string{
		"$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$c29tZWhhc2g",
		"",
		"$",
		"$$$$$$",
		"not-a-hash",
		"$bcrypt$invalid$format$$$",
		"$notargon2id$v=19$m=19456,t=2,p=1$AAAA$BBBB",
		"$argon2id$v=99$m=19456,t=2,p=1$AAAA$BBBB",
		"$argon2id$v=0$m=19456,t=2,p=1$AAAA$BBBB",
		"$argon2id$v=19$m=0,t=0,p=0$$",
		"$argon2id$v=19$m=4294967295,t=4294967295,p=255$AAAA$BBBB",
		"$argon2id$v=19$m=-1,t=2,p=1$AAAA$BBBB",
		"$argon2id$v=19$m=19456,t=0,p=1$AAAA$BBBB",
		"$argon2id$v=19$m=19456,t=2,p=0$AAAA$BBBB",
		"$argon2id$v=19$m=19456,t=2,p=1$$BBBB",
		"$argon2id$v=19$m=19456,t=2,p=1$AAAA$",
		"$argon2id$v=19$m=19456,t=2,p=1$!!!invalid-base64!!!$BBBB",
		"$argon2id$v=19$m=19456,t=2,p=1$AAAA$!!!invalid-base64!!!",
		"$argon2id$v=19$m=19456,t=2,p=1$" + strings.Repeat("A", 10000) + "$BBBB",
		"$argon2id$v=19$m=19456,t=2,p=1$AAAA$" + strings.Repeat("B", 10000),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, encoded string) {
		p, err := parsePHC(encoded)
		if err != nil {
			return
		}
		if p.iterations < 1 {
			t.Errorf("parsePHC(%q) succeeded with iterations = %d, want >= 1", encoded, p.iterations)
		}
		if p.parallelism < 1 {
			t.Errorf("parsePHC(%q) succeeded with parallelism = %d, want >= 1", encoded, p.parallelism)
		}
		if p.keyLen < 1 {
			t.Errorf("parsePHC(%q) succeeded with keyLen = %d, want >= 1", encoded, p.keyLen)
		}
	})
}
