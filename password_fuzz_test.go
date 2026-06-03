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
