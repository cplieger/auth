package auth

import (
	"errors"
	"testing"

	"pgregory.net/rapid"
)

func TestNormalizeUsername_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr error
	}{
		{name: "ascii is lowercased", in: "ALEX", want: "alex"},
		{name: "already canonical is unchanged", in: "alex", want: "alex"},
		{name: "non-ascii case folds", in: "Müller", want: "müller"},
		{name: "non-ascii initial folds", in: "Ökonom", want: "ökonom"},
		{name: "sharp s is not transliterated", in: "straße", want: "straße"},
		{name: "dotted capital I decomposes", in: "İbrahim", want: "i\u0307brahim"},
		{name: "dot is allowed", in: "alex.muller", want: "alex.muller"},
		{name: "underscore is allowed", in: "alex_muller", want: "alex_muller"},
		{name: "hyphen is allowed", in: "alex-muller", want: "alex-muller"},
		{name: "digits are allowed", in: "user2", want: "user2"},

		{name: "empty is rejected", in: "", wantErr: ErrUsernameEmpty},
		{name: "interior space is rejected", in: "alex muller", wantErr: ErrUsernameInvalid},
		{name: "trailing space is rejected", in: "admin ", wantErr: ErrUsernameInvalid},
		{name: "tab is rejected", in: "a\tb", wantErr: ErrUsernameInvalid},
		{name: "newline is rejected", in: "alex\nmuller", wantErr: ErrUsernameInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NormalizeUsername(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("NormalizeUsername(%q) error = %v, want %v", tt.in, err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("NormalizeUsername(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestNormalizeUsername_foldsToOneAccount states the property the index key
// depends on: two spellings that differ only by case are one account.
func TestNormalizeUsername_foldsToOneAccount(t *testing.T) {
	t.Parallel()
	pairs := [][2]string{
		{"alex", "ALEX"},
		{"müller", "MÜLLER"},
		{"ökonom", "Ökonom"},
		{"user2", "USER2"},
	}
	for _, p := range pairs {
		t.Run(p[0], func(t *testing.T) {
			t.Parallel()
			a, errA := NormalizeUsername(p[0])
			b, errB := NormalizeUsername(p[1])
			if errA != nil || errB != nil {
				t.Fatalf("NormalizeUsername(%q)/(%q) errors = %v/%v, want nil", p[0], p[1], errA, errB)
			}
			if a != b {
				t.Errorf("NormalizeUsername(%q) = %q and NormalizeUsername(%q) = %q, want equal", p[0], a, p[1], b)
			}
		})
	}
}

// TestNormalizeUsername_distinguishesNonEquivalent is the other half: a fold
// that collapsed too much would make two real accounts one, so pin the pairs
// the profile deliberately keeps apart.
func TestNormalizeUsername_distinguishesNonEquivalent(t *testing.T) {
	t.Parallel()
	pairs := [][2]string{
		{"straße", "strasse"},
		{"alex", "alexa"},
		{"müller", "muller"},
	}
	for _, p := range pairs {
		t.Run(p[0]+"_vs_"+p[1], func(t *testing.T) {
			t.Parallel()
			a, errA := NormalizeUsername(p[0])
			b, errB := NormalizeUsername(p[1])
			if errA != nil || errB != nil {
				t.Fatalf("NormalizeUsername(%q)/(%q) errors = %v/%v, want nil", p[0], p[1], errA, errB)
			}
			if a == b {
				t.Errorf("NormalizeUsername(%q) and NormalizeUsername(%q) both = %q, want different", p[0], p[1], a)
			}
		})
	}
}

// TestNormalizeUsername_isIdempotent is the property the storage layer relies
// on: it normalizes at index-write time and again on the login input, so a
// second application must not move the value.
func TestNormalizeUsername_isIdempotent(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		in := rapid.String().Draw(t, "username")
		once, err := NormalizeUsername(in)
		if err != nil {
			return // rejected inputs have no canonical form to re-apply
		}
		twice, err := NormalizeUsername(once)
		if err != nil {
			t.Fatalf("NormalizeUsername(%q) accepted but NormalizeUsername(%q) = error %v, want nil", in, once, err)
		}
		if twice != once {
			t.Fatalf("NormalizeUsername(%q) = %q, then NormalizeUsername(%q) = %q, want stable", in, once, once, twice)
		}
	})
}
