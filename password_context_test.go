package auth

import "testing"

func TestValidatePasswordContext(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name           string
		password       string
		username       string
		forbiddenWords []string
		wantErr        bool
	}{
		{"clean", "correct horse battery staple", "alice", []string{"forbidden"}, false},
		{"contains forbidden word", "myforbiddenpassword", "alice", []string{"forbidden"}, true},
		{"contains forbidden word mixed case", "MyForbiddenPass", "alice", []string{"forbidden"}, true},
		{"contains username", "alice-secret-passphrase", "alice", nil, true},
		{"contains username mixed case", "xxALICExxpadding", "alice", nil, true},
		{"short username ignored", "bobsyouruncle-long-pass", "bob", nil, false},
		{"four-char username rejected", "myuserlongpassword", "user", nil, true},
		{"empty username ok", "a-perfectly-fine-passphrase", "", nil, false},
		{"no forbidden words", "anything-goes-here", "alice", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidatePasswordContext(tc.password, PasswordContext{Username: tc.username, ForbiddenWords: tc.forbiddenWords})
			if (err != nil) != tc.wantErr {
				t.Errorf("ValidatePasswordContext(%q, {Username: %q, ForbiddenWords: %v}) err = %v, wantErr = %v",
					tc.password, tc.username, tc.forbiddenWords, err, tc.wantErr)
			}
		})
	}
}
