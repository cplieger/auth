package auth

import "testing"

func TestCookieConfig_Validate_RejectsControlChars(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  CookieConfig
	}{
		{"null in name", CookieConfig{Posture: PostureInsecureLAN, Name: "bad\x00name"}},
		{"newline in name", CookieConfig{Posture: PostureInsecureLAN, Name: "bad\nname"}},
		{"cr in name", CookieConfig{Posture: PostureInsecureLAN, Name: "bad\rname"}},
		{"semicolon in name", CookieConfig{Posture: PostureInsecureLAN, Name: "bad;name"}},
		{"space in name", CookieConfig{Posture: PostureInsecureLAN, Name: "bad name"}},
		{"null in domain", CookieConfig{Posture: PostureInsecureLAN, Name: "ok", Domain: "evil\x00.com"}},
		{"newline in path", CookieConfig{Posture: PostureInsecureLAN, Name: "ok", Path: "/\nevil"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.cfg.Validate(); err == nil {
				t.Fatal("expected Validate() to reject config with invalid characters")
			}
		})
	}
}

func TestCookieConfig_Validate_AcceptsValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  CookieConfig
	}{
		{"default", DefaultCookieConfig()},
		{"custom name insecure", CookieConfig{Posture: PostureInsecureLAN, Name: "my_session"}},
		{"with domain", CookieConfig{Posture: PostureInsecureLAN, Name: "sess", Domain: "example.com"}},
		{"with path", CookieConfig{Posture: PostureInsecureLAN, Name: "sess", Path: "/app/auth"}},
		{"zero value", CookieConfig{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if err := tc.cfg.Validate(); err != nil {
				t.Fatalf("Validate() = %v, want nil", err)
			}
		})
	}
}
