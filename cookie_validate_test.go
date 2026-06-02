package auth

import "testing"

func TestCookieConfig_Validate_RejectsControlChars(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  CookieConfig
	}{
		{"null in name", CookieConfig{Name: "bad\x00name", Prefix: CookieNoPrefix}},
		{"newline in name", CookieConfig{Name: "bad\nname", Prefix: CookieNoPrefix}},
		{"cr in name", CookieConfig{Name: "bad\rname", Prefix: CookieNoPrefix}},
		{"semicolon in name", CookieConfig{Name: "bad;name", Prefix: CookieNoPrefix}},
		{"space in name", CookieConfig{Name: "bad name", Prefix: CookieNoPrefix}},
		{"null in domain", CookieConfig{Name: "ok", Prefix: CookieNoPrefix, Domain: "evil\x00.com"}},
		{"newline in path", CookieConfig{Name: "ok", Prefix: CookieNoPrefix, Path: "/\nevil"}},
		{"control in prefix", CookieConfig{Name: "ok", Prefix: "__Host\x01-"}},
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
		{"custom name", CookieConfig{Name: "my_session", Prefix: CookieNoPrefix}},
		{"with domain", CookieConfig{Name: "sess", Domain: "example.com", Prefix: CookieNoPrefix}},
		{"with path", CookieConfig{Name: "sess", Path: "/app/auth", Prefix: CookieNoPrefix}},
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
