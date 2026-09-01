package auth

import (
	"net/http"
	"testing"
)

func FuzzValidateCookieField(f *testing.F) {
	f.Add("session")
	f.Add("")
	f.Add("name with spaces")
	f.Add("name;semicolon")
	f.Add("ctrl\x00char")
	f.Add("\x1f\x7f")
	f.Add("valid-cookie-name")
	f.Add("日本語クッキー")

	f.Fuzz(func(t *testing.T, input string) {
		err := validateCookieField("Name", input)
		if err != nil {
			return
		}
		for _, r := range input {
			if r < 0x20 || r == 0x7f {
				t.Fatalf("nil error but contains control char %U", r)
			}
		}
		for _, r := range input {
			switch r {
			case ' ', ';', '=', ',', '"', '\\':
				t.Fatalf("nil error but contains separator %q", r)
			}
		}
	})
}

func FuzzCookieConfigValidate(f *testing.F) {
	f.Add("session", "/", "example.com")
	f.Add("", "", "")
	f.Add("a\x00b", "/\x1f", "dom\x7f")
	f.Add("spaces here", "/path;bad", "evil;domain")

	f.Fuzz(func(t *testing.T, name, path, domain string) {
		cfg := &CookieConfig{
			Name:     name,
			Path:     path,
			Domain:   domain,
			SameSite: http.SameSiteLaxMode,
			Posture:  PostureInsecureLAN, // avoid __Host- prefix requiring Domain=""
		}
		if cfg.Validate() != nil {
			return
		}
		// A nil error promises every field written into the Set-Cookie header is
		// injection-free. Validate checks the resolved EffectiveName plus any
		// non-empty Domain/Path, so each must be free of control characters and
		// the name free of cookie-name separators.
		hasControl := func(s string) bool {
			for _, r := range s {
				if r < 0x20 || r == 0x7f {
					return true
				}
			}
			return false
		}
		eff := cfg.EffectiveName()
		if hasControl(eff) {
			t.Errorf("Validate()=nil but EffectiveName %q contains a control character", eff)
		}
		for _, r := range eff {
			switch r {
			case ' ', ';', '=', ',', '"', '\\':
				t.Errorf("Validate()=nil but EffectiveName %q contains separator %q", eff, r)
			}
		}
		if cfg.Domain != "" && hasControl(cfg.Domain) {
			t.Errorf("Validate()=nil but Domain %q contains a control character", cfg.Domain)
		}
		if cfg.Path != "" && hasControl(cfg.Path) {
			t.Errorf("Validate()=nil but Path %q contains a control character", cfg.Path)
		}
	})
}
