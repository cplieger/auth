package auth

import "testing"

func FuzzValidateRedirectURI(f *testing.F) {
	f.Add("/")
	f.Add("/dashboard")
	f.Add("//evil.com")
	f.Add("https://evil.com")
	f.Add("")
	f.Add("/path?q=1#frag")
	f.Add("javascript:alert(1)")

	f.Fuzz(func(t *testing.T, uri string) {
		result := ValidateRedirectURI(uri)
		if result == "" {
			t.Error("returned empty string")
		}
		if len(result) > 0 && result[0] != '/' {
			t.Errorf("result %q does not start with /", result)
		}
		if len(result) > 1 && result[1] == '/' {
			t.Errorf("result %q starts with // (open redirect)", result)
		}
	})
}
