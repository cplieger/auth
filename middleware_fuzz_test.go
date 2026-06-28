package auth

import (
	"strings"
	"testing"
)

func FuzzValidateRedirectURI(f *testing.F) {
	f.Add("/")
	f.Add("/dashboard")
	f.Add("//evil.com")
	f.Add("https://evil.com")
	f.Add("")
	f.Add("/path?q=1#frag")
	f.Add("javascript:alert(1)")
	f.Add("/\\evil.com")
	f.Add("/path\\to\\file")
	f.Add("/%zz")

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
		// A non-root result is the input accepted unchanged and must never
		// carry an open-redirect vector: no backslash (browsers fold "/\" to
		// "//") and no scheme separator.
		if result != "/" {
			if result != uri {
				t.Errorf("ValidateRedirectURI(%q) = %q, want either \"/\" or the input unchanged", uri, result)
			}
			if strings.Contains(result, "\\") {
				t.Errorf("accepted redirect %q contains a backslash (open-redirect vector)", result)
			}
			if strings.Contains(result, "://") {
				t.Errorf("accepted redirect %q contains a scheme separator", result)
			}
		}
	})
}
