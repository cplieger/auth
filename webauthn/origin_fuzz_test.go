package webauthn

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

// FuzzParseOrigin_roundtrip pins the properties the origin design rests on:
// the parser never panics on an attacker-controlled header, a parsed origin
// re-parses to itself, and the INPUT matches the parsed value under the
// upstream comparator the response is verified with. The last is what a
// repairing parser breaks, and it is the durable guard against re-introducing
// one: with a trailing-dot strip, "https://example.com." parses to a value the
// comparator no longer relates to the input.
func FuzzParseOrigin_roundtrip(f *testing.F) {
	for _, seed := range []string{
		"https://example.com",
		"https://example.com:443",
		"https://example.com:8443",
		"http://localhost:8374",
		"HTTPS://EXAMPLE.COM",
		"https://example.com/",
		"https://[::1]:8443",
		"https://[0:0:0:0:0:0:0:1]",
		"null",
		"https://example.com.",
		"https://sub..example.com",
		"https://ex%C3%A4mple.com",
		"https://u:p@example.com",
		"https://example.com:99999",
		"",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		o, err := ParseOrigin(raw)
		if err != nil {
			if !o.IsZero() {
				t.Fatalf("ParseOrigin(%q) = %v with error %v, want the zero Origin on refusal", raw, o, err)
			}
			return
		}
		again, err := ParseOrigin(o.String())
		if err != nil {
			t.Fatalf("ParseOrigin(%q).String() = %q does not re-parse: %v", raw, o.String(), err)
		}
		if again != o {
			t.Fatalf("ParseOrigin(%q) = %+v, re-parsed as %+v, want a stable round trip", raw, o, again)
		}
		if !protocol.IsOriginInHaystack(o.String(), []string{o.String()}) {
			t.Fatalf("ParseOrigin(%q).String() = %q is not equal to itself under the upstream comparator", raw, o.String())
		}
		if !protocol.IsOriginInHaystack(raw, []string{o.String()}) {
			t.Fatalf("ParseOrigin(%q) = %q, which the upstream comparator does not match against the input; the parser repaired something", raw, o.String())
		}
	})
}
