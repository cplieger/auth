package webauthn

import (
	"bytes"
	"regexp"
	"testing"
)

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// FuzzFormatAAGUID pins two invariants of formatAAGUID: a 16-byte input always
// formats to a canonical lowercase UUID that parses back to the original bytes,
// and any other length yields the empty string.
func FuzzFormatAAGUID(f *testing.F) {
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{})
	f.Add([]byte{1, 2, 3})
	f.Add(make([]byte, 17))

	f.Fuzz(func(t *testing.T, input []byte) {
		result := formatAAGUID(input)

		if len(input) != 16 {
			if result != "" {
				t.Fatalf("formatAAGUID(%d-byte input) = %q, want empty string", len(input), result)
			}
			return
		}

		if !uuidRe.MatchString(result) {
			t.Fatalf("formatAAGUID(% x) = %q, want canonical UUID format", input, result)
		}
		if got := parseAAGUID(result); !bytes.Equal(got, input) {
			t.Fatalf("parseAAGUID(formatAAGUID(% x)) = % x, want round-trip to original", input, got)
		}
	})
}
