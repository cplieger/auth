package auth

import "testing"

func FuzzVerifyPassword(f *testing.F) {
	f.Add("$argon2id$v=19$m=19456,t=2,p=1$c29tZXNhbHQ$c29tZWhhc2g")
	f.Add("")
	f.Add("$bcrypt$invalid$format")
	f.Add("not-a-hash-at-all")
	f.Fuzz(func(t *testing.T, encoded string) {
		_, _ = parsePHC(encoded)
	})
}
