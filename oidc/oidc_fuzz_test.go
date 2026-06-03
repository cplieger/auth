package oidc

import "testing"

func FuzzOIDCValidateConfig(f *testing.F) {
	f.Add("https://issuer.example.com", "client-id", "https://app.example.com/callback")
	f.Add("", "", "")
	f.Add("http://x", "c", "http://y")
	f.Add("\x00", "\x00", "\x00")
	f.Add("https://a.b", "id", "")

	f.Fuzz(func(t *testing.T, issuerURL, clientID, redirectURI string) {
		cfg := Config{
			IssuerURL:   issuerURL,
			ClientID:    clientID,
			RedirectURI: redirectURI,
		}
		err := ValidateConfig(cfg)
		// Must never panic
		if err == nil {
			// If no error, all fields must be non-empty
			if issuerURL == "" || clientID == "" || redirectURI == "" {
				t.Fatal("nil error with empty required field")
			}
		}
	})
}
