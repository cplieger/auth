package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func TestProperty_OIDCIdentityResolution(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		claims := &OIDCClaims{
			Subject:           rapid.StringMatching(`[a-z0-9]{8,32}`).Draw(t, "sub"),
			Issuer:            "https://idp.example.com",
			Email:             rapid.StringMatching(`[a-z]{4,8}@[a-z]{4,8}\.[a-z]{2,4}`).Draw(t, "email"),
			PreferredUsername: rapid.StringMatching(`[a-z]{4,16}`).Draw(t, "preferred_username"),
			Name:              rapid.StringMatching(`[A-Z][a-z]{2,8} [A-Z][a-z]{2,8}`).Draw(t, "name"),
		}

		existingBySub := &User{
			ID:       rapid.Int64Range(1, 1000).Draw(t, "subUserID"),
			Username: "oidc-sub-user",
			Role:     "admin",
			Enabled:  true,
		}

		user, isNew := ResolveOIDCUser(claims, existingBySub)
		if user != existingBySub {
			t.Fatal("expected existingBySub on sub match")
		}
		if isNew {
			t.Fatal("expected isNew=false")
		}

		user, isNew = ResolveOIDCUser(claims, nil)
		if !isNew {
			t.Fatal("expected isNew=true")
		}
		if user.Role != "user" {
			t.Fatalf("expected role 'user', got %q", user.Role)
		}
		if user.Username != claims.PreferredUsername {
			t.Fatalf("username = %q, want %q", user.Username, claims.PreferredUsername)
		}
		if user.Email != claims.Email {
			t.Fatalf("email = %q, want %q", user.Email, claims.Email)
		}
		if user.DisplayName != claims.Name {
			t.Fatalf("display_name = %q, want %q", user.DisplayName, claims.Name)
		}
		if user.OIDCSub != claims.Subject {
			t.Fatalf("oidc_sub = %q, want %q", user.OIDCSub, claims.Subject)
		}
		if user.OIDCIssuer != claims.Issuer {
			t.Fatalf("oidc_issuer = %q, want %q", user.OIDCIssuer, claims.Issuer)
		}
		if !user.Enabled {
			t.Fatal("expected Enabled=true for new user")
		}
	})
}

func TestProperty_OIDCIdentityResolution_EmptyPreferredUsername(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		claims := &OIDCClaims{
			Subject:           rapid.StringMatching(`[a-z0-9]{8,32}`).Draw(t, "sub"),
			Email:             rapid.StringMatching(`[a-z]{4,8}@[a-z]{4,8}\.[a-z]{2,4}`).Draw(t, "email"),
			PreferredUsername: "",
		}
		user, isNew := ResolveOIDCUser(claims, nil)
		if !isNew {
			t.Fatal("expected isNew=true")
		}
		if user.Username != claims.Email {
			t.Fatalf("username = %q, want email %q", user.Username, claims.Email)
		}
	})
}

func TestProperty_PKCERoundTrip(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		verifier, challenge, err := GeneratePKCE()
		if err != nil {
			t.Fatalf("GeneratePKCE error: %v", err)
		}
		if verifier == "" || challenge == "" {
			t.Fatal("empty verifier or challenge")
		}

		h := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(h[:])
		if challenge != expected {
			t.Fatalf("challenge mismatch")
		}

		raw, err := base64.RawURLEncoding.DecodeString(verifier)
		if err != nil {
			t.Fatalf("verifier not valid base64url: %v", err)
		}
		if len(raw) != 32 {
			t.Fatalf("verifier raw length %d, want 32", len(raw))
		}
	})
}

func TestProperty_OIDCStateGeneration(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 20).Draw(t, "n")
		states := make(map[string]struct{}, n)
		for i := range n {
			state, err := GenerateOIDCState()
			if err != nil {
				t.Fatalf("GenerateOIDCState[%d] error: %v", i, err)
			}
			if len(state) != 64 {
				t.Fatalf("state length %d, want 64", len(state))
			}
			if _, dup := states[state]; dup {
				t.Fatalf("duplicate state")
			}
			states[state] = struct{}{}
		}
	})
}

func TestNewOIDCProvider_validation_errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		wantErr string
		cfg     OIDCConfig
	}{
		{"empty issuer_url", "issuer_url is required", OIDCConfig{ClientID: "cid", RedirectURI: "http://localhost/cb"}},
		{"empty client_id", "client_id is required", OIDCConfig{IssuerURL: "https://idp.example.com", RedirectURI: "http://localhost/cb"}},
		{"empty redirect_uri", "redirect_uri is required", OIDCConfig{IssuerURL: "https://idp.example.com", ClientID: "cid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewOIDCProvider(context.Background(), tt.cfg)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestProperty_PKCEUniqueness(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 20).Draw(t, "n")
		verifiers := make(map[string]struct{}, n)
		challenges := make(map[string]struct{}, n)

		for i := range n {
			verifier, challenge, err := GeneratePKCE()
			if err != nil {
				t.Fatalf("GeneratePKCE[%d] error: %v", i, err)
			}
			if _, dup := verifiers[verifier]; dup {
				t.Fatalf("duplicate verifier at index %d", i)
			}
			verifiers[verifier] = struct{}{}
			if _, dup := challenges[challenge]; dup {
				t.Fatalf("duplicate challenge at index %d", i)
			}
			challenges[challenge] = struct{}{}
		}
	})
}
