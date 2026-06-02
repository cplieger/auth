package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/cplieger/auth"

	"pgregory.net/rapid"
)

func TestProperty_OIDCIdentityResolution(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		claims := &Claims{
			Subject:           rapid.StringMatching(`[a-z0-9]{8,32}`).Draw(t, "sub"),
			Issuer:            "https://idp.example.com",
			Email:             rapid.StringMatching(`[a-z]{4,8}@[a-z]{4,8}\.[a-z]{2,4}`).Draw(t, "email"),
			PreferredUsername: rapid.StringMatching(`[a-z]{4,16}`).Draw(t, "preferred_username"),
			Name:              rapid.StringMatching(`[A-Z][a-z]{2,8} [A-Z][a-z]{2,8}`).Draw(t, "name"),
		}

		existingBySub := &auth.User{
			ID:       rapid.Int64Range(1, 1000).Draw(t, "subUserID"),
			Username: "oidc-sub-user",
			Role:     "admin",
			Enabled:  true,
		}

		user, isNew := ResolveUser(claims, existingBySub)
		if user != existingBySub {
			t.Fatal("expected existingBySub on sub match")
		}
		if isNew {
			t.Fatal("expected isNew=false")
		}

		user, isNew = ResolveUser(claims, nil)
		if !isNew {
			t.Fatal("expected isNew=true")
		}
		if user.Role != auth.RoleUser {
			t.Fatalf("expected role 'user', got %q", user.Role)
		}
		if user.Username != claims.PreferredUsername {
			t.Fatalf("username = %q, want %q", user.Username, claims.PreferredUsername)
		}
	})
}

func TestProperty_OIDCIdentityResolution_EmptyPreferredUsername(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		claims := &Claims{
			Subject:           rapid.StringMatching(`[a-z0-9]{8,32}`).Draw(t, "sub"),
			Email:             rapid.StringMatching(`[a-z]{4,8}@[a-z]{4,8}\.[a-z]{2,4}`).Draw(t, "email"),
			PreferredUsername: "",
		}
		user, isNew := ResolveUser(claims, nil)
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
	})
}

func TestProperty_StateGeneration(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 20).Draw(t, "n")
		states := make(map[string]struct{}, n)
		for i := range n {
			state, err := GenerateState()
			if err != nil {
				t.Fatalf("GenerateState[%d] error: %v", i, err)
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

func TestValidateConfig_errors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		wantErr string
		cfg     Config
	}{
		{"empty issuer_url", "issuer_url is required", Config{ClientID: "cid", RedirectURI: "http://localhost/cb"}},
		{"empty client_id", "client_id is required", Config{IssuerURL: "https://idp.example.com", RedirectURI: "http://localhost/cb"}},
		{"empty redirect_uri", "redirect_uri is required", Config{IssuerURL: "https://idp.example.com", ClientID: "cid"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewProvider(context.Background(), tt.cfg)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}
