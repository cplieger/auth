package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/cplieger/auth/v4"
	"golang.org/x/oauth2"
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

		user, isNew, err := ResolveUser(claims, existingBySub)
		if err != nil {
			t.Fatalf("ResolveUser(existing) error = %v, want nil", err)
		}
		if user != existingBySub {
			t.Fatal("expected existingBySub on sub match")
		}
		if isNew {
			t.Fatal("expected isNew=false")
		}

		user, isNew, err = ResolveUser(claims, nil)
		if err != nil {
			t.Fatalf("ResolveUser(new) error = %v, want nil", err)
		}
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
		user, isNew, err := ResolveUser(claims, nil)
		if err != nil {
			t.Fatalf("ResolveUser(email fallback) error = %v, want nil", err)
		}
		if !isNew {
			t.Fatal("expected isNew=true")
		}
		if user.Username != claims.Email {
			t.Fatalf("username = %q, want email %q", user.Username, claims.Email)
		}
	})
}

func TestUsernameFromClaims(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		claims  *Claims
		want    string
		wantErr bool
	}{
		{"preferred_username preferred", &Claims{PreferredUsername: "alice", Email: "a@x.io"}, "alice", false},
		{"email fallback when no preferred_username", &Claims{Email: "a@x.io"}, "a@x.io", false},
		{"neither claim present is rejected", &Claims{}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := usernameFromClaims(tc.claims)
			if (err != nil) != tc.wantErr {
				t.Fatalf("usernameFromClaims error = %v, wantErr=%v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, ErrNoUsername) {
				t.Errorf("error %v does not wrap ErrNoUsername", err)
			}
			if got != tc.want {
				t.Errorf("usernameFromClaims = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolveUser_rejects_token_without_username_or_email(t *testing.T) {
	t.Parallel()
	claims := &Claims{Subject: "sub-123", Issuer: "https://idp.example.com"}
	user, isNew, err := ResolveUser(claims, nil)
	if !errors.Is(err, ErrNoUsername) {
		t.Fatalf("ResolveUser error = %v, want ErrNoUsername", err)
	}
	if user != nil || isNew {
		t.Errorf("ResolveUser = (%+v, isNew=%v), want (nil, false) on rejected provisioning", user, isNew)
	}
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
		expected := CodeChallenge(base64.RawURLEncoding.EncodeToString(h[:]))
		if challenge != expected {
			t.Fatalf("challenge mismatch")
		}
	})
}

func TestProperty_StateGeneration(t *testing.T) {
	t.Parallel()
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(2, 20).Draw(t, "n")
		states := make(map[State]struct{}, n)
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
			_, err := NewProvider(t.Context(), tt.cfg)
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want containing %q", err, tt.wantErr)
			}
		})
	}
}

// AuthorizationURL must carry the CSRF state, the OIDC nonce, and the PKCE
// S256 challenge and method so the provider can enforce them. The Provider is
// built directly from a static oauth2 config to avoid live provider discovery.
func TestAuthorizationURL_includes_pkce_and_state(t *testing.T) {
	t.Parallel()

	p := &Provider{
		oauth2: oauth2.Config{
			ClientID:    "test-client",
			RedirectURL: "https://app.example.com/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.example.com/authorize"},
			Scopes:      []string{"openid", "profile", "email"},
		},
	}

	raw, err := p.AuthorizationURL("state-xyz", "nonce-abc", "challenge-123")
	if err != nil {
		t.Fatalf("AuthorizationURL error: %v", err)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("AuthorizationURL produced an unparseable URL %q: %v", raw, err)
	}
	q := u.Query()

	if got := q.Get("state"); got != "state-xyz" {
		t.Errorf("state = %q, want %q", got, "state-xyz")
	}
	if got := q.Get("nonce"); got != "nonce-abc" {
		t.Errorf("nonce = %q, want %q", got, "nonce-abc")
	}
	if got := q.Get("code_challenge"); got != "challenge-123" {
		t.Errorf("code_challenge = %q, want %q", got, "challenge-123")
	}
	if got := q.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256 (PKCE)", got)
	}
}

// AuthorizationURL fails closed on an empty state or code challenge, mirroring
// Exchange's empty-nonce posture: an empty state would emit an authorization
// request with no CSRF binding, an empty challenge one with no PKCE
// protection, and both would otherwise be silent.
func TestAuthorizationURL_rejects_empty_state_and_challenge(t *testing.T) {
	t.Parallel()

	p := &Provider{
		oauth2: oauth2.Config{
			ClientID:    "test-client",
			RedirectURL: "https://app.example.com/callback",
			Endpoint:    oauth2.Endpoint{AuthURL: "https://idp.example.com/authorize"},
		},
	}

	cases := []struct {
		name          string
		state         State
		codeChallenge CodeChallenge
		wantInErr     string
	}{
		{"empty state", "", "challenge-123", "empty state"},
		{"empty code challenge", "state-xyz", "", "empty code challenge"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			raw, err := p.AuthorizationURL(tc.state, "nonce-abc", tc.codeChallenge)
			if err == nil {
				t.Fatalf("AuthorizationURL(%q, _, %q) = %q, nil; want error (fail closed)", tc.state, tc.codeChallenge, raw)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Errorf("error = %q, want containing %q", err, tc.wantInErr)
			}
		})
	}
}

// TestCheckAuthorizedParty exercises the extracted OIDC Core 3.1.3.7 step-3
// azp check directly: a multi-audience ID token must carry azp == client_id,
// while single/zero-audience tokens skip the check.
func TestCheckAuthorizedParty(t *testing.T) {
	t.Parallel()
	const clientID = "client-123"
	cases := []struct {
		name      string
		audiences []string
		azp       string
		wantErr   bool
	}{
		{"single audience ignores azp", []string{clientID}, "", false},
		{"single audience with foreign azp still ok", []string{clientID}, "someone-else", false},
		{"no audience", nil, "", false},
		{"multi audience matching azp", []string{clientID, "other"}, clientID, false},
		{"multi audience mismatched azp", []string{clientID, "other"}, "other", true},
		{"multi audience empty azp", []string{clientID, "other"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkAuthorizedParty(tc.audiences, tc.azp, clientID)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkAuthorizedParty(%v, %q, %q) error = %v, wantErr=%v", tc.audiences, tc.azp, clientID, err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrTokenInvalid) {
				t.Errorf("checkAuthorizedParty error %v does not wrap ErrTokenInvalid", err)
			}
		})
	}
}

func TestCheckNonce(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		expected string
		got      string
		wantErr  bool
	}{
		{"match", "abc123", "abc123", false},
		{"mismatch", "abc123", "xyz789", true},
		{"empty expected rejected (fail closed)", "", "", true},
		{"empty expected, token carries a nonce", "", "abc123", true},
		{"expected set, token nonce empty", "abc123", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := checkNonce(tc.expected, tc.got)
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkNonce(%q, %q) error = %v, wantErr=%v", tc.expected, tc.got, err, tc.wantErr)
			}
			if err != nil && !errors.Is(err, ErrNonceMismatch) {
				t.Errorf("checkNonce error %v does not wrap ErrNonceMismatch", err)
			}
		})
	}
}

// TestZeroProviderExchangeFailsBeforeTheNilVerifier pins the zero-value
// contract stated on [Provider]: a zero Provider has no discovered endpoints
// and no verifier, and Exchange must report the unreachable token endpoint as
// ErrExchange rather than nil-dereferencing the verifier. The doc comment
// claimed a panic here until this test was written; that claim was wrong
// because the token request runs first.
func TestZeroProviderExchangeFailsBeforeTheNilVerifier(t *testing.T) {
	t.Parallel()

	var p Provider
	if p.verifier != nil {
		t.Fatalf("zero Provider verifier = %v, want nil (the premise of this test)", p.verifier)
	}

	claims, expiry, err := p.Exchange(t.Context(), "code-abc", "verifier-xyz", "nonce-123")
	if err == nil {
		t.Fatalf("zero Provider Exchange = %+v, %v, nil; want ErrExchange", claims, expiry)
	}
	if !errors.Is(err, ErrExchange) {
		t.Errorf("zero Provider Exchange err = %v, want errors.Is(err, ErrExchange): the empty token endpoint is what fails, not the verifier", err)
	}
	if claims != nil || expiry != nil {
		t.Errorf("zero Provider Exchange = %+v, %v; want nil, nil alongside the error", claims, expiry)
	}
}
