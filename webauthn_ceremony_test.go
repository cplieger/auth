package auth

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestNewWebAuthn_valid_config(t *testing.T) {
	wa, err := NewWebAuthn("example.com", "Example", []string{"https://example.com"})
	if err != nil {
		t.Fatalf("NewWebAuthn error: %v", err)
	}
	if wa == nil {
		t.Fatal("NewWebAuthn returned nil")
	}
}

func TestBeginRegistration_with_user(t *testing.T) {
	wa, err := NewWebAuthn("example.com", "Example", []string{"https://example.com"})
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}

	user := &WebAuthnUser{
		User:        &User{ID: 1, Username: "test"},
		Credentials: nil,
	}

	creation, session, err := BeginRegistration(wa, user)
	if err != nil {
		t.Fatalf("BeginRegistration error: %v", err)
	}
	if creation == nil {
		t.Fatal("creation nil")
	}
	if session == nil {
		t.Fatal("session nil")
	}
}

func TestNewWebAuthn_empty_rpID(t *testing.T) {
	wa, err := NewWebAuthn("", "Example", []string{"https://example.com"})
	if err != nil {
		t.Fatalf("NewWebAuthn returned unexpected error: %v", err)
	}
	if wa == nil {
		t.Fatal("NewWebAuthn returned nil for empty rpID")
	}
}

func TestNewWebAuthn_multiple_origins(t *testing.T) {
	wa, err := NewWebAuthn("example.com", "Example", []string{
		"https://example.com",
		"https://app.example.com",
	})
	if err != nil {
		t.Fatalf("NewWebAuthn returned error: %v", err)
	}
	if wa == nil {
		t.Fatal("NewWebAuthn returned nil")
	}
}

func TestBeginRegistration_requires_user_verification(t *testing.T) {
	wa, err := NewWebAuthn("example.com", "Example", []string{"https://example.com"})
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}

	user := &WebAuthnUser{User: &User{ID: 1, Username: "test"}}
	creation, _, err := BeginRegistration(wa, user)
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}

	uv := creation.Response.AuthenticatorSelection.UserVerification
	if uv != protocol.VerificationRequired {
		t.Errorf("UserVerification = %q, want %q", uv, protocol.VerificationRequired)
	}
}

func TestBeginLogin_requires_user_verification(t *testing.T) {
	wa, err := NewWebAuthn("example.com", "Example", []string{"https://example.com"})
	if err != nil {
		t.Fatalf("NewWebAuthn: %v", err)
	}

	assertion, _, err := BeginLogin(wa)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}

	uv := assertion.Response.UserVerification
	if uv != protocol.VerificationRequired {
		t.Errorf("UserVerification = %q, want %q", uv, protocol.VerificationRequired)
	}
}
