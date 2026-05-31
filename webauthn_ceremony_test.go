package auth

import "testing"

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
