package auth

import (
	"context"
	"net/http"
)

// CredentialVerifier resolves an HTTP request to an authenticated user
// using a specific credential type (session, API key, passkey).
type CredentialVerifier interface {
	Verify(ctx context.Context, r *http.Request) (*User, string, error)
}
