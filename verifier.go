package auth

import (
	"context"
	"net/http"
)

// CredentialVerifier resolves an HTTP request to an authenticated user
// using a specific credential type (session, API key, passkey).
// Implementations return (nil, "", nil) to indicate "not my credential type"
// and allow the next verifier in the chain to attempt authentication.
type CredentialVerifier interface {
	Verify(ctx context.Context, r *http.Request) (*User, string, error)
}
