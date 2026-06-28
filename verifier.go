package auth

import (
	"context"
	"net/http"
)

// CredentialVerifier resolves an HTTP request to an authenticated user
// using a specific credential type (session, API key, passkey).
// Implementations return (nil, "", nil) to indicate "not my credential type"
// and allow the next verifier in the chain to attempt authentication.
//
// Chain semantics (see Authenticator.Authenticate): the chain stops at the first
// verifier that returns a non-nil *User (granted) OR a non-nil error. A non-nil
// error ABORTS the whole chain - verifiers ordered after it never run - and is
// surfaced to the caller as a failed authentication. A verifier that wants the
// chain to continue to the next credential type MUST return (nil, "", nil), never
// an error, for a credential it cannot positively authenticate. The built-in
// verifiers differ deliberately: SessionVerifier treats every session problem as
// (nil, "", nil) and falls through, whereas APIKeyVerifier returns
// ErrUnauthenticated for a present-but-invalid key. In the default NewAuthenticator
// chain APIKeyVerifier runs last, so this is unobservable; but a custom
// WithVerifiers chain that places an error-returning verifier before others will
// reject a request (HTTP 401) whose earlier-type credential is present-but-invalid
// even when a later verifier holds a valid credential. This fails closed (denial,
// never a bypass); to avoid masking a later valid credential, order error-returning
// verifiers last or have them return (nil, "", nil) on "not my credential".
type CredentialVerifier interface {
	Verify(ctx context.Context, r *http.Request) (*User, string, error)
}
