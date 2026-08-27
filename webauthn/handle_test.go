package webauthn

import (
	"bytes"
	"testing"

	"github.com/cplieger/auth/v5"
)

// TestUser_WebAuthnID_returnsTheStoredHandle: the account presents the handle
// the store holds, byte for byte. A passkey is bound to that value, so anything
// but an exact passthrough stops the credential resolving.
func TestUser_WebAuthnID_returnsTheStoredHandle(t *testing.T) {
	t.Parallel()
	stored := auth.GenerateWebAuthnHandle()
	u := &User{AuthUser: &auth.User{ID: 7, Username: "alex", WebAuthnHandle: stored}}

	got := u.WebAuthnID()

	if !bytes.Equal(got, stored) {
		t.Errorf("WebAuthnID() = %x, want the stored handle %x", got, stored)
	}
}

// TestStoreUserFinder_resolvesAGeneratedHandle walks the login path: the
// authenticator returns the stored random handle, and the finder resolves it
// through the store rather than decoding it.
func TestStoreUserFinder_resolvesAGeneratedHandle(t *testing.T) {
	t.Parallel()
	handle := auth.GenerateWebAuthnHandle()
	stored := &auth.User{ID: 7, Username: "alex", Enabled: true, WebAuthnHandle: handle}
	store := &fakeStore{
		users: map[int64]*auth.User{7: stored},
		creds: map[int64][]auth.PasskeyCredential{7: {{CredentialID: []byte{1}, UserID: 7}}},
	}

	got, err := storeUserFinder(t.Context(), store)(nil, handle)
	if err != nil {
		t.Fatalf("finder(generated handle) error = %v, want nil", err)
	}
	u, ok := got.(*userAdapter)
	if !ok {
		t.Fatalf("finder returned %#v, want a *userAdapter", got)
	}
	if u.AuthUser != stored {
		t.Errorf("finder resolved %v, want the stored account %v", u.AuthUser, stored)
	}
}
