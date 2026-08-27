package webauthn

import (
	"bytes"
	"testing"

	"github.com/cplieger/auth/v5"
)

// TestUser_WebAuthnID_prefersTheStoredHandle is the read side of the migration.
// An account that has been given a handle must present that handle, or the
// credential registered against it stops resolving.
func TestUser_WebAuthnID_prefersTheStoredHandle(t *testing.T) {
	t.Parallel()
	stored := auth.GenerateWebAuthnHandle()
	u := &User{AuthUser: &auth.User{ID: 7, Username: "alex", WebAuthnHandle: stored}}

	got := u.WebAuthnID()

	if !bytes.Equal(got, stored) {
		t.Errorf("WebAuthnID() = %x, want the stored handle %x", got, stored)
	}
	if bytes.Equal(got, auth.LegacyWebAuthnHandle(7)) {
		t.Errorf("WebAuthnID() = %x, which is the derived handle; want the stored one", got)
	}
}

// TestUser_WebAuthnID_fallsBackToTheDerivedHandle is the case that keeps existing
// passkeys working before, or during, a partial backfill. The fallback must
// produce exactly what the backfill writes, so the two can never disagree about
// which account a credential belongs to.
func TestUser_WebAuthnID_fallsBackToTheDerivedHandle(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		handle []byte
	}{
		{name: "handle never set", handle: nil},
		{name: "handle set to an empty slice", handle: []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			u := &User{AuthUser: &auth.User{ID: 7, Username: "alex", WebAuthnHandle: tt.handle}}

			got := u.WebAuthnID()

			if len(got) == 0 {
				t.Fatal("WebAuthnID() is empty; a user handle must never be empty")
			}
			if want := auth.LegacyWebAuthnHandle(7); !bytes.Equal(got, want) {
				t.Errorf("WebAuthnID() = %x, want the derived handle %x so a backfill cannot disagree with it", got, want)
			}
		})
	}
}

// TestStoreUserFinder_resolvesAGeneratedHandle walks the login path a migrated
// account takes: the authenticator returns the stored random handle, and the
// finder has to resolve it through the store rather than decoding it.
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
