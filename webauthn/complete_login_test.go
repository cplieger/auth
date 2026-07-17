package webauthn

import (
	"context"
	"encoding/binary"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cplieger/auth/v2"
	"github.com/cplieger/auth/v2/internal/capture"
	"github.com/go-webauthn/webauthn/webauthn"
)

// custodyRecord captures one UpdatePasskeyAfterLogin call.
type custodyRecord struct {
	credID    []byte
	signCount uint32
	flags     auth.PasskeyFlags
}

// fakeStore is an in-memory Store double for the CompleteLogin path.
type fakeStore struct {
	users     map[int64]*auth.User
	creds     map[int64][]auth.PasskeyCredential
	userErr   error
	credsErr  error
	updateErr error
	updated   *custodyRecord
}

func (f *fakeStore) GetUserByID(_ context.Context, id int64) (*auth.User, error) {
	if f.userErr != nil {
		return nil, f.userErr
	}
	return f.users[id], nil
}

func (f *fakeStore) GetPasskeysByUserID(_ context.Context, userID int64) ([]auth.PasskeyCredential, error) {
	if f.credsErr != nil {
		return nil, f.credsErr
	}
	return f.creds[userID], nil
}

func (f *fakeStore) UpdatePasskeyAfterLogin(_ context.Context, credID []byte, signCount uint32, flags auth.PasskeyFlags) error {
	f.updated = &custodyRecord{credID: credID, signCount: signCount, flags: flags}
	return f.updateErr
}

// Compile-time assertion: the double satisfies the consumed interface.
var _ Store = (*fakeStore)(nil)

// userHandle encodes a user ID the way User.WebAuthnID does.
func userHandle(id int64) []byte {
	buf := make([]byte, binary.MaxVarintLen64)
	n := binary.PutVarint(buf, id)
	return buf[:n]
}

func TestStoreUserFinder_table(t *testing.T) {
	t.Parallel()

	okUser := &auth.User{ID: 7, Username: "alice", Enabled: true}
	tests := []struct {
		store   *fakeStore
		name    string
		wantErr string
		handle  []byte
	}{
		{
			name:    "empty handle",
			handle:  nil,
			store:   &fakeStore{},
			wantErr: "invalid user handle",
		},
		{
			name:    "zero handle",
			handle:  userHandle(0),
			store:   &fakeStore{},
			wantErr: "invalid user handle",
		},
		{
			name:    "negative handle",
			handle:  userHandle(-3),
			store:   &fakeStore{},
			wantErr: "invalid user handle",
		},
		{
			name:    "user lookup error",
			handle:  userHandle(7),
			store:   &fakeStore{userErr: errors.New("disk on fire")},
			wantErr: "user not found",
		},
		{
			name:    "unknown user",
			handle:  userHandle(7),
			store:   &fakeStore{},
			wantErr: "user not found",
		},
		{
			name:    "passkey lookup error",
			handle:  userHandle(7),
			store:   &fakeStore{users: map[int64]*auth.User{7: okUser}, credsErr: errors.New("bucket gone")},
			wantErr: "get passkeys failed",
		},
		{
			name:   "success",
			handle: userHandle(7),
			store: &fakeStore{
				users: map[int64]*auth.User{7: okUser},
				creds: map[int64][]auth.PasskeyCredential{7: {{CredentialID: []byte{1}, UserID: 7}}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			finder := storeUserFinder(context.Background(), tc.store)
			got, err := finder(nil, tc.handle)

			if tc.wantErr != "" {
				if err == nil || err.Error() != tc.wantErr {
					t.Fatalf("finder error = %v, want %q (generic, enumeration-safe)", err, tc.wantErr)
				}
				if got != nil {
					t.Fatalf("finder user = %v, want nil on error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("finder error = %v, want nil", err)
			}
			u, ok := got.(*User)
			if !ok || u.AuthUser != tc.store.users[7] {
				t.Fatalf("finder user = %#v, want *User wrapping the stored account", got)
			}
			if len(u.Credentials) != 1 {
				t.Fatalf("finder credentials = %d, want 1", len(u.Credentials))
			}
		})
	}
}

// TestStoreUserFinder_lookup_failures_stay_generic pins the anti-enumeration
// property: a store failure and a missing user produce the SAME generic
// message, and no internal error detail leaks into the ceremony error.
func TestStoreUserFinder_lookup_failures_stay_generic(t *testing.T) {
	t.Parallel()
	finder := storeUserFinder(context.Background(), &fakeStore{userErr: errors.New("pg://secret-host timeout")})
	_, errStoreFail := finder(nil, userHandle(1))
	finder = storeUserFinder(context.Background(), &fakeStore{})
	_, errMissing := finder(nil, userHandle(1))

	if errStoreFail == nil || errMissing == nil {
		t.Fatal("both lookups must fail")
	}
	if errStoreFail.Error() != errMissing.Error() {
		t.Fatalf("store-failure error %q != missing-user error %q; must be indistinguishable", errStoreFail, errMissing)
	}
	if strings.Contains(errStoreFail.Error(), "secret-host") {
		t.Fatalf("internal error detail leaked: %q", errStoreFail)
	}
}

func TestPersistLoginCustody_records_all_flags(t *testing.T) {
	t.Parallel()
	fs := &fakeStore{}
	cred := &webauthn.Credential{
		ID: []byte{9, 9, 9},
		Flags: webauthn.CredentialFlags{
			UserPresent:    true,
			UserVerified:   true,
			BackupEligible: true,
			BackupState:    false,
		},
		Authenticator: webauthn.Authenticator{SignCount: 42, CloneWarning: true},
	}

	persistLoginCustody(context.Background(), fs, cred)

	if fs.updated == nil {
		t.Fatal("custody write not issued")
	}
	if got, want := fs.updated.signCount, uint32(42); got != want {
		t.Errorf("signCount = %d, want %d", got, want)
	}
	want := auth.PasskeyFlags{UserPresent: true, UserVerified: true, BackupEligible: true, BackupState: false, CloneWarning: true}
	if fs.updated.flags != want {
		t.Errorf("flags = %+v, want %+v (CloneWarning must persist)", fs.updated.flags, want)
	}
}

// TestPersistLoginCustody_failure_warns_only pins the best-effort contract: a
// custody-write failure logs a Warn and does not panic or propagate.
func TestPersistLoginCustody_failure_warns_only(t *testing.T) {
	h := capture.Default(t)
	fs := &fakeStore{updateErr: errors.New("bucket unavailable")}

	persistLoginCustody(context.Background(), fs, &webauthn.Credential{ID: []byte{1}})

	if n := h.CountMsg("post-login credential update failed"); n != 1 {
		t.Errorf("custody failure logged %d warnings, want 1", n)
	}
}

// TestCompleteLogin_ceremony_failure_returns_wrapped_error smoke-tests the
// composition: an undecodable assertion body fails the ceremony, the error is
// wrapped with context, no user is returned, and no custody write happens.
func TestCompleteLogin_ceremony_failure_returns_wrapped_error(t *testing.T) {
	t.Parallel()
	wa, err := NewWebAuthn("example.com", "Example", []string{"https://example.com"})
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeStore{}
	sess := &webauthn.SessionData{Challenge: "test-challenge"}
	r := httptest.NewRequest(http.MethodPost, "/finish", strings.NewReader("not json"))

	user, cred, cerr := CompleteLogin(context.Background(), wa, fs, sess, r)
	if cerr == nil {
		t.Fatal("CompleteLogin with garbage assertion = nil error, want failure")
	}
	if !strings.Contains(cerr.Error(), "assertion ceremony failed") {
		t.Errorf("error %q lacks ceremony context", cerr)
	}
	if user != nil || cred != nil {
		t.Errorf("CompleteLogin returned (%v, %v) on failure, want nils", user, cred)
	}
	if fs.updated != nil {
		t.Error("custody write issued despite ceremony failure")
	}
}
