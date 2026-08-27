package webauthn

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cplieger/auth/v5"
)

func TestNewSignals_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		user            *User
		wantIDs         []string
		wantName        string
		wantDisplayName string
	}{
		{
			name: "populated credentials",
			user: &User{
				AuthUser: &auth.User{ID: 7, Username: "alex", DisplayName: "Alex Müller"},
				Credentials: []auth.PasskeyCredential{
					{CredentialID: []byte{1, 2, 3}},
					{CredentialID: []byte{4, 5, 6}},
				},
			},
			wantIDs:         []string{"AQID", "BAUG"},
			wantName:        "alex",
			wantDisplayName: "Alex Müller",
		},
		{
			name: "empty credentials still signals the empty set",
			user: &User{
				AuthUser:    &auth.User{ID: 7, Username: "alex", DisplayName: "Alex"},
				Credentials: []auth.PasskeyCredential{},
			},
			wantIDs:         []string{},
			wantName:        "alex",
			wantDisplayName: "Alex",
		},
		{
			name: "nil credentials match empty credentials",
			user: &User{
				AuthUser:    &auth.User{ID: 7, Username: "alex", DisplayName: "Alex"},
				Credentials: nil,
			},
			wantIDs:         []string{},
			wantName:        "alex",
			wantDisplayName: "Alex",
		},
		{
			name: "absent display name falls back to the username",
			user: &User{
				AuthUser:    &auth.User{ID: 7, Username: "alex"},
				Credentials: []auth.PasskeyCredential{{CredentialID: []byte{9}}},
			},
			wantIDs:         []string{"CQ"},
			wantName:        "alex",
			wantDisplayName: "alex",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := NewSignals("example.com", tt.user)

			if got.AllAcceptedCredentials.RPID != "example.com" {
				t.Errorf("AllAcceptedCredentials.RPID = %q, want %q", got.AllAcceptedCredentials.RPID, "example.com")
			}
			if got.CurrentUserDetails.RPID != "example.com" {
				t.Errorf("CurrentUserDetails.RPID = %q, want %q", got.CurrentUserDetails.RPID, "example.com")
			}

			wantHandle := encodeBase64URL(tt.user.WebAuthnID())
			if gotHandle := encodeBase64URL(got.AllAcceptedCredentials.UserID); gotHandle != wantHandle {
				t.Errorf("AllAcceptedCredentials.UserID = %s, want %s", gotHandle, wantHandle)
			}
			if gotHandle := encodeBase64URL(got.CurrentUserDetails.UserID); gotHandle != wantHandle {
				t.Errorf("CurrentUserDetails.UserID = %s, want %s", gotHandle, wantHandle)
			}

			gotIDs := make([]string, 0, len(got.AllAcceptedCredentials.AllAcceptedCredentialIDs))
			for _, id := range got.AllAcceptedCredentials.AllAcceptedCredentialIDs {
				gotIDs = append(gotIDs, encodeBase64URL(id))
			}
			if strings.Join(gotIDs, ",") != strings.Join(tt.wantIDs, ",") {
				t.Errorf("AllAcceptedCredentialIDs = %v, want %v", gotIDs, tt.wantIDs)
			}

			if got.CurrentUserDetails.Name != tt.wantName {
				t.Errorf("CurrentUserDetails.Name = %q, want %q", got.CurrentUserDetails.Name, tt.wantName)
			}
			if got.CurrentUserDetails.DisplayName != tt.wantDisplayName {
				t.Errorf("CurrentUserDetails.DisplayName = %q, want %q", got.CurrentUserDetails.DisplayName, tt.wantDisplayName)
			}
		})
	}
}

// TestNewSignals_emptyListSerializesAsArray pins the distinction the client
// depends on. An empty allAcceptedCredentialIds instructs the credential manager
// to remove every passkey for the account; JSON null is not that instruction, and
// a nil slice would produce null.
func TestNewSignals_emptyListSerializesAsArray(t *testing.T) {
	t.Parallel()
	user := &User{AuthUser: &auth.User{ID: 7, Username: "alex"}, Credentials: nil}

	encoded, err := json.Marshal(NewSignals("example.com", user).AllAcceptedCredentials)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(encoded), `"allAcceptedCredentialIds":[]`) {
		t.Errorf("Marshal(empty signal) = %s, want it to contain \"allAcceptedCredentialIds\":[]", encoded)
	}
}

// TestNewSignals_memberNamesMatchTheSpecification pins the JSON member names,
// which the browser's own signal methods read. A rename here is not a
// compile error anywhere and produces a signal the client silently ignores.
func TestNewSignals_memberNamesMatchTheSpecification(t *testing.T) {
	t.Parallel()
	user := &User{
		AuthUser:    &auth.User{ID: 7, Username: "alex", DisplayName: "Alex"},
		Credentials: []auth.PasskeyCredential{{CredentialID: []byte{1}}},
	}
	signals := NewSignals("example.com", user)

	for _, tc := range []struct {
		what    string
		value   any
		members []string
	}{
		{
			what:    "signalAllAcceptedCredentials",
			value:   signals.AllAcceptedCredentials,
			members: []string{`"rpId"`, `"userId"`, `"allAcceptedCredentialIds"`},
		},
		{
			what:    "signalCurrentUserDetails",
			value:   signals.CurrentUserDetails,
			members: []string{`"rpId"`, `"userId"`, `"name"`, `"displayName"`},
		},
	} {
		t.Run(tc.what, func(t *testing.T) {
			t.Parallel()
			encoded, err := json.Marshal(tc.value)
			if err != nil {
				t.Fatalf("Marshal %s: %v", tc.what, err)
			}
			for _, member := range tc.members {
				if !strings.Contains(string(encoded), member+":") {
					t.Errorf("%s payload = %s, want it to carry the member %s", tc.what, encoded, member)
				}
			}
		})
	}
}

// encodeBase64URL renders a value the way the wire does, minus the JSON quotes,
// so a failure message shows what the client would receive rather than a byte
// slice.
func encodeBase64URL(b []byte) string {
	encoded, err := Base64URL(b).MarshalJSON()
	if err != nil {
		return "<unencodable>"
	}
	return strings.Trim(string(encoded), `"`)
}
