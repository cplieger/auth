package webauthn

import (
	"testing"
	"time"
)

// TestRelyingParty_ID pins the accessor a consumer reads to compare a stored
// credential's RPID against the relying party it is running. A wrong value here
// would make a relying-party rename undetectable, which is the one case that
// orphans every registered passkey at once.
func TestRelyingParty_ID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		id   string
	}{
		{name: "domain", id: "example.com"},
		{name: "subdomain", id: "auth.example.com"},
		{name: "localhost", id: "localhost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rp, err := New(RPConfig{ID: tt.id, DisplayName: "Example", Origins: []string{"https://" + tt.id}})
			if err != nil {
				t.Fatalf("New(RPConfig{ID: %q}): %v", tt.id, err)
			}
			if got := rp.ID(); got != tt.id {
				t.Errorf("RelyingParty.ID() = %q, want %q", got, tt.id)
			}
		})
	}
}

// TestCeremony_Expires_matchesTheConfiguredTimeout asserts the deadline a
// ceremony carries is the one this package configures, because a consumer's
// ceremony store evicts on it. A store that trusted its own clock instead could
// hold a ceremony the authenticator has already abandoned, or drop one still in
// flight.
func TestCeremony_Expires_matchesTheConfiguredTimeout(t *testing.T) {
	t.Parallel()
	rp, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://example.com"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	before := time.Now()
	_, ceremony, err := BeginLogin(rp)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	got := ceremony.Expires()
	lo, hi := before.Add(CeremonyTimeout), time.Now().Add(CeremonyTimeout)
	if got.Before(lo) || got.After(hi) {
		t.Errorf("Ceremony.Expires() = %v, want within [%v, %v] (CeremonyTimeout %v)", got, lo, hi, CeremonyTimeout)
	}
}

// TestCeremony_zeroValueHasNoDeadline records why a ceremony lookup reports
// absence with a separate boolean: a Ceremony is a value, so there is no nil to
// distinguish "not found" from a real ceremony, and the zero value is not one.
func TestCeremony_zeroValueHasNoDeadline(t *testing.T) {
	t.Parallel()
	var zero Ceremony
	if !zero.Expires().IsZero() {
		t.Errorf("zero Ceremony.Expires() = %v, want the zero time", zero.Expires())
	}
}
