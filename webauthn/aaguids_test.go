package webauthn

import (
	"bytes"
	"encoding/json"
	"os"
	"slices"
	"testing"

	"github.com/cplieger/auth/v6/internal/aaguidgen"
)

func readSnapshot(t *testing.T) ([]byte, map[string]string) {
	t.Helper()
	data, err := os.ReadFile("testdata/aaguid.json")
	if err != nil {
		t.Fatalf("Setup: read snapshot: %v", err)
	}
	var doc map[string]struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("Setup: decode snapshot: %v", err)
	}
	names := make(map[string]string, len(doc))
	for k, v := range doc {
		names[k] = v.Name
	}
	return data, names
}

func TestKnownAAGUIDTable_in_sync(t *testing.T) {
	t.Parallel()
	snapshot, _ := readSnapshot(t)
	out, err := aaguidgen.Generate(snapshot, aaguidListCommit)
	if err != nil {
		t.Fatalf("aaguidgen.Generate(testdata/aaguid.json, %s): %v", aaguidListCommit, err)
	}
	src, err := os.ReadFile("aaguids_gen.go")
	if err != nil {
		t.Fatalf("Setup: read aaguids_gen.go: %v", err)
	}
	if !bytes.Equal(src, out.Source) {
		t.Errorf(`aaguids_gen.go differs from aaguidgen.Generate(testdata/aaguid.json, %s); run "go generate ./webauthn"`, aaguidListCommit)
	}
	if !bytes.Equal(snapshot, out.Snapshot) {
		t.Errorf(`testdata/aaguid.json is not in generator form; run "go generate ./webauthn"`)
	}
}

func TestAAGUIDListCommit_is_readable_by_the_generator(t *testing.T) {
	t.Parallel()
	got, err := aaguidgen.ReadCommit("aaguids_source.go")
	if got != aaguidListCommit || err != nil {
		t.Errorf("aaguidgen.ReadCommit(aaguids_source.go) = %q, %v, want %q, nil", got, err, aaguidListCommit)
	}
}

func TestAuthenticatorName(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		aaguid   []byte
		want     string
		wantOkay bool
	}{
		{name: "kept_extra", aaguid: parseAAGUID("2fc0579f-8113-47ea-b116-bb5a8db9202a"), want: "YubiKey 5", wantOkay: true},
		{name: "listed", aaguid: parseAAGUID("adce0002-35bc-c60a-648b-0b25f1f05503"), want: "Chrome on Mac", wantOkay: true},
		{name: "unknown", aaguid: parseAAGUID("ffffffff-ffff-ffff-ffff-ffffffffffff")},
		{name: "short", aaguid: make([]byte, 15)},
		{name: "nil"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := AuthenticatorName(tc.aaguid)
			if got != tc.want || ok != tc.wantOkay {
				t.Errorf("AuthenticatorName(%x) = %q, %v, want %q, %v", tc.aaguid, got, ok, tc.want, tc.wantOkay)
			}
		})
	}
}

func TestAuthenticatorName_knows_every_listed_provider(t *testing.T) {
	t.Parallel()
	_, names := readSnapshot(t)
	for key, want := range names {
		if got, ok := AuthenticatorName(parseAAGUID(key)); got != want || !ok {
			t.Errorf("AuthenticatorName(%s) = %q, %v, want %q, true", key, got, ok, want)
		}
	}
}

func TestPasskeyFriendlyName_numbers_a_listed_provider(t *testing.T) {
	t.Parallel()
	const provider = "dd4ec289-e01d-41c9-bb89-70fa845d4bf2"
	_, names := readSnapshot(t)
	name, listed := names[provider]
	if !listed {
		t.Fatalf("Setup: %s is not in testdata/aaguid.json", provider)
	}
	aaguid := parseAAGUID(provider)
	tests := []struct {
		name     string
		aaguid   []byte
		existing []string
		want     string
	}{
		{name: "first", aaguid: aaguid, want: name},
		{name: "second", aaguid: aaguid, existing: []string{name}, want: name + " 2"},
		{name: "after_gap", aaguid: aaguid, existing: []string{name + " 3"}, want: name + " 4"},
		{name: "unknown_first", aaguid: parseAAGUID("ffffffff-ffff-ffff-ffff-ffffffffffff"), existing: []string{name}, want: "Passkey 1"},
		{name: "unknown_second", aaguid: nil, existing: []string{"Passkey 1"}, want: "Passkey 2"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := PasskeyFriendlyName(tc.aaguid, tc.existing); got != tc.want {
				t.Errorf("PasskeyFriendlyName(%x, %q) = %q, want %q", tc.aaguid, tc.existing, got, tc.want)
			}
		})
	}
}

func TestKnownAAGUIDs_mutation_has_no_effect(t *testing.T) {
	if len(KnownAAGUIDs) != len(knownAAGUIDTable) || !slices.Equal(KnownAAGUIDs, knownAAGUIDTable) {
		t.Fatalf("KnownAAGUIDs has %d entries and differs from the generated table of %d", len(KnownAAGUIDs), len(knownAAGUIDTable))
	}
	saved := KnownAAGUIDs[0]
	t.Cleanup(func() { KnownAAGUIDs[0] = saved })
	KnownAAGUIDs[0].Name = "changed"

	if got, ok := AuthenticatorName(parseAAGUID(saved.UUID)); got != saved.Name || !ok {
		t.Errorf("after changing KnownAAGUIDs[0], AuthenticatorName(%s) = %q, %v, want %q, true", saved.UUID, got, ok, saved.Name)
	}
}
