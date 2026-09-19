package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cplieger/auth/v6"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
)

// TestParseOrigin_accepts pins the two normalizations the parser performs,
// ASCII case folding and default-port elision, and that everything else is
// carried verbatim: the parsed value is compared against the browser's own
// serialization at Finish, so a normalization the comparator does not share
// would turn a clean refusal into a post-prompt mismatch.
func TestParseOrigin_accepts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		raw      string
		wantStr  string
		wantHost string
	}{
		{name: "https_default_port_implicit", raw: "https://example.com", wantStr: "https://example.com", wantHost: "example.com"},
		{name: "https_default_port_explicit_elided", raw: "https://example.com:443", wantStr: "https://example.com", wantHost: "example.com"},
		{name: "https_custom_port_kept", raw: "https://example.com:8443", wantStr: "https://example.com:8443", wantHost: "example.com"},
		{name: "http_localhost_custom_port_kept", raw: "http://localhost:8374", wantStr: "http://localhost:8374", wantHost: "localhost"},
		{name: "http_default_port_elided", raw: "http://localhost:80", wantStr: "http://localhost", wantHost: "localhost"},
		{name: "scheme_and_host_lowercased", raw: "HTTPS://EXAMPLE.COM", wantStr: "https://example.com", wantHost: "example.com"},
		{name: "root_path_normalized_away", raw: "https://example.com/", wantStr: "https://example.com", wantHost: "example.com"},
		{name: "ipv6_rebracketed", raw: "https://[::1]:8443", wantStr: "https://[::1]:8443", wantHost: "::1"},
		{name: "ipv6_uncanonical_form_kept_verbatim", raw: "https://[0:0:0:0:0:0:0:1]", wantStr: "https://[0:0:0:0:0:0:0:1]", wantHost: "0:0:0:0:0:0:0:1"},
		{name: "ipv4_kept_verbatim", raw: "https://127.0.0.001", wantStr: "https://127.0.0.001", wantHost: "127.0.0.001"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseOrigin(tt.raw)
			if err != nil {
				t.Fatalf("ParseOrigin(%q) error = %v, want nil", tt.raw, err)
			}
			if got.String() != tt.wantStr {
				t.Errorf("ParseOrigin(%q).String() = %q, want %q", tt.raw, got.String(), tt.wantStr)
			}
			if got.Host() != tt.wantHost {
				t.Errorf("ParseOrigin(%q).Host() = %q, want %q", tt.raw, got.Host(), tt.wantHost)
			}
			if got.IsZero() {
				t.Errorf("ParseOrigin(%q).IsZero() = true, want false", tt.raw)
			}
		})
	}
}

// TestParseOrigin_refuses pins every parse-stage reason. The trailing-dot row
// is the anchor against repairing the value: measured on go-webauthn v0.18.1,
// IsOriginInHaystack("https://sub.example.com.", ["https://sub.example.com"])
// is false, so a stripped dot would bind an origin the browser's re-presented
// value never matches.
func TestParseOrigin_refuses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want OriginRejection
	}{
		{name: "empty", raw: "", want: RejectMalformed},
		{name: "no_scheme", raw: "example.com", want: RejectMalformed},
		{name: "ftp_scheme", raw: "ftp://example.com", want: RejectMalformed},
		{name: "no_host", raw: "https://", want: RejectMalformed},
		{name: "path", raw: "https://example.com/path", want: RejectMalformed},
		{name: "query", raw: "https://example.com?q=1", want: RejectMalformed},
		{name: "fragment", raw: "https://example.com#f", want: RejectMalformed},
		{name: "userinfo", raw: "https://u:p@example.com", want: RejectMalformed},
		{name: "non_numeric_port", raw: "https://example.com:abc", want: RejectMalformed},
		{name: "port_out_of_range", raw: "https://example.com:99999", want: RejectMalformed},
		{name: "port_zero", raw: "https://example.com:0", want: RejectMalformed},
		{name: "port_leading_zero", raw: "https://example.com:0443", want: RejectMalformed},
		{name: "empty_port_after_colon", raw: "https://example.com:", want: RejectMalformed},
		{name: "opaque_origin_null", raw: "null", want: RejectMalformed},
		{name: "trailing_dot", raw: "https://sub.example.com.", want: RejectTrailingDot},
		{name: "empty_label", raw: "https://sub..example.com", want: RejectEmptyLabel},
		{name: "leading_dot", raw: "https://.example.com", want: RejectEmptyLabel},
		{name: "non_ascii_host", raw: "https://ex\u00e4mple.com", want: RejectNonASCII},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseOrigin(tt.raw)
			oe, ok := errors.AsType[*OriginError](err)
			if !ok {
				t.Fatalf("ParseOrigin(%q) = %v, %v; want a *OriginError", tt.raw, got, err)
			}
			if oe.Reason != tt.want {
				t.Errorf("ParseOrigin(%q) reason = %q, want %q", tt.raw, oe.Reason, tt.want)
			}
			if oe.Origin != tt.raw {
				t.Errorf("ParseOrigin(%q) error names %q, want the value as given", tt.raw, oe.Origin)
			}
			if oe.RPID != "" {
				t.Errorf("ParseOrigin(%q) error names relying party %q, want none at the parse stage", tt.raw, oe.RPID)
			}
			if !got.IsZero() {
				t.Errorf("ParseOrigin(%q) = %v on refusal, want the zero Origin", tt.raw, got)
			}
		})
	}
}

// TestCheckOrigin_accepts pins the policy's accepted set with the list unset:
// https at or under the relying-party ID on any port, and http for localhost
// only. The sibling-subdomain row is the unset-list arm of the two-arm design.
func TestCheckOrigin_accepts(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		rpID   string
		origin string
	}{
		{name: "rp_id_itself", rpID: "example.com", origin: "https://example.com"},
		{name: "subdomain", rpID: "example.com", origin: "https://sub.example.com"},
		{name: "deeper_subdomain", rpID: "example.com", origin: "https://a.b.example.com"},
		{name: "subdomain_custom_port", rpID: "example.com", origin: "https://sub.example.com:8443"},
		{name: "sibling_subdomain_with_list_unset", rpID: "example.com", origin: "https://evil.example.com"},
		{name: "localhost_http_custom_port", rpID: "localhost", origin: "http://localhost:8374"},
		{name: "localhost_https", rpID: "localhost", origin: "https://localhost"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rp := mustNew(t, RPConfig{ID: tt.rpID, DisplayName: "Example"})
			if err := rp.CheckOrigin(mustParseOrigin(t, tt.origin)); err != nil {
				t.Errorf("CheckOrigin(%q) for RP %q = %v, want nil", tt.origin, tt.rpID, err)
			}
		})
	}
}

// TestCheckOrigin_refuses pins each policy-stage reason and the rule order:
// the IP rule fires before the scheme rule, so an address that can never carry
// a passkey is reported as that rather than as "add TLS".
func TestCheckOrigin_refuses(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		rpID   string
		origin string
		want   OriginRejection
	}{
		{name: "dot_guard_evilexample", rpID: "example.com", origin: "https://evilexample.com", want: RejectHostNotCovered},
		{name: "rp_id_as_prefix", rpID: "example.com", origin: "https://example.com.evil.test", want: RejectHostNotCovered},
		{name: "unrelated_host", rpID: "example.com", origin: "https://notexample.com", want: RejectHostNotCovered},
		{name: "http_subdomain", rpID: "example.com", origin: "http://sub.example.com", want: RejectInsecureScheme},
		{name: "http_sub_localhost", rpID: "localhost", origin: "http://sub.localhost", want: RejectInsecureScheme},
		{name: "http_localhost_wrong_rp", rpID: "example.com", origin: "http://localhost", want: RejectHostNotCovered},
		{name: "http_wrong_host_for_localhost_rp", rpID: "localhost", origin: "http://example.com", want: RejectInsecureScheme},
		{name: "ipv4_https", rpID: "example.com", origin: "https://10.0.0.5", want: RejectIPHost},
		{name: "ipv4_http_reports_ip_before_scheme", rpID: "example.com", origin: "http://10.0.0.5:8374", want: RejectIPHost},
		{name: "ipv6", rpID: "example.com", origin: "https://[::1]", want: RejectIPHost},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rp := mustNew(t, RPConfig{ID: tt.rpID, DisplayName: "Example"})
			o := mustParseOrigin(t, tt.origin)
			err := rp.CheckOrigin(o)
			oe, ok := errors.AsType[*OriginError](err)
			if !ok {
				t.Fatalf("CheckOrigin(%q) for RP %q = %v, want a *OriginError", tt.origin, tt.rpID, err)
			}
			if oe.Reason != tt.want {
				t.Errorf("CheckOrigin(%q) for RP %q reason = %q, want %q", tt.origin, tt.rpID, oe.Reason, tt.want)
			}
			if oe.RPID != tt.rpID || oe.Origin != o.String() {
				t.Errorf("CheckOrigin(%q) error names origin %q for RP %q, want %q for %q", tt.origin, oe.Origin, oe.RPID, o.String(), tt.rpID)
			}
		})
	}
}

// TestCheckOrigin_zeroOriginRefused pins the fail-closed answer for an origin
// that was never parsed.
func TestCheckOrigin_zeroOriginRefused(t *testing.T) {
	t.Parallel()
	rp := mustNew(t, RPConfig{ID: "example.com", DisplayName: "Example"})
	err := rp.CheckOrigin(Origin{})
	oe, ok := errors.AsType[*OriginError](err)
	if !ok || oe.Reason != RejectNoOrigin {
		t.Errorf("CheckOrigin(Origin{}) = %v, want reason %q", err, RejectNoOrigin)
	}
}

// TestCheckOrigin_dotGuardIsLoadBearing is the dedicated anchor for the
// separator in the suffix test (GHSA-22w3-693w-x895): a host that merely ENDS
// WITH the relying-party ID is not under it.
func TestCheckOrigin_dotGuardIsLoadBearing(t *testing.T) {
	t.Parallel()
	rp := mustNew(t, RPConfig{ID: "example.com", DisplayName: "Example"})
	if err := rp.CheckOrigin(mustParseOrigin(t, "https://sub.example.com")); err != nil {
		t.Errorf("CheckOrigin(https://sub.example.com) = %v, want nil", err)
	}
	err := rp.CheckOrigin(mustParseOrigin(t, "https://evilexample.com"))
	oe, ok := errors.AsType[*OriginError](err)
	if !ok || oe.Reason != RejectHostNotCovered {
		t.Errorf("CheckOrigin(https://evilexample.com) = %v, want reason %q", err, RejectHostNotCovered)
	}
}

// TestCheckOrigin_allowlist pins the set-list arm: the policy first, then an
// exact scheme+host+port match against the parsed list, so a sibling subdomain
// the policy alone admits is refused, and no dimension of the comparison is
// collapsed (CVE-2026-30964 collapsed origins to their host).
func TestCheckOrigin_allowlist(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		origins []string
		origin  string
		want    OriginRejection // "" means accepted
	}{
		{name: "sibling_subdomain_refused", origins: []string{"https://subflux.example.com"}, origin: "https://evil.example.com", want: RejectNotAllowlisted},
		{name: "listed_origin_accepted", origins: []string{"https://subflux.example.com"}, origin: "https://subflux.example.com"},
		{name: "port_differs_refused", origins: []string{"https://subflux.example.com"}, origin: "https://subflux.example.com:8443", want: RejectNotAllowlisted},
		{name: "policy_fires_before_list", origins: []string{"https://subflux.example.com"}, origin: "http://subflux.example.com", want: RejectInsecureScheme},
		{name: "canonical_equality_accepted", origins: []string{"https://subflux.example.com"}, origin: "https://Subflux.Example.com:443"},
		{name: "two_entries_first_accepted", origins: []string{"https://a.example.com", "https://b.example.com"}, origin: "https://a.example.com"},
		{name: "two_entries_second_accepted", origins: []string{"https://a.example.com", "https://b.example.com"}, origin: "https://b.example.com"},
		{name: "two_entries_third_refused", origins: []string{"https://a.example.com", "https://b.example.com"}, origin: "https://c.example.com", want: RejectNotAllowlisted},
		{name: "listed_with_default_port_matches_implicit", origins: []string{"https://subflux.example.com:443"}, origin: "https://subflux.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rp := mustNew(t, RPConfig{ID: "example.com", DisplayName: "Example", Origins: tt.origins})
			err := rp.CheckOrigin(mustParseOrigin(t, tt.origin))
			if tt.want == "" {
				if err != nil {
					t.Errorf("CheckOrigin(%q) with Origins %q = %v, want nil", tt.origin, tt.origins, err)
				}
				return
			}
			oe, ok := errors.AsType[*OriginError](err)
			if !ok {
				t.Fatalf("CheckOrigin(%q) with Origins %q = %v, want a *OriginError", tt.origin, tt.origins, err)
			}
			if oe.Reason != tt.want {
				t.Errorf("CheckOrigin(%q) with Origins %q reason = %q, want %q", tt.origin, tt.origins, oe.Reason, tt.want)
			}
		})
	}
}

// TestNew_originsCannotWiden pins the construction-time refusal: a listed
// origin the policy would itself reject, or one that is not an origin at all,
// makes New fail with a typed error naming the entry, its index and the reason.
func TestNew_originsCannotWiden(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		origins   []string
		wantIndex int
		wantEntry string
		want      OriginRejection
	}{
		{name: "http_subdomain", origins: []string{"http://subflux.example.com"}, wantIndex: 0, wantEntry: "http://subflux.example.com", want: RejectInsecureScheme},
		{name: "second_entry_not_covered", origins: []string{"https://subflux.example.com", "https://evilexample.com"}, wantIndex: 1, wantEntry: "https://evilexample.com", want: RejectHostNotCovered},
		{name: "ip_host", origins: []string{"https://10.0.0.5"}, wantIndex: 0, wantEntry: "https://10.0.0.5", want: RejectIPHost},
		{name: "bare_host_no_scheme", origins: []string{"subflux.example.com"}, wantIndex: 0, wantEntry: "subflux.example.com", want: RejectMalformed},
		{name: "empty_string_is_not_unset", origins: []string{""}, wantIndex: 0, wantEntry: "", want: RejectMalformed},
		{name: "trailing_dot", origins: []string{"https://subflux.example.com."}, wantIndex: 0, wantEntry: "https://subflux.example.com.", want: RejectTrailingDot},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rp, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: tt.origins})
			if rp != nil {
				t.Errorf("New(Origins %q) = %v, want nil on refusal", tt.origins, rp)
			}
			le, ok := errors.AsType[*OriginsError](err)
			if !ok {
				t.Fatalf("New(Origins %q) error = %v, want a *OriginsError", tt.origins, err)
			}
			if le.Index != tt.wantIndex || le.Entry != tt.wantEntry {
				t.Errorf("New(Origins %q) refused [%d] %q, want [%d] %q", tt.origins, le.Index, le.Entry, tt.wantIndex, tt.wantEntry)
			}
			inner, ok := errors.AsType[*OriginError](err)
			if !ok {
				t.Fatalf("New(Origins %q) error = %v, want the inner *OriginError reachable through errors.As", tt.origins, err)
			}
			if inner.Reason != tt.want {
				t.Errorf("New(Origins %q) inner reason = %q, want %q", tt.origins, inner.Reason, tt.want)
			}
		})
	}
}

// TestOriginsError_messageComposesOnce pins the message shape: the prefix
// appears exactly once, so a caller adding its own context does not produce
// "auth/webauthn: ... auth/webauthn: ...".
func TestOriginsError_messageComposesOnce(t *testing.T) {
	t.Parallel()
	_, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://subflux.example.com", "https://evilexample.com"}})
	if err == nil {
		t.Fatal("New(Origins with evilexample.com) error = nil, want a refusal")
	}
	const wantPrefix = `auth/webauthn: RPConfig.Origins[1] "https://evilexample.com" cannot narrow the origin policy for relying party "example.com": `
	if !strings.HasPrefix(err.Error(), wantPrefix) {
		t.Errorf("New error = %q, want prefix %q", err, wantPrefix)
	}
	if n := strings.Count(err.Error(), "auth/webauthn:"); n != 1 {
		t.Errorf("New error = %q carries the package prefix %d times, want 1", err, n)
	}
}

// TestNew_constructsWithoutOriginList pins that a relying party needs no
// enumerated origin set: nil and empty both construct and both leave the policy
// deciding alone.
func TestNew_constructsWithoutOriginList(t *testing.T) {
	t.Parallel()
	for _, origins := range [][]string{nil, {}} {
		rp, err := New(RPConfig{ID: "example.com", DisplayName: "Example", Origins: origins})
		if err != nil {
			t.Fatalf("New(Origins %#v) error = %v, want nil", origins, err)
		}
		if err := rp.CheckOrigin(mustParseOrigin(t, "https://anything.example.com")); err != nil {
			t.Errorf("New(Origins %#v).CheckOrigin(https://anything.example.com) = %v, want nil", origins, err)
		}
	}
}

// TestNew_storesParsedOriginList pins that the list is stored in canonical
// form, so a listed entry and a presented origin compare field by field.
func TestNew_storesParsedOriginList(t *testing.T) {
	t.Parallel()
	rp := mustNew(t, RPConfig{ID: "example.com", DisplayName: "Example", Origins: []string{"https://Example.com:443", "https://sub.example.com:8443"}})
	got := make([]string, 0, len(rp.origins))
	for _, o := range rp.origins {
		got = append(got, o.String())
	}
	want := []string{"https://example.com", "https://sub.example.com:8443"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("New stored origins %q, want %q", got, want)
	}
}

// TestValidateRPID pins the one legality predicate: upstream's domain rules
// plus this package's lowercase requirement, every refusal matching
// ErrIllegalRPID. The hyphen and numeric-label rows are the two shapes a
// derived-domain path can hand it (a leading-hyphen label and "foo.123").
func TestValidateRPID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		id      string
		wantErr bool
	}{
		{id: "example.com"},
		{id: "sub.example.com"},
		{id: "localhost"},
		{id: "duckdns.org"},
		{id: "", wantErr: true},
		{id: "Example.COM", wantErr: true},
		{id: "10.0.0.5", wantErr: true},
		{id: "::1", wantErr: true},
		{id: "[::1]", wantErr: true},
		{id: "http://example.com", wantErr: true},
		{id: "example.com:8443", wantErr: true},
		{id: "example.com.", wantErr: true},
		{id: "nas", wantErr: true},
		{id: "foo.123", wantErr: true},
		{id: "-foo.example.com", wantErr: true},
		{id: "ex\u00e4mple.com", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.id, "/", "_"), func(t *testing.T) {
			t.Parallel()
			err := ValidateRPID(tt.id)
			if gotErr := err != nil; gotErr != tt.wantErr {
				t.Fatalf("ValidateRPID(%q) error = %v, want error presence %v", tt.id, err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, ErrIllegalRPID) {
				t.Errorf("ValidateRPID(%q) error = %v, want it to match ErrIllegalRPID", tt.id, err)
			}
			if tt.wantErr && !strings.Contains(err.Error(), `"`+tt.id+`"`) {
				t.Errorf("ValidateRPID(%q) error = %q, want it to name the value", tt.id, err)
			}
		})
	}
}

// TestNew_refusesIllegalRPID pins that New applies ValidateRPID, so a
// misspelled or IP relying party fails at construction rather than at ceremony
// time.
func TestNew_refusesIllegalRPID(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"Example.COM", "10.0.0.5", "foo.123", "-foo.example.com", "example.com."} {
		rp, err := New(RPConfig{ID: id, DisplayName: "Example"})
		if !errors.Is(err, ErrIllegalRPID) {
			t.Errorf("New(RPConfig{ID: %q}) = %v, %v; want ErrIllegalRPID", id, rp, err)
		}
	}
}

// TestCeremonyBindsItsOrigin is the CVE-2026-30964 port case asserted at the
// layer that CVE broke: a ceremony begun at one port refuses a response
// declaring another, because the bound origin carries the port and the
// upstream comparator compares it. The second case sends the list's verdict
// through the bound origin to Finish.
func TestCeremonyBindsItsOrigin(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		origins   []string
		beginAt   string
		responder string
	}{
		{name: "port_differs", beginAt: "https://sub.example.com:8443", responder: "https://sub.example.com:9443"},
		{name: "sibling_subdomain_with_list", origins: []string{"https://subflux.example.com"}, beginAt: "https://subflux.example.com", responder: "https://evil.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			rp := mustNew(t, RPConfig{ID: "example.com", DisplayName: "Example", Origins: tt.origins})
			user := &User{AuthUser: &auth.User{ID: 7, Username: "alex", WebAuthnHandle: auth.GenerateWebAuthnHandle()}}
			_, ceremony, err := BeginRegistration(rp, user, mustParseOrigin(t, tt.beginAt))
			if err != nil {
				t.Fatalf("BeginRegistration at %q: %v", tt.beginAt, err)
			}
			if ceremony.origin() != tt.beginAt {
				t.Errorf("ceremony bound origin = %q, want %q", ceremony.origin(), tt.beginAt)
			}
			if protocol.IsOriginInHaystack(tt.responder, []string{ceremony.origin()}) {
				t.Errorf("IsOriginInHaystack(%q, [%q]) = true, want false", tt.responder, ceremony.origin())
			}

			_, err = FinishRegistration(rp, user, ceremony, registrationResponse(t, ceremony.data.Challenge, tt.responder))
			pe, ok := errors.AsType[*protocol.Error](err)
			if !ok || pe.Details != "Error validating origin" {
				t.Errorf("FinishRegistration with response from %q = %v, want the origin to be refused", tt.responder, err)
			}

			_, err = FinishRegistration(rp, user, ceremony, registrationResponse(t, ceremony.data.Challenge, tt.beginAt))
			if pe, ok := errors.AsType[*protocol.Error](err); ok && pe.Details == "Error validating origin" {
				t.Errorf("FinishRegistration with response from %q refused the bound origin: %v", tt.beginAt, err)
			}
		})
	}
}

// TestFinishRefusesUnboundCeremony pins the fail-closed guard: a ceremony
// carrying no origin cannot be finished, on either leg, and nothing falls back
// to a relying-party-derived origin.
func TestFinishRefusesUnboundCeremony(t *testing.T) {
	t.Parallel()
	rp := mustNew(t, RPConfig{ID: "example.com", DisplayName: "Example"})
	user := &User{AuthUser: &auth.User{ID: 7, Username: "alex", WebAuthnHandle: auth.GenerateWebAuthnHandle()}}
	for _, ceremony := range []Ceremony{{}, {data: &gowebauthn.SessionData{Challenge: "c"}}} {
		r := httptest.NewRequest(http.MethodPost, "/finish", strings.NewReader("{}"))
		if _, err := FinishRegistration(rp, user, ceremony, r); !errors.Is(err, ErrCeremonyUnbound) {
			t.Errorf("FinishRegistration(unbound ceremony %+v) error = %v, want ErrCeremonyUnbound", ceremony, err)
		}
		if _, err := CompleteLogin(t.Context(), rp, &fakeStore{}, ceremony, r); !errors.Is(err, ErrCeremonyUnbound) {
			t.Errorf("CompleteLogin(unbound ceremony %+v) error = %v, want ErrCeremonyUnbound", ceremony, err)
		}
	}
}

func mustNew(t *testing.T, cfg RPConfig) *RelyingParty {
	t.Helper()
	rp, err := New(cfg)
	if err != nil {
		t.Fatalf("New(%+v): %v", cfg, err)
	}
	return rp
}

// registrationResponse builds a registration response whose client data
// declares origin and carries the ceremony's challenge, over a minimal
// attestation object that parses. It is enough to reach client-data
// verification, which is the step under test; nothing past it can succeed.
func registrationResponse(t *testing.T, challenge, origin string) *http.Request {
	t.Helper()
	clientData, err := json.Marshal(map[string]string{"type": "webauthn.create", "challenge": challenge, "origin": origin})
	if err != nil {
		t.Fatalf("marshal client data: %v", err)
	}
	credID := []byte{1, 2, 3}
	authData := make([]byte, 0, 64)
	authData = append(authData, make([]byte, 32)...)
	authData = append(authData, byte(protocol.FlagUserPresent|protocol.FlagAttestedCredentialData))
	authData = append(authData, 0, 0, 0, 1)
	authData = append(authData, make([]byte, 16)...)
	authData = append(authData, 0, byte(len(credID)))
	authData = append(authData, credID...)
	authData = append(authData, 0xa0)
	attestation, err := webauthncbor.Marshal(map[string]any{"fmt": "none", "attStmt": map[string]any{}, "authData": authData})
	if err != nil {
		t.Fatalf("marshal attestation object: %v", err)
	}
	b64 := base64.RawURLEncoding.EncodeToString
	body, err := json.Marshal(map[string]any{
		"id":    b64(credID),
		"rawId": b64(credID),
		"type":  "public-key",
		"response": map[string]string{
			"attestationObject": b64(attestation),
			"clientDataJSON":    b64(clientData),
		},
	})
	if err != nil {
		t.Fatalf("marshal response body: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, "/finish", bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}
