package auth

import (
	"crypto/sha1"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// hibpFake stands up the Have I Been Pwned range endpoint on httptest's
// in-memory network (Go 1.27). The client it returns routes the hardcoded
// https://api.pwnedpasswords.com/range/... URL that CheckBreachedPassword
// builds straight to the handler with the Host, path and headers intact —
// measured on go1.27.0 — which is why no rebasing RoundTripper is needed.
//
// The fake it replaces had to rewrite the request onto the listener's address,
// and in doing so erased the one thing worth asserting about an outbound
// breach check: which host the library actually contacted. The handler records
// it, so gotHost below is a stronger assertion than the old fixture could make.
type hibpFake struct {
	respByPrefix  map[string]string
	gotHost       string
	gotPath       string
	gotAddPadding string
}

func newHibpFake(t *testing.T, respByPrefix map[string]string) (*http.Client, *hibpFake) {
	t.Helper()
	f := &hibpFake{respByPrefix: respByPrefix}
	srv := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.gotHost, f.gotPath = r.Host, r.URL.Path
		f.gotAddPadding = r.Header.Get("Add-Padding")
		body, ok := f.respByPrefix[strings.ToUpper(strings.TrimPrefix(r.URL.Path, "/range/"))]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	return srv.Client(), f
}

func TestCheckBreachedPassword_sets_add_padding_header(t *testing.T) {
	t.Parallel()
	hash := sha1.Sum([]byte("anything"))
	prefix := fmt.Sprintf("%X", hash)[:5]
	client, fake := newHibpFake(t, map[string]string{prefix: ""})

	_, _ = CheckBreachedPassword(t.Context(), client, "anything")

	if fake.gotAddPadding != "true" {
		t.Errorf("Add-Padding = %q, want %q", fake.gotAddPadding, "true")
	}
	// The in-memory network preserves the request the library built, so the
	// k-anonymity contract is directly observable: only the 5-hex-character
	// prefix may leave the process, never the full SHA-1.
	if fake.gotHost != "api.pwnedpasswords.com" {
		t.Errorf("outbound Host = %q, want %q", fake.gotHost, "api.pwnedpasswords.com")
	}
	if want := "/range/" + prefix; fake.gotPath != want {
		t.Errorf("outbound path = %q, want %q (only the 5-char prefix, never the full hash)", fake.gotPath, want)
	}
}

func TestCheckBreachedPassword_filters_zero_count_padding(t *testing.T) {
	t.Parallel()
	password := "MySecretPassword!"
	hash := sha1.Sum([]byte(password))
	hexStr := fmt.Sprintf("%X", hash)
	prefix, suffix := hexStr[:5], hexStr[5:]

	body := suffix + ":0\nDEADBEEF" + strings.Repeat("0", len(suffix)-8) + ":7\n"
	client, _ := newHibpFake(t, map[string]string{prefix: body})

	breached, err := CheckBreachedPassword(t.Context(), client, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if breached {
		t.Error("count=0 treated as breach")
	}
}

func TestCheckBreachedPassword_real_hit(t *testing.T) {
	t.Parallel()
	password := "Password123!"
	hash := sha1.Sum([]byte(password))
	hexStr := fmt.Sprintf("%X", hash)
	prefix, suffix := hexStr[:5], hexStr[5:]

	body := suffix + ":42\n"
	client, _ := newHibpFake(t, map[string]string{prefix: body})

	breached, err := CheckBreachedPassword(t.Context(), client, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !breached {
		t.Error("real hit not detected")
	}
}

func TestCheckBreachedPassword_no_match(t *testing.T) {
	t.Parallel()
	password := "UntestedPassword99"
	hash := sha1.Sum([]byte(password))
	prefix := fmt.Sprintf("%X", hash)[:5]

	body := "DEADBEEFCAFE0000111122223333444455556666:5\n"
	client, _ := newHibpFake(t, map[string]string{prefix: body})

	breached, err := CheckBreachedPassword(t.Context(), client, password)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if breached {
		t.Error("no-match treated as breach")
	}
}

type breachStubTransport struct {
	err    error
	status int
}

func (rt breachStubTransport) RoundTrip(*http.Request) (*http.Response, error) {
	if rt.err != nil {
		return nil, rt.err
	}
	return &http.Response{StatusCode: rt.status, Body: http.NoBody, Header: make(http.Header)}, nil
}

func TestCheckBreachedPassword_failsOpenOnUpstreamFailure(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		transport http.RoundTripper
	}{
		{"transport error", breachStubTransport{err: fmt.Errorf("dial tcp: connection refused")}},
		{"500 status", breachStubTransport{status: http.StatusInternalServerError}},
		{"429 status", breachStubTransport{status: http.StatusTooManyRequests}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			client := &http.Client{Transport: tc.transport}
			breached, err := CheckBreachedPassword(t.Context(), client, "any-password-value")
			if err != nil {
				t.Errorf("CheckBreachedPassword(%s) error = %v, want nil (fail open)", tc.name, err)
			}
			if breached {
				t.Errorf("CheckBreachedPassword(%s) = true, want false (fail open)", tc.name)
			}
		})
	}
}

func TestCheckBreachedPassword_skipsMalformedCountLine(t *testing.T) {
	t.Parallel()
	password := "Some-Password-99"
	hash := sha1.Sum([]byte(password))
	hexStr := fmt.Sprintf("%X", hash)
	prefix, suffix := hexStr[:5], hexStr[5:]

	// The one line matching our suffix carries a non-numeric count, so the
	// parser must skip it and report not-breached (never error, never breach).
	body := suffix + ":not-a-number\n"
	client, _ := newHibpFake(t, map[string]string{prefix: body})

	breached, err := CheckBreachedPassword(t.Context(), client, password)
	if err != nil {
		t.Fatalf("CheckBreachedPassword error = %v, want nil", err)
	}
	if breached {
		t.Error("malformed count treated as a breach, want not-breached")
	}
}
