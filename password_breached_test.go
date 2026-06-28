package auth

import (
	"context"
	"crypto/sha1"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type hibpRoundTripper struct {
	t             *testing.T
	server        *httptest.Server
	respByPrefix  map[string]string
	gotAddPadding string
}

func (rt *hibpRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.t.Helper()
	rt.gotAddPadding = req.Header.Get("Add-Padding")
	rebased, _ := http.NewRequest(req.Method, rt.server.URL+req.URL.Path, http.NoBody)
	rebased.Header = req.Header
	return rt.server.Client().Do(rebased) //nolint:wrapcheck // test inspects the raw error
}

func newHibpFake(t *testing.T, respByPrefix map[string]string) *http.Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path[len("/range/"):]
		body, ok := respByPrefix[strings.ToUpper(key)]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	rt := &hibpRoundTripper{t: t, server: srv, respByPrefix: respByPrefix}
	return &http.Client{Transport: rt}
}

func hibpFakeWithCapture(t *testing.T, respByPrefix map[string]string) (*http.Client, *hibpRoundTripper) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Path[len("/range/"):]
		body, ok := respByPrefix[strings.ToUpper(key)]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	rt := &hibpRoundTripper{t: t, server: srv, respByPrefix: respByPrefix}
	return &http.Client{Transport: rt}, rt
}

func TestCheckBreachedPassword_sets_add_padding_header(t *testing.T) {
	t.Parallel()
	hash := sha1.Sum([]byte("anything"))
	prefix := fmt.Sprintf("%X", hash)[:5]
	client, rt := hibpFakeWithCapture(t, map[string]string{prefix: ""})

	_, _ = CheckBreachedPassword(context.Background(), client, "anything")

	if rt.gotAddPadding != "true" {
		t.Errorf("Add-Padding = %q, want %q", rt.gotAddPadding, "true")
	}
}

func TestCheckBreachedPassword_filters_zero_count_padding(t *testing.T) {
	t.Parallel()
	password := "MySecretPassword!"
	hash := sha1.Sum([]byte(password))
	hexStr := fmt.Sprintf("%X", hash)
	prefix, suffix := hexStr[:5], hexStr[5:]

	body := suffix + ":0\nDEADBEEF" + strings.Repeat("0", len(suffix)-8) + ":7\n"
	client := newHibpFake(t, map[string]string{prefix: body})

	breached, err := CheckBreachedPassword(context.Background(), client, password)
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
	client := newHibpFake(t, map[string]string{prefix: body})

	breached, err := CheckBreachedPassword(context.Background(), client, password)
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
	client := newHibpFake(t, map[string]string{prefix: body})

	breached, err := CheckBreachedPassword(context.Background(), client, password)
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
			breached, err := CheckBreachedPassword(context.Background(), client, "any-password-value")
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
	client := newHibpFake(t, map[string]string{prefix: body})

	breached, err := CheckBreachedPassword(context.Background(), client, password)
	if err != nil {
		t.Fatalf("CheckBreachedPassword error = %v, want nil", err)
	}
	if breached {
		t.Error("malformed count treated as a breach, want not-breached")
	}
}
