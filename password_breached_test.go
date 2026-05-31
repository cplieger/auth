package auth

import (
	"context"
	"crypto/sha1" //nolint:gosec
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
	return rt.server.Client().Do(rebased) //nolint:wrapcheck
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
