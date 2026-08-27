package auth

import (
	"net/http"
	"testing"
)

func TestIsBrowserRequest_table(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		accept string
		apiKey string
		want   bool
	}{
		{"browser html", "text/html,application/xhtml+xml", "", true},
		{"browser with wildcard", "text/html, */*", "", true},
		{"api client json", "application/json", "", false},
		{"api key overrides browser", "text/html", "ak_abc123", false},
		{"empty accept", "", "", false},
		{"api key with empty accept", "", "ak_abc123", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, _ := http.NewRequest(http.MethodGet, "/", nil)
			if tt.accept != "" {
				r.Header.Set("Accept", tt.accept)
			}
			if tt.apiKey != "" {
				r.Header.Set("X-API-Key", tt.apiKey)
			}
			got := IsBrowserRequest(r)
			if got != tt.want {
				t.Errorf("IsBrowserRequest() = %v, want %v", got, tt.want)
			}
		})
	}
}
