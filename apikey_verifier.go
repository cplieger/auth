package auth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

// APIKeyVerifierStore is the minimal interface for API key verification.
type APIKeyVerifierStore interface {
	APIKeyReader
	UserReader
}

// APIKeyVerifier authenticates requests via the X-API-Key header.
// Create with [NewAPIKeyVerifier].
type APIKeyVerifier struct {
	store APIKeyVerifierStore
	cfg   authConfig
}

// NewAPIKeyVerifier creates an APIKeyVerifier with the given store and options.
// Of the shared [Option] set it consults only [WithLogger]; every other option
// (cookie, timeouts, throttle, bypass, hooks) configures session or
// authenticator behavior this verifier does not have and is silently ignored.
func NewAPIKeyVerifier(store APIKeyVerifierStore, opts ...Option) *APIKeyVerifier {
	cfg := authConfig{}
	for _, o := range opts {
		if o != nil {
			o(&cfg)
		}
	}
	return &APIKeyVerifier{store: store, cfg: cfg}
}

// logger returns the configured logger or slog.Default().
func (v *APIKeyVerifier) logger() *slog.Logger {
	if v.cfg.logger != nil {
		return v.cfg.logger
	}
	return slog.Default()
}

// Verify checks the X-API-Key header and returns the user if the key is valid.
// API keys are accepted only via the header, never via a URL query parameter;
// a key in a query string leaks into access logs, browser history, and the
// Referer header (CWE-598).
func (v *APIKeyVerifier) Verify(ctx context.Context, r *http.Request) (*User, string, error) {
	key := r.Header.Get(HeaderXAPIKey)
	if key == "" {
		return nil, "", nil
	}
	apiKey, err := VerifyAPIKey(ctx, v.store, key)
	if err != nil {
		if errors.Is(err, ErrInvalidAPIKey) {
			v.logger().Debug("auth: API key verification failed", "error", err)
			return nil, "", ErrUnauthenticated
		}
		return nil, "", err
	}
	user, found, err := v.store.GetUserByID(ctx, apiKey.UserID)
	if err != nil {
		return nil, "", err
	}
	if !found || !user.Enabled {
		v.logger().Debug("auth: API key resolved to missing or disabled user", "user_id", apiKey.UserID)
		return nil, "", ErrUnauthenticated
	}
	return user, "", nil
}
