package auth

import (
	"context"
	"errors"
	"net/http"
)

// APIKeyVerifier authenticates requests via X-API-Key header or api_key query param.
// Create with [NewAPIKeyVerifier].
type APIKeyVerifier struct {
	store SessionStore
}

// NewAPIKeyVerifier creates an APIKeyVerifier with the given session store and options.
func NewAPIKeyVerifier(store SessionStore, opts ...Option) *APIKeyVerifier { //nolint:revive // opts reserved for forward-compat
	return &APIKeyVerifier{store: store}
}

// Verify checks the API key header and query param, returns the user if valid.
func (v *APIKeyVerifier) Verify(ctx context.Context, r *http.Request) (*User, string, error) {
	key := r.Header.Get(HeaderXAPIKey)
	if key == "" {
		key = r.URL.Query().Get(QueryParamAPIKey)
	}
	if key == "" {
		return nil, "", nil
	}
	apiKey, err := VerifyAPIKey(ctx, v.store, key)
	if err != nil {
		if errors.Is(err, ErrInvalidAPIKey) {
			return nil, "", ErrUnauthenticated
		}
		return nil, "", err
	}
	user, err := v.store.GetUserByID(ctx, apiKey.UserID)
	if err != nil {
		return nil, "", err
	}
	if user == nil || !user.Enabled {
		return nil, "", ErrUnauthenticated
	}
	return user, "", nil
}
