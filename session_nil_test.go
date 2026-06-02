package auth

import (
	"testing"
	"time"
)

func TestValidateSession_NilSession(t *testing.T) {
	t.Parallel()
	err := ValidateSession(nil, time.Hour, 24*time.Hour, time.Now())
	if err != ErrSessionNotFound {
		t.Fatalf("ValidateSession(nil) = %v, want ErrSessionNotFound", err)
	}
}
