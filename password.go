// Package auth implements authentication primitives: password hashing
// (Argon2id in PHC string format), WebAuthn/FIDO2 passkey ceremonies, OIDC
// provider integration with PKCE, session management with idle/absolute
// timeouts, API key generation and verification, and role-based access
// control helpers.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters per OWASP recommendations.
const (
	argonMemory      = 19456 // 19 MiB
	argonIterations  = 2
	argonParallelism = 1
	argonSaltLen     = 16
	argonKeyLen      = 32
)

// DummyHash returns a pre-computed Argon2id hash used by the login handler
// to equalize timing when the username doesn't exist (H2 mitigation).
// The hash is computed lazily on first call via sync.Once.
func DummyHash() string {
	dummyHashOnce.Do(func() {
		h, err := HashPassword("dummy-init-password")
		if err != nil {
			panic("auth: failed to generate dummy hash: " + err.Error())
		}
		dummyHashVal = h
	})
	return dummyHashVal
}

var (
	dummyHashOnce sync.Once
	dummyHashVal  string
)

// HashPassword hashes a password using Argon2id with OWASP parameters.
// Returns the hash in PHC string format:
// $argon2id$v=19$m=19456,t=2,p=1$<base64-salt>$<base64-hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallelism, argonKeyLen)

	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonIterations, argonParallelism,
		b64Salt, b64Key), nil
}

// VerifyPassword verifies a password against an encoded Argon2id hash
// in PHC string format. Uses constant-time comparison.
func VerifyPassword(password, encodedHash string) (bool, error) {
	p, err := parsePHC(encodedHash)
	if err != nil {
		return false, err
	}

	derived := argon2.IDKey([]byte(password), p.salt, p.iterations, p.memory, p.parallelism, p.keyLen)
	return subtle.ConstantTimeCompare(p.key, derived) == 1, nil
}

// phcParams holds the parsed parameters from a PHC-format Argon2id hash string.
type phcParams struct {
	salt, key          []byte
	memory, iterations uint32
	parallelism        uint8
	keyLen             uint32
}

// NeedsRehash reports whether the encoded hash was produced with parameters
// different from the current OWASP-recommended defaults. Returns true if the
// hash is invalid or uses outdated parameters.
func NeedsRehash(encodedHash string) bool {
	p, err := parsePHC(encodedHash)
	if err != nil {
		return true
	}
	return p.memory != argonMemory || p.iterations != argonIterations ||
		p.parallelism != argonParallelism || p.keyLen != argonKeyLen
}

// parsePHC extracts parameters from a PHC-format Argon2id hash string.
func parsePHC(encoded string) (phcParams, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return phcParams{}, errors.New("auth: invalid PHC hash format")
	}

	var version int
	if _, errV := fmt.Sscanf(parts[2], "v=%d", &version); errV != nil {
		return phcParams{}, fmt.Errorf("auth: parse version: %w", errV)
	}
	if version != argon2.Version {
		return phcParams{}, fmt.Errorf("auth: unsupported argon2 version %d", version)
	}

	var p phcParams
	if _, errP := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.memory, &p.iterations, &p.parallelism); errP != nil {
		return phcParams{}, fmt.Errorf("auth: parse params: %w", errP)
	}

	var err error
	p.salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return phcParams{}, fmt.Errorf("auth: decode salt: %w", err)
	}

	p.key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return phcParams{}, fmt.Errorf("auth: decode key: %w", err)
	}

	p.keyLen = uint32(len(p.key)) //nolint:gosec // G115: key length bounded by argon2 params

	// Reject params that would panic inside argon2.IDKey.
	if p.iterations < 1 {
		return phcParams{}, errors.New("auth: invalid PHC hash: iterations must be >= 1")
	}
	if p.parallelism < 1 {
		return phcParams{}, errors.New("auth: invalid PHC hash: parallelism must be >= 1")
	}
	if p.keyLen < 1 {
		return phcParams{}, errors.New("auth: invalid PHC hash: key must not be empty")
	}

	return p, nil
}
