package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

// Argon2Params describes the Argon2id parameters for password hashing.
type Argon2Params struct {
	// Memory in KiB. Default: 19456 (19 MiB, OWASP recommendation #2).
	Memory uint32
	// Iterations (time cost). Default: 2.
	Iterations uint32
	// Parallelism (threads). Default: 1.
	Parallelism uint8
	// SaltLength in bytes. Default: 16.
	SaltLength uint32
	// KeyLength in bytes. Default: 32.
	KeyLength uint32
}

// DefaultArgon2Params returns the OWASP-recommended Argon2id parameters.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{
		Memory:      argonMemory,
		Iterations:  argonIterations,
		Parallelism: argonParallelism,
		SaltLength:  argonSaltLen,
		KeyLength:   argonKeyLen,
	}
}

// Validate checks that the params are within safe bounds.
func (p Argon2Params) Validate() error {
	if p.Memory < 1024 {
		return errors.New("auth: argon2 memory must be >= 1024 KiB")
	}
	if p.Memory > 4*1024*1024 { // 4 GiB upper bound to prevent OOM
		return errors.New("auth: argon2 memory must be <= 4 GiB (4194304 KiB)")
	}
	if p.Iterations < 1 {
		return errors.New("auth: argon2 iterations must be >= 1")
	}
	if p.Iterations > 100 { // upper bound to prevent CPU exhaustion
		return errors.New("auth: argon2 iterations must be <= 100")
	}
	if p.Parallelism < 1 {
		return errors.New("auth: argon2 parallelism must be >= 1")
	}
	if p.SaltLength < 8 {
		return errors.New("auth: argon2 salt length must be >= 8")
	}
	if p.KeyLength < 16 {
		return errors.New("auth: argon2 key length must be >= 16")
	}
	return nil
}

// Hasher provides configurable Argon2id password hashing with optional pepper.
type Hasher struct {
	pepper []byte // optional; if nil, no pepper is applied
	params Argon2Params
}

// NewHasher creates a Hasher with the given params. Returns an error if params
// are invalid. Use [WithPepper] to enable HMAC peppering. A Hasher must be
// constructed with NewHasher: the zero value has all-zero Argon2 parameters,
// which panic inside x/crypto's argon2 on first use.
func NewHasher(params Argon2Params, opts ...HasherOption) (*Hasher, error) {
	if err := params.Validate(); err != nil {
		return nil, err
	}
	var hcfg hasherConfig
	for _, o := range opts {
		if o != nil {
			o(&hcfg)
		}
	}
	var p []byte
	if len(hcfg.pepper) > 0 {
		p = make([]byte, len(hcfg.pepper))
		copy(p, hcfg.pepper)
	}
	return &Hasher{params: params, pepper: p}, nil
}

// applyPepper returns HMAC-SHA256(pepper, password) if pepper is set,
// otherwise returns password unchanged.
func (h *Hasher) applyPepper(password string) []byte {
	if len(h.pepper) == 0 {
		return []byte(password)
	}
	mac := hmac.New(sha256.New, h.pepper)
	mac.Write([]byte(password))
	return mac.Sum(nil)
}

// Hash hashes a password using Argon2id with the configured parameters.
// Returns the hash in PHC string format.
//
// It cannot fail, and so returns no error. Its only former failure source was
// the salt draw, and since Go 1.24 [crypto/rand.Read] never returns an error;
// [NewHasher] has already rejected parameters that would make argon2 panic. The
// asymmetry with [Hasher.Verify], which does return an error, is deliberate:
// Verify parses caller-supplied input and can genuinely fail.
func (h *Hasher) Hash(password string) string {
	salt := make([]byte, h.params.SaltLength)
	rand.Read(salt) // never returns an error (Go 1.24+); it crashes instead
	input := h.applyPepper(password)
	key := argon2.IDKey(input, salt, h.params.Iterations, h.params.Memory, h.params.Parallelism, h.params.KeyLength)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Key := base64.RawStdEncoding.EncodeToString(key)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, h.params.Memory, h.params.Iterations, h.params.Parallelism,
		b64Salt, b64Key)
}

// Verify verifies a password against an encoded Argon2id hash in PHC format.
func (h *Hasher) Verify(password, encodedHash string) (bool, error) {
	p, err := parsePHC(encodedHash)
	if err != nil {
		return false, err
	}
	input := h.applyPepper(password)
	derived := argon2.IDKey(input, p.salt, p.iterations, p.memory, p.parallelism, p.keyLen)
	return subtle.ConstantTimeCompare(p.key, derived) == 1, nil
}

// NeedsRehash reports whether the hash uses different parameters than this Hasher.
func (h *Hasher) NeedsRehash(encodedHash string) bool {
	p, err := parsePHC(encodedHash)
	if err != nil {
		return true
	}
	return p.memory != h.params.Memory || p.iterations != h.params.Iterations ||
		p.parallelism != h.params.Parallelism || p.keyLen != h.params.KeyLength
}
