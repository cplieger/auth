package auth

import (
	"testing"
)

func TestHasher_DefaultParams(t *testing.T) {
	t.Parallel()
	h, err := NewHasher(DefaultArgon2Params())
	if err != nil {
		t.Fatal(err)
	}
	hash, err := h.Hash("test-password")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := h.Verify("test-password", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected verification to succeed")
	}
	ok, err = h.Verify("wrong-password", hash)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected verification to fail")
	}
}

func TestHasher_CustomParams(t *testing.T) {
	t.Parallel()
	params := Argon2Params{
		Memory:      2048,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	h, err := NewHasher(params)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := h.Hash("custom-params")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := h.Verify("custom-params", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected verification to succeed with custom params")
	}
}

func TestHasher_NeedsRehash(t *testing.T) {
	t.Parallel()
	p1 := Argon2Params{Memory: 2048, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	h1, _ := NewHasher(p1)
	hash, _ := h1.Hash("pw")

	p2 := Argon2Params{Memory: 4096, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	h2, _ := NewHasher(p2)

	if !h2.NeedsRehash(hash) {
		t.Fatal("expected NeedsRehash=true for different params")
	}
	if h1.NeedsRehash(hash) {
		t.Fatal("expected NeedsRehash=false for same params")
	}
}

func TestHasher_WithPepper(t *testing.T) {
	t.Parallel()
	pepper := []byte("super-secret-pepper-key-32bytes!")
	h, err := NewHasher(DefaultArgon2Params(), WithPepper(pepper))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := h.Hash("peppered-password")
	if err != nil {
		t.Fatal(err)
	}
	ok, err := h.Verify("peppered-password", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected peppered verification to succeed")
	}

	// Without pepper should fail
	hNoPepper, _ := NewHasher(DefaultArgon2Params())
	ok, err = hNoPepper.Verify("peppered-password", hash)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("expected verification without pepper to fail")
	}
}

func TestHasher_InvalidParams(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		params Argon2Params
	}{
		{"low memory", Argon2Params{Memory: 512, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}},
		{"zero iterations", Argon2Params{Memory: 2048, Iterations: 0, Parallelism: 1, SaltLength: 16, KeyLength: 32}},
		{"zero parallelism", Argon2Params{Memory: 2048, Iterations: 1, Parallelism: 0, SaltLength: 16, KeyLength: 32}},
		{"short salt", Argon2Params{Memory: 2048, Iterations: 1, Parallelism: 1, SaltLength: 4, KeyLength: 32}},
		{"short key", Argon2Params{Memory: 2048, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 8}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewHasher(tc.params)
			if err == nil {
				t.Fatal("expected error for invalid params")
			}
		})
	}
}

func TestHasher_CompatibleWithPackageFunctions(t *testing.T) {
	t.Parallel()
	// A hash created by the package-level HashPassword should be verifiable
	// by a Hasher with default params and no pepper.
	hash, err := HashPassword("compat-test")
	if err != nil {
		t.Fatal(err)
	}
	h, _ := NewHasher(DefaultArgon2Params())
	ok, err := h.Verify("compat-test", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected Hasher to verify package-level hash")
	}
}
