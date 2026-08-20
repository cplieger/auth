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
	hash := h.Hash("test-password")
	t.Run("verifies correct password", func(t *testing.T) {
		ok, err := h.Verify("test-password", hash)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("Verify(correct password) = %v, want true", ok)
		}
	})
	t.Run("rejects wrong password", func(t *testing.T) {
		ok, err := h.Verify("wrong-password", hash)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Errorf("Verify(wrong password) = %v, want false", ok)
		}
	})
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
	hash := h.Hash("custom-params")
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
	hash := h1.Hash("pw")

	p2 := Argon2Params{Memory: 4096, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	h2, _ := NewHasher(p2)

	t.Run("different params need rehash", func(t *testing.T) {
		if got := h2.NeedsRehash(hash); !got {
			t.Errorf("NeedsRehash(hash made with %+v) under %+v = %v, want true", p1, p2, got)
		}
	})
	t.Run("same params do not need rehash", func(t *testing.T) {
		if got := h1.NeedsRehash(hash); got {
			t.Errorf("NeedsRehash(hash made with %+v) under same params = %v, want false", p1, got)
		}
	})
}

func TestHasher_WithPepper(t *testing.T) {
	t.Parallel()
	pepper := []byte("super-secret-pepper-key-32bytes!")
	h, err := NewHasher(DefaultArgon2Params(), WithPepper(pepper))
	if err != nil {
		t.Fatal(err)
	}
	hash := h.Hash("peppered-password")
	t.Run("verifies with same pepper", func(t *testing.T) {
		ok, err := h.Verify("peppered-password", hash)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("Verify(with pepper) = %v, want true", ok)
		}
	})
	t.Run("rejects without pepper", func(t *testing.T) {
		hNoPepper, _ := NewHasher(DefaultArgon2Params())
		ok, err := hNoPepper.Verify("peppered-password", hash)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Errorf("Verify(without pepper) = %v, want false", ok)
		}
	})
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
	hash := HashPassword("compat-test")
	h, _ := NewHasher(DefaultArgon2Params())
	ok, err := h.Verify("compat-test", hash)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected Hasher to verify package-level hash")
	}
}

func TestHasher_differentPeppersProduceIncompatibleHashes(t *testing.T) {
	t.Parallel()
	// The pepper is HMAC-mixed into the password before Argon2, so two hashers
	// configured with different peppers must derive different keys for the same
	// password: a hash made under one pepper verifies under its own pepper but
	// must NOT verify under a different one. This pins that the pepper actually
	// participates in the derived hash rather than being silently dropped.
	params := Argon2Params{Memory: 2048, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
	h1, err := NewHasher(params, WithPepper([]byte("pepper-one")))
	if err != nil {
		t.Fatal(err)
	}
	h2, err := NewHasher(params, WithPepper([]byte("pepper-two")))
	if err != nil {
		t.Fatal(err)
	}

	const password = "correct horse battery staple"
	hash1 := h1.Hash(password)

	t.Run("verifies under its own pepper", func(t *testing.T) {
		ok, err := h1.Verify(password, hash1)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Errorf("Verify(own pepper) = %v, want true", ok)
		}
	})
	t.Run("rejects under a different pepper", func(t *testing.T) {
		ok, err := h2.Verify(password, hash1)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Errorf("Verify(different pepper) = %v, want false (the pepper must affect the derived key)", ok)
		}
	})
}
