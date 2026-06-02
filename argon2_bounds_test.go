package auth

import (
	"math"
	"testing"
)

func TestArgon2Params_Validate_RejectsExcessiveMemory(t *testing.T) {
	t.Parallel()
	p := Argon2Params{
		Memory:      math.MaxUint32,
		Iterations:  2,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for excessive memory param")
	}
}

func TestArgon2Params_Validate_RejectsExcessiveIterations(t *testing.T) {
	t.Parallel()
	p := Argon2Params{
		Memory:      19456,
		Iterations:  math.MaxUint32,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected error for excessive iterations param")
	}
}

func TestArgon2Params_Validate_AcceptsUpperBound(t *testing.T) {
	t.Parallel()
	// 4 GiB is the max allowed memory
	p := Argon2Params{
		Memory:      4 * 1024 * 1024,
		Iterations:  100,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("expected valid at upper bound, got: %v", err)
	}
}
