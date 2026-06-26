package auth

import (
	"math"
	"testing"
)

// TestArgon2Params_Validate_bounds pins every boundary of Argon2Params.Validate:
// each safety limit is checked at its rejecting side, at its exact accepting
// edge, and (for memory/iterations) at the uint32 extreme.
func TestArgon2Params_Validate_bounds(t *testing.T) {
	t.Parallel()

	// valid is the baseline accepted configuration; each case overrides one
	// field to probe a single boundary.
	valid := Argon2Params{Memory: 19456, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}

	cases := []struct {
		name    string
		p       Argon2Params
		wantErr bool
	}{
		{"baseline valid", valid, false},

		{"memory below min", Argon2Params{Memory: 1023, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}, true},
		{"memory at min", Argon2Params{Memory: 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}, false},
		{"memory above max", Argon2Params{Memory: 4*1024*1024 + 1, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}, true},
		{"memory at max", Argon2Params{Memory: 4 * 1024 * 1024, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}, false},
		{"memory max uint32", Argon2Params{Memory: math.MaxUint32, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 32}, true},

		{"iterations zero", Argon2Params{Memory: 19456, Iterations: 0, Parallelism: 1, SaltLength: 16, KeyLength: 32}, true},
		{"iterations at min", Argon2Params{Memory: 19456, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}, false},
		{"iterations at max", Argon2Params{Memory: 19456, Iterations: 100, Parallelism: 1, SaltLength: 16, KeyLength: 32}, false},
		{"iterations above max", Argon2Params{Memory: 19456, Iterations: 101, Parallelism: 1, SaltLength: 16, KeyLength: 32}, true},
		{"iterations max uint32", Argon2Params{Memory: 19456, Iterations: math.MaxUint32, Parallelism: 1, SaltLength: 16, KeyLength: 32}, true},

		{"parallelism zero", Argon2Params{Memory: 19456, Iterations: 2, Parallelism: 0, SaltLength: 16, KeyLength: 32}, true},

		{"salt below min", Argon2Params{Memory: 19456, Iterations: 2, Parallelism: 1, SaltLength: 7, KeyLength: 32}, true},
		{"salt at min", Argon2Params{Memory: 19456, Iterations: 2, Parallelism: 1, SaltLength: 8, KeyLength: 32}, false},

		{"key below min", Argon2Params{Memory: 19456, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 15}, true},
		{"key at min", Argon2Params{Memory: 19456, Iterations: 2, Parallelism: 1, SaltLength: 16, KeyLength: 16}, false},

		{"all minimum accepted", Argon2Params{Memory: 1024, Iterations: 1, Parallelism: 1, SaltLength: 8, KeyLength: 16}, false},
		{"upper bound combo accepted", Argon2Params{Memory: 4 * 1024 * 1024, Iterations: 100, Parallelism: 1, SaltLength: 16, KeyLength: 32}, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.p.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate(%+v) error = %v, wantErr = %v", tc.p, err, tc.wantErr)
			}
		})
	}
}
