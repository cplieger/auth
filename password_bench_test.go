package auth

import "testing"

func BenchmarkHashPassword(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_, err := HashPassword("benchmark-password-123!")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	hash, err := HashPassword("benchmark-password-123!")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = VerifyPassword("benchmark-password-123!", hash)
	}
}
