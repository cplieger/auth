package auth

import "testing"

func BenchmarkHashPassword(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		HashPassword("benchmark-password-123!")
	}
}

func BenchmarkVerifyPassword(b *testing.B) {
	hash := HashPassword("benchmark-password-123!")
	b.ReportAllocs()
	for b.Loop() {
		_, _ = VerifyPassword("benchmark-password-123!", hash)
	}
}
