package traefik_http_knock

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPBKDF2ReusesIterationBuffer guards the fast path in pbkdf2SHA256: Sum(nil)
// allocates once per iteration, which at 600,000 iterations means roughly
// 19 MiB of garbage per password verification. Keep the allocation count
// independent of the iteration count.
func TestPBKDF2ReusesIterationBuffer(t *testing.T) {
	password := []byte("password")
	salt := []byte("0123456789abcdef")

	allocs := testing.AllocsPerRun(3, func() {
		_ = pbkdf2SHA256(password, salt, minPBKDF2Iterations, pbkdf2KeyLength)
	})
	if allocs > 50 {
		t.Fatalf("pbkdf2SHA256 allocates %.0f times per call; want <= 50", allocs)
	}
}

func BenchmarkPBKDF2SHA256(b *testing.B) {
	password := []byte("correct horse battery staple")
	salt := []byte("0123456789abcdef")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = pbkdf2SHA256(password, salt, DefaultPBKDF2Iterations, pbkdf2KeyLength)
	}
}

// BenchmarkAuthenticateSharedFirstMatch exercises the shared-password path when
// the first credential matches. Before the early break it ran the KDF for every
// shared credential on every login.
func BenchmarkAuthenticateSharedFirstMatch(b *testing.B) {
	first, err := HashPassword("first password", minPBKDF2Iterations)
	if err != nil {
		b.Fatal(err)
	}
	second, err := HashPassword("second password", minPBKDF2Iterations)
	if err != nil {
		b.Fatal(err)
	}
	set, err := buildUserSet([]User{
		{PasswordHash: first},
		{PasswordHash: second},
	}, "", "")
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, ok := set.authenticate("", "first password"); !ok {
			b.Fatal("authenticate failed")
		}
	}
}

func BenchmarkClientIPFromRequest(b *testing.B) {
	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.RemoteAddr = "203.0.113.7:54321"
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = clientIPFromRequest(req, "")
	}
}

func BenchmarkApplyPrivateHeaders(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		header := make(http.Header)
		applyPrivateHeaders(header)
	}
}
