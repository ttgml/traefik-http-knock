package traefik_http_knock

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestPBKDF2SHA256KnownVector(t *testing.T) {
	// RFC 7914 section 11 / common PBKDF2-HMAC-SHA256 test vector.
	got := hex.EncodeToString(pbkdf2SHA256([]byte("password"), []byte("salt"), 1, 32))
	want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if got != want {
		t.Fatalf("pbkdf2SHA256 = %q, want %q", got, want)
	}
}

func TestHashPasswordRoundTrip(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple", minPBKDF2Iterations)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "pbkdf2-sha256$") {
		t.Fatalf("unexpected hash format %q", hash)
	}

	parsed, err := parsePasswordHash(hash)
	if err != nil {
		t.Fatalf("parsePasswordHash: %v", err)
	}
	if !parsed.verifyPassword("correct horse battery staple") {
		t.Fatal("correct password was rejected")
	}
	if parsed.verifyPassword("wrong") {
		t.Fatal("wrong password was accepted")
	}
	if parsed.verifyPassword("") {
		t.Fatal("empty password was accepted")
	}
}

func TestHashPasswordRejectsBadInput(t *testing.T) {
	if _, err := HashPassword("", minPBKDF2Iterations); err == nil {
		t.Fatal("expected an error for an empty password")
	}
	if _, err := HashPassword("x", 1); err == nil {
		t.Fatal("expected an error for too few iterations")
	}
	if _, err := HashPassword("x", -1); err == nil {
		t.Fatal("expected an error for a negative iteration count")
	}
}

func TestParsePasswordHashRejectsMalformedValues(t *testing.T) {
	values := []string{
		"",
		"plaintext",
		"pbkdf2-sha256$1$c2FsdA==$aGFzaA==",
		"pbkdf2-sha256$10000$not-base64$abcd",
		"pbkdf2-sha256$10000$c2FsdA==$not-base64",
		"sha256$10000$c2FsdA==$aGFzaA==",
	}
	for _, value := range values {
		if _, err := parsePasswordHash(value); err == nil {
			t.Fatalf("parsePasswordHash(%q) succeeded, want an error", value)
		}
	}
}

func TestSessionTokenRoundTrip(t *testing.T) {
	secret := []byte(testCookieSecret)
	wantID, err := newSessionID()
	if err != nil {
		t.Fatalf("newSessionID: %v", err)
	}
	token := signSessionToken(secret, "realm-a", wantID)
	sessionID, ok := parseSessionToken(secret, "realm-a", token)
	if !ok || sessionID != wantID {
		t.Fatalf("parseSessionToken = %q, %v; want %q, true", sessionID, ok, wantID)
	}

	if _, ok := parseSessionToken(secret, "realm-b", token); ok {
		t.Fatal("token must not validate for another realm")
	}
	if _, ok := parseSessionToken([]byte("another-secret-0123456789abcdef"), "realm-a", token); ok {
		t.Fatal("token must not validate with another secret")
	}

	for _, malformed := range []string{"", "v1", "v2.a.b", "v1.a", "v1..b", "v1.a.b.c"} {
		if _, ok := parseSessionToken(secret, "realm-a", malformed); ok {
			t.Fatalf("malformed token %q was accepted", malformed)
		}
	}
}

func TestValidUsernameAndCookieName(t *testing.T) {
	validUsers := []string{"", "alice", "alice.smith", "alice_1", "alice-1", "alice@example.com"}
	for _, username := range validUsers {
		if !validUsername(username) {
			t.Fatalf("validUsername(%q) = false", username)
		}
	}
	invalidUsers := []string{"alice:bob", "alice|bob", "alice bob", "ali\nce", strings.Repeat("a", 65)}
	for _, username := range invalidUsers {
		if validUsername(username) {
			t.Fatalf("validUsername(%q) = true", username)
		}
	}

	if !validCookieName("__Host-http-knock-abc") {
		t.Fatal("valid cookie name rejected")
	}
	for _, name := range []string{"", "bad cookie", "bad;cookie", "bad,cookie"} {
		if validCookieName(name) {
			t.Fatalf("validCookieName(%q) = true", name)
		}
	}
}

func TestCredentialsFileParsing(t *testing.T) {
	value := `
# comment
alice:plain:alice-password
bob:plain:bob-password:with:colon
plain:shared-password
pbkdf2-sha256$10000$c2FsdA==$aGFzaA==
`
	users, err := parseCredentialLines(value)
	if err != nil {
		t.Fatalf("parseCredentialLines: %v", err)
	}
	if len(users) != 4 {
		t.Fatalf("users = %d, want 4: %+v", len(users), users)
	}
	if users[0].Username != "alice" || users[0].Password != "alice-password" {
		t.Fatalf("unexpected first user: %+v", users[0])
	}
	if users[1].Username != "bob" || users[1].Password != "bob-password:with:colon" {
		t.Fatalf("unexpected second user: %+v", users[1])
	}
	if users[2].Username != "" || users[2].Password != "shared-password" {
		t.Fatalf("unexpected shared user: %+v", users[2])
	}
	if users[3].PasswordHash == "" {
		t.Fatalf("expected a hash entry, got %+v", users[3])
	}
}
