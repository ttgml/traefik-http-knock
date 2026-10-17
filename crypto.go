package traefik_http_knock

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// This file contains the cryptographic helpers used by password and session
// authentication. Everything here is standard library only so the plugin stays
// loadable by Yaegi.
//
// The code deliberately avoids errors.Is/errors.As and comma-separated case
// expressions; see yaegi_compat_test.go.

const (
	pbkdf2Algorithm = "pbkdf2-sha256"
	// DefaultPBKDF2Iterations is used by HashPassword when no explicit
	// iteration count is given. Verification uses the count stored in the hash,
	// so this value can be raised later without invalidating existing hashes.
	DefaultPBKDF2Iterations = 120000

	minPBKDF2Iterations = 10000
	maxPBKDF2Iterations = 10000000

	pbkdf2SaltLength = 16
	pbkdf2KeyLength  = 32

	sessionIDLength = 32
)

// HashPassword derives a PBKDF2-HMAC-SHA256 hash in the format
//
//	pbkdf2-sha256$<iterations>$<base64 salt>$<base64 hash>
//
// The salt and hash use standard base64 (with padding) so the value stays a
// single printable field in YAML, a credentials file or a Secret.
func HashPassword(password string, iterations int) (string, error) {
	if iterations == 0 {
		iterations = DefaultPBKDF2Iterations
	}
	if iterations < minPBKDF2Iterations {
		return "", fmt.Errorf("http-knock: pbkdf2 iterations must be at least %d", minPBKDF2Iterations)
	}
	if iterations > maxPBKDF2Iterations {
		return "", fmt.Errorf("http-knock: pbkdf2 iterations must be at most %d", maxPBKDF2Iterations)
	}
	if password == "" {
		return "", errors.New("http-knock: password must not be empty")
	}

	salt := make([]byte, pbkdf2SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("http-knock: cannot generate password salt: %w", err)
	}
	hash := pbkdf2SHA256([]byte(password), salt, iterations, pbkdf2KeyLength)

	return fmt.Sprintf("%s$%d$%s$%s",
		pbkdf2Algorithm,
		iterations,
		base64.StdEncoding.EncodeToString(salt),
		base64.StdEncoding.EncodeToString(hash),
	), nil
}

// passwordHash is the parsed form of a pbkdf2-sha256 hash.
type passwordHash struct {
	iterations int
	salt       []byte
	expected   []byte
}

// parsePasswordHash validates and decodes a stored PBKDF2 hash. A malformed
// hash is a configuration error, never a reason to let a request through.
func parsePasswordHash(value string) (*passwordHash, error) {
	value = strings.TrimSpace(value)
	parts := strings.Split(value, "$")
	if len(parts) != 4 {
		return nil, errors.New("http-knock: password hash must have the form pbkdf2-sha256$iterations$salt$hash")
	}
	if parts[0] != pbkdf2Algorithm {
		return nil, fmt.Errorf("http-knock: unsupported password hash algorithm %q", parts[0])
	}

	iterations, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("http-knock: invalid pbkdf2 iteration count %q", parts[1])
	}
	if iterations < minPBKDF2Iterations {
		return nil, fmt.Errorf("http-knock: pbkdf2 iterations must be at least %d", minPBKDF2Iterations)
	}
	if iterations > maxPBKDF2Iterations {
		return nil, fmt.Errorf("http-knock: pbkdf2 iterations must be at most %d", maxPBKDF2Iterations)
	}

	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("http-knock: password hash salt is not valid base64")
	}
	if len(salt) < 8 {
		return nil, errors.New("http-knock: password hash salt is too short")
	}

	expected, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, errors.New("http-knock: password hash value is not valid base64")
	}
	if len(expected) != pbkdf2KeyLength {
		return nil, fmt.Errorf("http-knock: password hash must be %d bytes, got %d", pbkdf2KeyLength, len(expected))
	}

	return &passwordHash{iterations: iterations, salt: salt, expected: expected}, nil
}

// verifyPassword derives the hash with the stored parameters and compares it in
// constant time.
func (h *passwordHash) verifyPassword(password string) bool {
	if h == nil || password == "" {
		return false
	}
	actual := pbkdf2SHA256([]byte(password), h.salt, h.iterations, len(h.expected))
	return constantTimeEqualBytes(actual, h.expected)
}

// pbkdf2SHA256 implements PBKDF2 (RFC 8018) with HMAC-SHA256. Only the standard
// library is used so the plugin has no third-party dependency.
func pbkdf2SHA256(password, salt []byte, iterations, keyLength int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLength := prf.Size()
	blockCount := (keyLength + hashLength - 1) / hashLength

	derived := make([]byte, 0, blockCount*hashLength)
	var blockIndex [4]byte
	var u [sha256.Size]byte
	var t [sha256.Size]byte

	for block := 1; block <= blockCount; block++ {
		prf.Reset()
		_, _ = prf.Write(salt)
		binary.BigEndian.PutUint32(blockIndex[:], uint32(block))
		_, _ = prf.Write(blockIndex[:])

		copy(u[:], prf.Sum(nil))
		copy(t[:], u[:])

		for i := 1; i < iterations; i++ {
			prf.Reset()
			_, _ = prf.Write(u[:])
			copy(u[:], prf.Sum(nil))
			for j := 0; j < len(t); j++ {
				t[j] ^= u[j]
			}
		}
		derived = append(derived, t[:]...)
	}

	return derived[:keyLength]
}

// newSessionID returns a 256-bit random session identifier encoded with
// URL-safe base64 (no padding) so it is safe in a cookie or Authorization
// header.
func newSessionID() (string, error) {
	raw := make([]byte, sessionIDLength)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("http-knock: cannot generate session id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// signSessionToken builds a compact, HMAC-authenticated session token:
//
//	v1.<session-id>.<hmac>
//
// The HMAC covers the realm and the session id, so a token issued by one
// middleware cannot be replayed against another even when they share a Redis
// database or a cookie secret.
func signSessionToken(secret []byte, realm, sessionID string) string {
	signature := sessionTokenSignature(secret, realm, sessionID)
	return "v1." + sessionID + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// parseSessionToken verifies the token format and HMAC and returns the session
// id. The signature comparison is constant time.
func parseSessionToken(secret []byte, realm, token string) (string, bool) {
	sessionID, signature, ok := splitSessionToken(token)
	if !ok {
		return "", false
	}

	rawID, err := base64.RawURLEncoding.DecodeString(sessionID)
	if err != nil || len(rawID) != sessionIDLength {
		return "", false
	}
	rawSignature, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return "", false
	}

	expected := sessionTokenSignature(secret, realm, sessionID)
	if !constantTimeEqualBytes(rawSignature, expected) {
		return "", false
	}
	return sessionID, true
}

func splitSessionToken(token string) (string, string, bool) {
	first := strings.IndexByte(token, '.')
	if first < 0 {
		return "", "", false
	}
	if token[:first] != "v1" {
		return "", "", false
	}
	rest := token[first+1:]
	second := strings.IndexByte(rest, '.')
	if second < 0 {
		return "", "", false
	}
	sessionID := rest[:second]
	signature := rest[second+1:]
	if sessionID == "" || signature == "" || strings.IndexByte(signature, '.') >= 0 {
		return "", "", false
	}
	return sessionID, signature, true
}

func sessionTokenSignature(secret []byte, realm, sessionID string) []byte {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(realm))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(sessionID))
	return mac.Sum(nil)
}

// sha256Hex returns the hex-encoded SHA-256 digest of value. It is used for
// Redis key material and credential fingerprints; no secret is stored in
// plaintext in Redis keys.
func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

// constantTimeEqualBytes compares two byte slices without leaking the position
// of the first difference. Lengths are public information.
func constantTimeEqualBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

// validUsername keeps usernames safe for the compact session value stored in
// Redis ("username|fingerprint") and for HTTP Basic auth.
func validUsername(username string) bool {
	if len(username) > 64 {
		return false
	}
	for i := 0; i < len(username); i++ {
		c := username[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '.':
		case c == '_':
		case c == '-':
		case c == '@':
		default:
			return false
		}
	}
	return true
}
