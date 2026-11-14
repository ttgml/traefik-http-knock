package traefik_http_knock

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRequestScheme covers the scheme detection behind same-origin checks and
// cookie policy, including the reverse-proxy case where TLS is terminated in
// front of Traefik and only X-Forwarded-Proto carries the client scheme.
func TestRequestScheme(t *testing.T) {
	tests := []struct {
		name  string
		tls   bool
		proto string
		want  string
	}{
		{name: "plain http", want: "http"},
		{name: "tls terminated by traefik", tls: true, want: "https"},
		{name: "tls terminated upstream", proto: "https", want: "https"},
		{name: "upstream proxy appends a list", proto: "https, http", want: "https"},
		{name: "first list entry wins", proto: " http , https", want: "http"},
		{name: "unknown protocol falls back to http", proto: "ftp", want: "http"},
		{name: "empty protocol falls back to http", proto: " ", want: "http"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://example.com/private", nil)
			if tc.tls {
				req = httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)
				if req.TLS == nil {
					t.Fatal("httptest.NewRequest did not set TLS for an https target")
				}
			}
			if tc.proto != "" {
				req.Header.Set("X-Forwarded-Proto", tc.proto)
			}
			if got := requestScheme(req); got != tc.want {
				t.Fatalf("requestScheme() = %q, want %q", got, tc.want)
			}
		})
	}

	// TLS wins over a stale or spoofed X-Forwarded-Proto header.
	req := httptest.NewRequest(http.MethodGet, "https://example.com/private", nil)
	req.Header.Set("X-Forwarded-Proto", "http")
	if got := requestScheme(req); got != "https" {
		t.Fatalf("requestScheme() = %q, want https when TLS is present", got)
	}
}

// TestSameOriginPostRefererAndFetchMetadata covers the request headers that are
// used when Origin is absent, and their precedence.
func TestSameOriginPostRefererAndFetchMetadata(t *testing.T) {
	tests := []struct {
		name     string
		origin   string
		referer  string
		secFetch string
		want     bool
	}{
		{name: "no headers is allowed", want: true},
		{name: "same-origin referer", referer: "https://example.com/private", want: true},
		{name: "cross-origin referer", referer: "https://evil.example/private", want: false},
		{name: "malformed referer", referer: "not a url", want: false},
		{name: "referer without host", referer: "/private", want: false},
		{name: "origin null from a sandboxed form", origin: "null", want: false},
		{name: "origin wins over a same-origin referer", origin: "https://evil.example", referer: "https://example.com/private", want: false},
		{name: "fetch metadata none", secFetch: "none", want: true},
		{name: "fetch metadata same-site is still cross-origin", secFetch: "same-site", want: false},
		{name: "fetch metadata wins over a same-origin origin", secFetch: "cross-site", origin: "https://example.com", want: false},
		{name: "spoofed origin null with same-origin fetch metadata", origin: "null", secFetch: "same-origin", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := newRequest(http.MethodPost, "https://example.com/private", "10.2.0.30:1234")
			req.Host = "example.com"
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.referer != "" {
				req.Header.Set("Referer", tc.referer)
			}
			if tc.secFetch != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetch)
			}
			if got := sameOriginPost(req); got != tc.want {
				t.Fatalf("sameOriginPost() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestSameOriginThroughTLSTerminatingProxy proves that a login POST is accepted
// when Traefik itself receives plain HTTP but the browser talks HTTPS to a
// proxy in front of it.
func TestSameOriginThroughTLSTerminatingProxy(t *testing.T) {
	handler, _, _, _ := newPasswordHarness(t, nil)

	req := loginRequest("alice", "correct horse", "10.2.0.31:1234")
	req.TLS = nil
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Origin", "https://example.com")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 for a same-origin HTTPS proxy request (body %q)", rec.Code, rec.Body.String())
	}

	crossScheme := loginRequest("alice", "correct horse", "10.2.0.32:1234")
	crossScheme.TLS = nil
	crossScheme.Header.Set("X-Forwarded-Proto", "https")
	crossScheme.Header.Set("Origin", "http://example.com")

	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, crossScheme)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a different client scheme", rec.Code)
	}
}

func TestSameOriginURLHostAndPortMatching(t *testing.T) {
	req := newRequest(http.MethodPost, "http://example.com/private", "10.2.0.33:1234")
	req.Host = "example.com:80"

	tests := []struct {
		name   string
		origin string
		want   bool
	}{
		{name: "implicit default http port", origin: "http://example.com", want: true},
		{name: "explicit default http port", origin: "http://example.com:80", want: true},
		{name: "different port", origin: "http://example.com:8080", want: false},
		{name: "different host", origin: "http://other.example", want: false},
		{name: "different scheme", origin: "https://example.com", want: false},
		{name: "empty origin", origin: "", want: false},
		{name: "origin without scheme", origin: "example.com", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := sameOriginURL(req, tc.origin); got != tc.want {
				t.Fatalf("sameOriginURL(%q) = %v, want %v", tc.origin, got, tc.want)
			}
		})
	}

	ipv6 := newRequest(http.MethodPost, "http://[2001:db8::1]:8443/private", "10.2.0.34:1234")
	ipv6.Host = "[2001:db8::1]:8443"
	if !sameOriginURL(ipv6, "http://[2001:db8::1]:8443") {
		t.Fatal("an identical IPv6 authority must be same-origin")
	}
	if sameOriginURL(ipv6, "http://[2001:db8::2]:8443") {
		t.Fatal("a different IPv6 address must not be same-origin")
	}

	name, port := splitAuthority("[2001:db8::1]")
	if name != "2001:db8::1" || port != "" {
		t.Fatalf("splitAuthority = %q, %q, want the bracketed IPv6 host without a port", name, port)
	}
}

func TestParseSameSite(t *testing.T) {
	tests := []struct {
		in      string
		want    http.SameSite
		wantErr bool
	}{
		{in: "", want: http.SameSiteLaxMode},
		{in: "Lax", want: http.SameSiteLaxMode},
		{in: " lax ", want: http.SameSiteLaxMode},
		{in: "Strict", want: http.SameSiteStrictMode},
		{in: "NONE", want: http.SameSiteNoneMode},
		{in: "cross-site", wantErr: true},
		{in: "0", wantErr: true},
	}
	for _, tc := range tests {
		got, err := parseSameSite(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("parseSameSite(%q) = %v, want an error", tc.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("parseSameSite(%q): %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("parseSameSite(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestValidRealm(t *testing.T) {
	for _, realm := range []string{
		"test",
		"prod-1.eu_west@cluster:443/path",
		strings.Repeat("a", 128),
	} {
		if !validRealm(realm) {
			t.Errorf("validRealm(%q) = false, want true", realm)
		}
	}
	for _, realm := range []string{
		"",
		strings.Repeat("a", 129),
		"has space",
		"has\ttab",
		"has|pipe",
		"semi;colon",
		"ünïcode",
	} {
		if validRealm(realm) {
			t.Errorf("validRealm(%q) = true, want false", realm)
		}
	}
}

func TestValidKeyPrefix(t *testing.T) {
	for _, prefix := range []string{"traefik:http-knock:", "x", "前缀:", strings.Repeat("p", 256)} {
		if !validKeyPrefix(prefix) {
			t.Errorf("validKeyPrefix(%q) = false, want true", prefix)
		}
	}
	for _, prefix := range []string{"", "has space", "tab\there", "newline\nhere", "\x7fdelete", "\x00nul"} {
		if validKeyPrefix(prefix) {
			t.Errorf("validKeyPrefix(%q) = true, want false", prefix)
		}
	}
}

func TestSessionValueEdgeCases(t *testing.T) {
	if got := sessionValue(nil); got != "|" {
		t.Fatalf("sessionValue(nil) = %q, want %q", got, "|")
	}

	user := &userCredential{username: "alice", fingerprint: "abc123"}
	username, fingerprint, ok := parseSessionValue(sessionValue(user))
	if !ok || username != "alice" || fingerprint != "abc123" {
		t.Fatalf("round trip = %q, %q, %v", username, fingerprint, ok)
	}

	if _, _, ok := parseSessionValue("no-separator"); ok {
		t.Fatal("parseSessionValue accepted a value without a separator")
	}
	username, fingerprint, ok = parseSessionValue("|only-fingerprint")
	if !ok || username != "" || fingerprint != "only-fingerprint" {
		t.Fatalf("shared session value parsed as %q, %q, %v", username, fingerprint, ok)
	}
	_, fingerprint, ok = parseSessionValue("alice|fp|extra")
	if !ok || fingerprint != "fp|extra" {
		t.Fatalf("only the first separator must split the value, got %q", fingerprint)
	}
}

func TestFindByFingerprint(t *testing.T) {
	var missing *userSet
	if _, ok := missing.findByFingerprint("alice", "fp"); ok {
		t.Fatal("a nil user set must not resolve a fingerprint")
	}

	users, err := buildUserSet([]User{
		{Username: "alice", Password: "alice-password"},
		{Password: "shared-password"},
	}, "", "")
	if err != nil {
		t.Fatalf("buildUserSet: %v", err)
	}

	alice := users.byName["alice"]
	if alice == nil {
		t.Fatal("alice is missing from the user set")
	}
	if got, ok := users.findByFingerprint("alice", alice.fingerprint); !ok || got != alice {
		t.Fatal("the matching named user was not resolved")
	}
	if _, ok := users.findByFingerprint("alice", "wrong-fingerprint"); ok {
		t.Fatal("a wrong fingerprint resolved the named user")
	}
	if _, ok := users.findByFingerprint("nobody", alice.fingerprint); ok {
		t.Fatal("an unknown username resolved a fingerprint")
	}

	if len(users.shared) != 1 {
		t.Fatalf("shared users = %d, want 1", len(users.shared))
	}
	shared := users.shared[0]
	if got, ok := users.findByFingerprint("", shared.fingerprint); !ok || got != shared {
		t.Fatal("the matching shared password was not resolved")
	}
	if _, ok := users.findByFingerprint("", "wrong-fingerprint"); ok {
		t.Fatal("a wrong fingerprint resolved a shared password")
	}
}
