package traefik_http_knock

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestLoginRejectsCrossOriginPost(t *testing.T) {
	handler, _, _, _ := newPasswordHarness(t, nil)

	tests := []struct {
		name       string
		origin     string
		secFetch   string
		wantStatus int
	}{
		{name: "cross-origin form", origin: "https://evil.example", wantStatus: http.StatusForbidden},
		{name: "cross-site fetch metadata", secFetch: "cross-site", wantStatus: http.StatusForbidden},
		{name: "same-site but cross-origin", origin: "https://sub.example.com", wantStatus: http.StatusForbidden},
		{name: "same-origin form", origin: "https://example.com", wantStatus: http.StatusNoContent},
		{name: "same-origin fetch metadata", secFetch: "same-origin", wantStatus: http.StatusNoContent},
		{name: "non-browser client", wantStatus: http.StatusNoContent},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := loginRequest("alice", "correct horse", "10.2.0.1:1234")
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.secFetch != "" {
				req.Header.Set("Sec-Fetch-Site", tc.secFetch)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestCrossOriginLogoutKeepsIPGrant(t *testing.T) {
	handler, _, srv, _ := newPasswordHarness(t, func(c *Config) {
		c.GrantMode = GrantModeIP
	})

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, loginRequest("alice", "correct horse", "10.2.0.2:1234"))
	if login.Code != http.StatusNoContent {
		t.Fatalf("login status = %d, want 204", login.Code)
	}
	key := ipGrantKey(DefaultKeyPrefix, "test", "10.2.0.2")
	if !srv.get(key) {
		t.Fatal("missing IP grant after login")
	}

	logout := logoutRequest("10.2.0.2:1234", "", "")
	logout.Header.Set("Origin", "https://evil.example")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, logout)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin logout status = %d, want 403", rec.Code)
	}
	if !srv.get(key) {
		t.Fatal("a cross-origin logout must not delete the IP grant")
	}
}

func TestIPGrantModeDoesNotIssueOrAcceptSessions(t *testing.T) {
	handler, _, _, _ := newPasswordHarness(t, func(c *Config) {
		c.GrantMode = GrantModeIP
	})
	m := handler.(*middleware)

	req := loginRequest("alice", "correct horse", "10.2.0.3:1234")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("JSON login status = %d, want 200", rec.Code)
	}
	var response loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if !response.OK || response.Token != "" {
		t.Fatalf("grantMode ip must not issue a token: %+v", response)
	}

	// Even a session minted directly (for example by an older configuration)
	// must not authorize a request while grantMode is ip.
	user, ok := m.cfg.users.authenticate("alice", "correct horse")
	if !ok {
		t.Fatal("cannot resolve test user")
	}
	token, err := m.createSession(user)
	if err != nil {
		t.Fatalf("createSession: %v", err)
	}

	protected := newRequest(http.MethodGet, "https://example.com/private", "10.2.0.4:1234")
	protected.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, protected)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("Bearer in grantMode ip status = %d, want 403", rec.Code)
	}
}

func TestIPGrantRevokedWhenPasswordChanges(t *testing.T) {
	srv := startFakeRedis(t)

	newHandler := func(password string) http.Handler {
		cfg := CreateConfig()
		cfg.KnockPath = testKnockPath
		cfg.RedisAddr = srv.addr()
		cfg.AuthMode = AuthModePassword
		cfg.GrantMode = GrantModeIP
		cfg.Realm = "test"
		cfg.Users = []User{{Username: "alice", Password: password}}
		cfg.CookieSecret = testCookieSecret
		handler, err := New(context.Background(), &recordingBackend{}, cfg, "test")
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		t.Cleanup(func() {
			if closer, ok := handler.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
		})
		return handler
	}

	oldHandler := newHandler("old-password")
	login := httptest.NewRecorder()
	oldHandler.ServeHTTP(login, loginRequest("alice", "old-password", "10.2.0.5:1234"))
	if login.Code != http.StatusNoContent {
		t.Fatalf("login status = %d, want 204", login.Code)
	}

	key := ipGrantKey(DefaultKeyPrefix, "test", "10.2.0.5")
	if !srv.get(key) {
		t.Fatal("missing IP grant after login")
	}

	// A new configuration changes the password fingerprint. The IP grant is
	// anonymous, so it must be checked against the current credential set.
	rotated := newHandler("new-password")
	req := newRequest(http.MethodGet, "https://example.com/private", "10.2.0.5:5678")
	rec := httptest.NewRecorder()
	rotated.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stale IP grant after password change = %d, want 403", rec.Code)
	}
	if srv.get(key) {
		t.Fatal("stale IP grant was not deleted")
	}
}

func TestBasicAuthRespectsConcurrencyLimit(t *testing.T) {
	handler, _, _, _ := newPasswordHarness(t, func(c *Config) {
		c.AuthMode = AuthModeBasic
		c.GrantMode = ""
		c.CookieSecret = ""
		c.Users = []User{{Username: "api", Password: "api-password"}}
		c.MaxConcurrentLogins = 1
	})
	m := handler.(*middleware)

	// Occupy the only KDF slot, then prove Basic returns 429 instead of
	// starting another expensive verification.
	m.loginSlots <- struct{}{}
	defer func() { <-m.loginSlots }()

	req := newRequest(http.MethodGet, "https://example.com/private", "10.2.0.6:1234")
	req.SetBasicAuth("api", "api-password")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 while the KDF slot is busy", rec.Code)
	}
}

func TestLoadSecretFileWinsOverMissingEnvironment(t *testing.T) {
	dir := t.TempDir()
	file := dir + "/cookie-secret"
	want := "0123456789abcdef0123456789abcdef"
	if err := os.WriteFile(file, []byte(want+"\n"), 0600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	t.Setenv("HTTP_KNOCK_TEST_EMPTY_SECRET", "")

	secret, err := loadSecret("inline", file, "HTTP_KNOCK_TEST_EMPTY_SECRET", "cookieSecret")
	if err != nil {
		t.Fatalf("loadSecret: %v", err)
	}
	if string(secret) != want {
		t.Fatalf("secret = %q, want the file value", secret)
	}
}

func TestEndpointPathRejectsUnsafeValues(t *testing.T) {
	for _, path := range []string{
		"//evil.example/login",
		`/\evil.example/login`,
		"/has space",
		"/has%20space",
		"/has\tcontrol",
	} {
		cfg := CreateConfig()
		cfg.KnockPath = testKnockPath
		cfg.RedisAddr = "redis:6379"
		cfg.AuthMode = AuthModePassword
		cfg.LoginPath = path
		cfg.Users = []User{{Username: "alice", Password: "secret"}}
		cfg.CookieSecret = testCookieSecret
		if err := cfg.Validate(); err == nil {
			t.Errorf("loginPath %q was accepted, want an error", path)
		}
	}
}

func TestPathIPGrantRequiresLegacyMarker(t *testing.T) {
	handler, backend, srv := newHarness(t, nil)
	ip := "10.2.0.7"
	key := testKey(ip)

	// A password-style value (or any non-marker value) must not authorize a
	// path-mode request, even if an operator shares a realm between modes.
	srv.set(key, "alice|deadbeef", time.Now().Add(time.Hour))
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, newRequest(http.MethodGet, "https://example.com/private", ip+":1234"))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-marker grant status = %d, want 403", denied.Code)
	}
	if srv.get(key) {
		t.Fatal("invalid path-mode grant was not deleted")
	}
	if backend.callCount() != 0 {
		t.Fatal("invalid grant reached the backend")
	}

	srv.set(key, knockValue, time.Now().Add(time.Hour))
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, newRequest(http.MethodGet, "https://example.com/private", ip+":1234"))
	if allowed.Code != http.StatusOK {
		t.Fatalf("legacy marker status = %d, want 200", allowed.Code)
	}
}
