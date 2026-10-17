package traefik_http_knock

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

const testCookieSecret = "0123456789abcdef0123456789abcdef"

func newPasswordHarness(t *testing.T, mutate func(*Config)) (http.Handler, *recordingBackend, *fakeRedisServer, *Config) {
	t.Helper()

	srv := startFakeRedis(t)
	cfg := CreateConfig()
	cfg.KnockPath = testKnockPath
	cfg.RedisAddr = srv.addr()
	cfg.AuthMode = AuthModePassword
	cfg.Users = []User{{Username: "alice", Password: "correct horse"}}
	cfg.CookieSecret = testCookieSecret
	cfg.CookieName = "http-knock-test"
	cfg.MaxLoginAttempts = 5
	cfg.LoginWindow = "15m"
	cfg.MaxConcurrentLogins = 2
	if mutate != nil {
		mutate(cfg)
	}

	backend := &recordingBackend{}
	handler, err := New(context.Background(), backend, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if closer, ok := handler.(interface{ Close() error }); ok {
		t.Cleanup(func() { _ = closer.Close() })
	}
	return handler, backend, srv, cfg
}

func loginRequest(username, password, remoteAddr string) *http.Request {
	form := url.Values{}
	form.Set("username", username)
	form.Set("password", password)
	req := httptest.NewRequest(http.MethodPost, "https://example.com"+testKnockPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remoteAddr
	return req
}

func logoutRequest(remoteAddr, cookieName, token string) *http.Request {
	form := url.Values{}
	form.Set("action", "logout")
	req := httptest.NewRequest(http.MethodPost, "https://example.com"+testKnockPath, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = remoteAddr
	if token != "" {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: token})
	}
	return req
}

func cookieFrom(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

func addCookie(req *http.Request, cookie *http.Cookie) {
	if cookie != nil {
		req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	}
}

func TestPasswordLoginCreatesRedisSession(t *testing.T) {
	handler, backend, srv, cfg := newPasswordHarness(t, nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, loginRequest("alice", "correct horse", "10.1.0.1:1234"))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("login status = %d, want 204 (body %q)", rec.Code, rec.Body.String())
	}
	if backend.callCount() != 0 {
		t.Fatal("the login request must never be forwarded to the backend")
	}
	cookie := cookieFrom(rec, cfg.CookieName)
	if cookie == nil {
		t.Fatalf("login did not set the session cookie, headers: %v", rec.Header())
	}
	if !cookie.HttpOnly {
		t.Fatal("session cookie must be HttpOnly")
	}
	if !cookie.Secure {
		t.Fatal("session cookie must be Secure by default")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite = %v, want Lax", cookie.SameSite)
	}
	if cookie.Path != "/" {
		t.Fatalf("cookie Path = %q, want /", cookie.Path)
	}

	sessionID, ok := parseSessionToken([]byte(testCookieSecret), "test", cookie.Value)
	if !ok {
		t.Fatal("cookie value is not a valid signed session token")
	}
	key := sessionRedisKey(DefaultKeyPrefix, "test", sessionID)
	value, ok := srv.getValue(key)
	if !ok {
		t.Fatalf("expected session key %q in Redis", key)
	}
	if !strings.HasPrefix(value, "alice|") {
		t.Fatalf("session value = %q, want alice|fingerprint", value)
	}

	protected := newRequest(http.MethodGet, "https://example.com/private", "10.1.0.1:5678")
	addCookie(protected, cookie)
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, protected)
	if allowed.Code != http.StatusOK {
		t.Fatalf("protected status = %d, want 200", allowed.Code)
	}
	if backend.callCount() != 1 {
		t.Fatalf("backend calls = %d, want 1", backend.callCount())
	}

	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, newRequest(http.MethodGet, "https://example.com/private", "10.1.0.1:5678"))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("request without cookie status = %d, want 403", denied.Code)
	}
}

func TestPasswordLoginWrongPasswordIsCounted(t *testing.T) {
	handler, backend, srv, cfg := newPasswordHarness(t, nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, loginRequest("alice", "wrong", "10.1.0.2:1234"))

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if cookieFrom(rec, cfg.CookieName) != nil {
		t.Fatal("a failed login must not set a session cookie")
	}
	if backend.callCount() != 0 {
		t.Fatal("a failed login must not reach the backend")
	}
	key := loginFailureKey(DefaultKeyPrefix, "test", "10.1.0.2")
	if value, ok := srv.getValue(key); !ok || value != "1" {
		t.Fatalf("failure counter = %q, %v; want 1, true", value, ok)
	}
}

func TestPasswordLoginSupportsMultipleUsers(t *testing.T) {
	handler, backend, srv, cfg := newPasswordHarness(t, func(c *Config) {
		c.Users = []User{
			{Username: "alice", Password: "alice-password"},
			{Username: "bob", Password: "bob-password"},
		}
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, loginRequest("bob", "bob-password", "10.1.0.3:1234"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login status = %d, want 204", rec.Code)
	}
	cookie := cookieFrom(rec, cfg.CookieName)
	if cookie == nil {
		t.Fatal("missing session cookie")
	}
	sessionID, ok := parseSessionToken([]byte(testCookieSecret), "test", cookie.Value)
	if !ok {
		t.Fatal("invalid session token")
	}
	value, ok := srv.getValue(sessionRedisKey(DefaultKeyPrefix, "test", sessionID))
	if !ok || !strings.HasPrefix(value, "bob|") {
		t.Fatalf("session value = %q, want bob|...", value)
	}

	protected := newRequest(http.MethodGet, "https://example.com/private", "10.1.0.3:5678")
	addCookie(protected, cookie)
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, protected)
	if allowed.Code != http.StatusOK {
		t.Fatalf("protected status = %d, want 200", allowed.Code)
	}
	if backend.callCount() != 1 {
		t.Fatalf("backend calls = %d, want 1", backend.callCount())
	}
}

func TestPasswordLoginIPGrantMode(t *testing.T) {
	handler, backend, srv, cfg := newPasswordHarness(t, func(c *Config) {
		c.GrantMode = GrantModeIP
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, loginRequest("alice", "correct horse", "10.1.0.4:1234"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login status = %d, want 204", rec.Code)
	}
	if cookieFrom(rec, cfg.CookieName) != nil {
		t.Fatal("grantMode ip must not issue a session cookie for an HTML login")
	}
	if !srv.get(ipGrantKey(DefaultKeyPrefix, "test", "10.1.0.4")) {
		t.Fatalf("missing IP grant, commands: %v", srv.recordedCommands())
	}

	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, newRequest(http.MethodGet, "https://example.com/private", "10.1.0.4:5678"))
	if allowed.Code != http.StatusOK {
		t.Fatalf("protected status = %d, want 200", allowed.Code)
	}
	if backend.callCount() != 1 {
		t.Fatalf("backend calls = %d, want 1", backend.callCount())
	}

	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, newRequest(http.MethodGet, "https://example.com/private", "10.1.0.5:5678"))
	if denied.Code != http.StatusForbidden {
		t.Fatalf("other IP status = %d, want 403", denied.Code)
	}
}

func TestPasswordLoginBothGrants(t *testing.T) {
	handler, _, srv, cfg := newPasswordHarness(t, func(c *Config) {
		c.GrantMode = GrantModeBoth
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, loginRequest("alice", "correct horse", "10.1.0.6:1234"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("login status = %d, want 204", rec.Code)
	}
	cookie := cookieFrom(rec, cfg.CookieName)
	if cookie == nil {
		t.Fatal("grantMode both must issue a session cookie")
	}
	if !srv.get(ipGrantKey(DefaultKeyPrefix, "test", "10.1.0.6")) {
		t.Fatal("grantMode both must also issue an IP grant")
	}

	// Cookie-only and IP-only requests both work.
	cookieOnly := newRequest(http.MethodGet, "https://example.com/private", "10.1.0.6:5678")
	addCookie(cookieOnly, cookie)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, cookieOnly)
	if rec.Code != http.StatusOK {
		t.Fatalf("cookie request status = %d, want 200", rec.Code)
	}

	ipOnly := httptest.NewRecorder()
	handler.ServeHTTP(ipOnly, newRequest(http.MethodGet, "https://example.com/private", "10.1.0.6:9999"))
	if ipOnly.Code != http.StatusOK {
		t.Fatalf("IP request status = %d, want 200", ipOnly.Code)
	}
}

func TestLogoutRevokesSession(t *testing.T) {
	handler, _, srv, cfg := newPasswordHarness(t, nil)

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, loginRequest("alice", "correct horse", "10.1.0.7:1234"))
	cookie := cookieFrom(login, cfg.CookieName)
	if cookie == nil {
		t.Fatal("missing session cookie")
	}
	sessionID, _ := parseSessionToken([]byte(testCookieSecret), "test", cookie.Value)
	key := sessionRedisKey(DefaultKeyPrefix, "test", sessionID)

	logout := httptest.NewRecorder()
	handler.ServeHTTP(logout, logoutRequest("10.1.0.7:1234", cfg.CookieName, cookie.Value))
	if logout.Code != http.StatusNoContent && logout.Code != http.StatusSeeOther {
		t.Fatalf("logout status = %d, want 204/303", logout.Code)
	}
	if srv.get(key) {
		t.Fatal("logout must delete the Redis session")
	}

	replay := newRequest(http.MethodGet, "https://example.com/private", "10.1.0.7:1234")
	addCookie(replay, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, replay)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("stolen/logout cookie status = %d, want 403", rec.Code)
	}
}

func TestSessionCookieIsUnusableWhenRedisIsDown(t *testing.T) {
	handler, backend, srv, cfg := newPasswordHarness(t, func(c *Config) {
		// Even with failClosed: false, a password session must not turn into a
		// fail-open bypass while the session store is unavailable.
		c.FailClosed = boolPtr(false)
	})

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, loginRequest("alice", "correct horse", "10.1.0.8:1234"))
	cookie := cookieFrom(login, cfg.CookieName)
	if cookie == nil {
		t.Fatal("missing session cookie")
	}

	srv.Close()

	req := newRequest(http.MethodGet, "https://example.com/private", "10.1.0.8:1234")
	addCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when Redis is down", rec.Code)
	}
	if backend.callCount() != 0 {
		t.Fatal("a session request must not reach the backend while Redis is down")
	}
}

func TestPasswordLoginRateLimit(t *testing.T) {
	handler, _, srv, _ := newPasswordHarness(t, func(c *Config) {
		c.MaxLoginAttempts = 2
		c.LoginWindow = "1m"
	})

	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, loginRequest("alice", "wrong", "10.1.0.9:1234"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d, want 401", i+1, rec.Code)
		}
	}

	blocked := httptest.NewRecorder()
	handler.ServeHTTP(blocked, loginRequest("alice", "correct horse", "10.1.0.9:1234"))
	if blocked.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 even with a correct password", blocked.Code)
	}
	if got := blocked.Header().Get("Retry-After"); got == "" {
		t.Fatal("429 response must include Retry-After")
	}

	// Simulate expiry of the failure window.
	srv.expireAll()
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, loginRequest("alice", "correct horse", "10.1.0.9:1234"))
	if allowed.Code != http.StatusNoContent {
		t.Fatalf("status after window expiry = %d, want 204", allowed.Code)
	}
}

func TestJSONLoginReturnsBearerToken(t *testing.T) {
	handler, backend, _, _ := newPasswordHarness(t, nil)

	req := loginRequest("alice", "correct horse", "10.1.0.10:1234")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("JSON login status = %d, want 200 (body %q)", rec.Code, rec.Body.String())
	}

	var response loginResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !response.OK || response.Token == "" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Fatalf("Content-Type = %q, want application/json", got)
	}

	protected := newRequest(http.MethodGet, "https://example.com/private", "10.1.0.10:5678")
	protected.Header.Set("Authorization", "Bearer "+response.Token)
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, protected)
	if allowed.Code != http.StatusOK {
		t.Fatalf("bearer request status = %d, want 200", allowed.Code)
	}
	if backend.callCount() != 1 {
		t.Fatalf("backend calls = %d, want 1", backend.callCount())
	}

	logout := logoutRequest("10.1.0.10:1234", "", "")
	logout.Header.Set("Authorization", "Bearer "+response.Token)
	logoutRec := httptest.NewRecorder()
	handler.ServeHTTP(logoutRec, logout)
	if logoutRec.Code != http.StatusNoContent && logoutRec.Code != http.StatusSeeOther {
		t.Fatalf("logout status = %d, want 204/303", logoutRec.Code)
	}

	replay := newRequest(http.MethodGet, "https://example.com/private", "10.1.0.10:5678")
	replay.Header.Set("Authorization", "Bearer "+response.Token)
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, replay)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("revoked bearer status = %d, want 401", denied.Code)
	}
}

func TestBasicAuthMode(t *testing.T) {
	handler, backend, _, _ := newPasswordHarness(t, func(c *Config) {
		c.AuthMode = AuthModeBasic
		c.GrantMode = ""
		c.CookieSecret = ""
		c.Users = []User{{Username: "api", Password: "api-password"}}
	})

	challenge := httptest.NewRecorder()
	handler.ServeHTTP(challenge, newRequest(http.MethodGet, "https://example.com/private", "10.1.0.11:1234"))
	if challenge.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", challenge.Code)
	}
	if got := challenge.Header().Get("WWW-Authenticate"); !strings.HasPrefix(got, "Basic ") {
		t.Fatalf("WWW-Authenticate = %q, want Basic challenge", got)
	}
	if backend.callCount() != 0 {
		t.Fatal("unauthenticated request must not reach the backend")
	}

	req := newRequest(http.MethodGet, "https://example.com/private", "10.1.0.11:1234")
	req.SetBasicAuth("api", "api-password")
	allowed := httptest.NewRecorder()
	handler.ServeHTTP(allowed, req)
	if allowed.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d, want 200", allowed.Code)
	}
	if backend.callCount() != 1 {
		t.Fatalf("backend calls = %d, want 1", backend.callCount())
	}

	bad := newRequest(http.MethodGet, "https://example.com/private", "10.1.0.11:1234")
	bad.SetBasicAuth("api", "wrong")
	denied := httptest.NewRecorder()
	handler.ServeHTTP(denied, bad)
	if denied.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want 401", denied.Code)
	}
}

func TestLoginPageAndLogoutForm(t *testing.T) {
	handler, _, _, _ := newPasswordHarness(t, nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com"+testKnockPath, "10.1.0.12:1234"))
	if rec.Code != http.StatusOK {
		t.Fatalf("login page status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "<form") {
		t.Fatal("login page does not contain a form")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got == "" {
		t.Fatal("login page must set Content-Security-Policy")
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("X-Frame-Options = %q, want DENY", got)
	}
}

func TestRealmIsolation(t *testing.T) {
	srv := startFakeRedis(t)
	backendA := &recordingBackend{}
	backendB := &recordingBackend{}

	makeHandler := func(name, realm string, backend http.Handler) http.Handler {
		cfg := CreateConfig()
		cfg.KnockPath = testKnockPath
		cfg.RedisAddr = srv.addr()
		cfg.AuthMode = AuthModePassword
		cfg.Realm = realm
		cfg.Users = []User{{Username: "alice", Password: "correct horse"}}
		cfg.CookieSecret = testCookieSecret
		// Same cookie name on purpose: realm must still isolate the token.
		cfg.CookieName = "shared-knock"
		handler, err := New(context.Background(), backend, cfg, name)
		if err != nil {
			t.Fatalf("New(%s): %v", name, err)
		}
		t.Cleanup(func() {
			if closer, ok := handler.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
		})
		return handler
	}

	handlerA := makeHandler("app-a", "app-a", backendA)
	handlerB := makeHandler("app-b", "app-b", backendB)

	login := httptest.NewRecorder()
	handlerA.ServeHTTP(login, loginRequest("alice", "correct horse", "10.1.0.13:1234"))
	cookie := cookieFrom(login, "shared-knock")
	if cookie == nil {
		t.Fatal("missing cookie from app-a")
	}

	cross := newRequest(http.MethodGet, "https://example.com/private", "10.1.0.13:1234")
	addCookie(cross, cookie)
	crossRec := httptest.NewRecorder()
	handlerB.ServeHTTP(crossRec, cross)
	if crossRec.Code != http.StatusForbidden {
		t.Fatalf("cross-realm cookie status = %d, want 403", crossRec.Code)
	}

	if !srv.get(scopedKey(DefaultKeyPrefix, "app-a", "session", sha256Hex(mustSessionID(t, cookie.Value)))) {
		t.Fatal("missing realm-scoped session key for app-a")
	}
}

func mustSessionID(t *testing.T, token string) string {
	t.Helper()
	sessionID, ok := parseSessionToken([]byte(testCookieSecret), "app-a", token)
	if !ok {
		t.Fatal("invalid session token")
	}
	return sessionID
}

func TestPrivateResponseHeadersOverrideBackendCache(t *testing.T) {
	cacheBackend := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Cache-Control", "public, max-age=3600")
		rw.Header().Set("Vary", "Accept-Encoding")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write([]byte("protected"))
	})

	srv := startFakeRedis(t)
	cfg := CreateConfig()
	cfg.KnockPath = testKnockPath
	cfg.RedisAddr = srv.addr()
	cfg.AuthMode = AuthModePassword
	cfg.Users = []User{{Username: "alice", Password: "correct horse"}}
	cfg.CookieSecret = testCookieSecret
	cfg.CookieName = "http-knock-test"

	handler, err := New(context.Background(), cacheBackend, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() {
		if closer, ok := handler.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	})

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, loginRequest("alice", "correct horse", "10.1.0.14:1234"))
	cookie := cookieFrom(login, cfg.CookieName)

	req := newRequest(http.MethodGet, "https://example.com/private", "10.1.0.14:1234")
	addCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "private" {
		t.Fatalf("Cache-Control = %q, want private", got)
	}
	vary := strings.Join(rec.Header().Values("Vary"), ",")
	if !strings.Contains(vary, "Cookie") || !strings.Contains(vary, "Authorization") {
		t.Fatalf("Vary = %q, want Cookie and Authorization", vary)
	}
	if !strings.Contains(vary, "Accept-Encoding") {
		t.Fatalf("Vary = %q, want existing Accept-Encoding preserved", vary)
	}
}

func TestForwardUserHeaderCannotBeSpoofed(t *testing.T) {
	handler, backend, _, cfg := newPasswordHarness(t, func(c *Config) {
		c.ForwardUserHeader = "X-Knock-User"
	})

	login := httptest.NewRecorder()
	handler.ServeHTTP(login, loginRequest("alice", "correct horse", "10.1.0.15:1234"))
	cookie := cookieFrom(login, cfg.CookieName)

	req := newRequest(http.MethodGet, "https://example.com/private", "10.1.0.15:1234")
	req.Header.Set("X-Knock-User", "attacker")
	addCookie(req, cookie)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	_, _, _, _, headers := backend.snapshot()
	if got := headers.Get("X-Knock-User"); got != "alice" {
		t.Fatalf("forwarded user = %q, want alice", got)
	}
}

func TestPasswordConfigValidation(t *testing.T) {
	valid := func() *Config {
		cfg := CreateConfig()
		cfg.KnockPath = testKnockPath
		cfg.RedisAddr = "redis:6379"
		cfg.AuthMode = AuthModePassword
		cfg.Users = []User{{Username: "alice", Password: "secret"}}
		cfg.CookieSecret = testCookieSecret
		return cfg
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "valid password config"},
		{name: "valid basic config without redis", mutate: func(c *Config) {
			c.AuthMode = AuthModeBasic
			c.GrantMode = ""
			c.RedisAddr = ""
			c.CookieSecret = ""
		}},
		{name: "missing users", mutate: func(c *Config) { c.Users = nil }, wantErr: "at least one user"},
		{name: "missing cookie secret", mutate: func(c *Config) { c.CookieSecret = "" }, wantErr: "cookieSecret"},
		{name: "short cookie secret", mutate: func(c *Config) { c.CookieSecret = "short" }, wantErr: "at least 32"},
		{name: "invalid hash", mutate: func(c *Config) {
			c.Users = []User{{Username: "alice", PasswordHash: "not-a-hash"}}
		}, wantErr: "password hash"},
		{name: "duplicate username", mutate: func(c *Config) {
			c.Users = []User{{Username: "alice", Password: "a"}, {Username: "alice", Password: "b"}}
		}, wantErr: "duplicate username"},
		{name: "insecure host cookie", mutate: func(c *Config) {
			c.CookieName = "__Host-knock"
			c.CookieSecure = boolPtr(false)
		}, wantErr: "__Host-"},
		{name: "same site none without secure", mutate: func(c *Config) {
			c.CookieSameSite = "None"
			c.CookieSecure = boolPtr(false)
		}, wantErr: "None requires"},
		{name: "invalid cookie name", mutate: func(c *Config) { c.CookieName = "bad cookie" }, wantErr: "cookie name"},
		{name: "path mode with users", mutate: func(c *Config) {
			c.AuthMode = AuthModePath
			c.GrantMode = ""
		}, wantErr: "require authMode"},
		{name: "password mode without grant", mutate: func(c *Config) { c.GrantMode = GrantModeNone }, wantErr: "requires grantMode"},
		{name: "basic mode with grant", mutate: func(c *Config) {
			c.AuthMode = AuthModeBasic
			c.GrantMode = GrantModeSession
		}, wantErr: "does not use a grant mode"},
		{name: "missing redis for password", mutate: func(c *Config) { c.RedisAddr = "" }, wantErr: "redisAddr"},
		{name: "negative attempts", mutate: func(c *Config) { c.MaxLoginAttempts = -1 }, wantErr: "maxLoginAttempts"},
		{name: "negative concurrent", mutate: func(c *Config) { c.MaxConcurrentLogins = -1 }, wantErr: "maxConcurrentLogins"},
		{name: "forward authorization header", mutate: func(c *Config) { c.ForwardUserHeader = "Authorization" }, wantErr: "must not overwrite Authorization"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := valid()
			if tt.mutate != nil {
				tt.mutate(cfg)
			}
			err := cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestPasswordHashLogin(t *testing.T) {
	hash, err := HashPassword("hashed-password", minPBKDF2Iterations)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	handler, _, _, _ := newPasswordHarness(t, func(c *Config) {
		c.Users = []User{{Username: "alice", PasswordHash: hash}}
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, loginRequest("alice", "hashed-password", "10.1.0.16:1234"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body %q)", rec.Code, rec.Body.String())
	}

	bad := httptest.NewRecorder()
	handler.ServeHTTP(bad, loginRequest("alice", "wrong", "10.1.0.16:1234"))
	if bad.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want 401", bad.Code)
	}
}

func TestSharedPasswordWithoutUsername(t *testing.T) {
	handler, _, _, cfg := newPasswordHarness(t, func(c *Config) {
		c.Users = []User{
			{Password: "shared-one"},
			{Password: "shared-two"},
		}
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, loginRequest("", "shared-two", "10.1.0.17:1234"))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if cookieFrom(rec, cfg.CookieName) == nil {
		t.Fatal("missing session cookie for shared password")
	}
}

func TestCredentialsFileAndEnvironment(t *testing.T) {
	dir := t.TempDir()
	file := dir + "/credentials"
	if err := os.WriteFile(file, []byte("alice:plain:file-password\nplain:shared-file-password\n"), 0600); err != nil {
		t.Fatalf("write credentials: %v", err)
	}
	t.Setenv("HTTP_KNOCK_TEST_CREDENTIALS", "bob:plain:env-password")

	set, err := buildUserSet(nil, file, "HTTP_KNOCK_TEST_CREDENTIALS")
	if err != nil {
		t.Fatalf("buildUserSet: %v", err)
	}
	for _, tc := range []struct {
		username string
		password string
	}{
		{username: "alice", password: "file-password"},
		{username: "", password: "shared-file-password"},
		{username: "bob", password: "env-password"},
	} {
		if user, ok := set.authenticate(tc.username, tc.password); !ok {
			t.Fatalf("authenticate(%q, %q) failed", tc.username, tc.password)
		} else if user.username != tc.username {
			t.Fatalf("authenticate(%q) matched user %q", tc.username, user.username)
		}
	}
	if _, ok := set.authenticate("alice", "wrong"); ok {
		t.Fatal("wrong password was accepted")
	}
}

func TestCookieSecretFileAndEnvironment(t *testing.T) {
	dir := t.TempDir()
	file := dir + "/cookie-secret"
	if err := os.WriteFile(file, []byte(strings.Repeat("f", 40)+"\n"), 0600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	secret, err := loadSecret("", file, "", "cookieSecret")
	if err != nil {
		t.Fatalf("loadSecret file: %v", err)
	}
	if string(secret) != strings.Repeat("f", 40) {
		t.Fatalf("file secret = %q", secret)
	}

	t.Setenv("HTTP_KNOCK_TEST_COOKIE_SECRET", strings.Repeat("e", 40))
	secret, err = loadSecret("", "", "HTTP_KNOCK_TEST_COOKIE_SECRET", "cookieSecret")
	if err != nil {
		t.Fatalf("loadSecret env: %v", err)
	}
	if string(secret) != strings.Repeat("e", 40) {
		t.Fatalf("env secret = %q", secret)
	}
}

func TestPasswordChangeRevokesExistingSession(t *testing.T) {
	srv := startFakeRedis(t)
	backend := &recordingBackend{}

	newHandler := func(password string) http.Handler {
		cfg := CreateConfig()
		cfg.KnockPath = testKnockPath
		cfg.RedisAddr = srv.addr()
		cfg.AuthMode = AuthModePassword
		cfg.Users = []User{{Username: "alice", Password: password}}
		cfg.CookieSecret = testCookieSecret
		cfg.CookieName = "http-knock-test"
		handler, err := New(context.Background(), backend, cfg, "test")
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
	oldHandler.ServeHTTP(login, loginRequest("alice", "old-password", "10.1.0.18:1234"))
	cookie := cookieFrom(login, "http-knock-test")
	if cookie == nil {
		t.Fatal("missing session cookie")
	}

	// A new configuration with a changed password must invalidate the old
	// session through the credential fingerprint stored in Redis.
	newHandler("new-password")
	req := newRequest(http.MethodGet, "https://example.com/private", "10.1.0.18:1234")
	addCookie(req, cookie)
	rec := httptest.NewRecorder()
	newHandler("new-password").ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("old session after password change = %d, want 403", rec.Code)
	}
}

func TestAuthConfigDefaults(t *testing.T) {
	cfg := CreateConfig()
	if cfg.AuthMode != AuthModePath {
		t.Fatalf("AuthMode = %q, want path", cfg.AuthMode)
	}
	if cfg.CookieSecure == nil || !*cfg.CookieSecure {
		t.Fatal("CookieSecure must default to true")
	}
	if cfg.CookieSameSite != "Lax" {
		t.Fatalf("CookieSameSite = %q, want Lax", cfg.CookieSameSite)
	}
	if cfg.MaxLoginAttempts != defaultMaxLoginAttempts {
		t.Fatalf("MaxLoginAttempts = %d, want %d", cfg.MaxLoginAttempts, defaultMaxLoginAttempts)
	}
	if cfg.MaxConcurrentLogins != defaultMaxConcurrent {
		t.Fatalf("MaxConcurrentLogins = %d, want %d", cfg.MaxConcurrentLogins, defaultMaxConcurrent)
	}

	s, err := cfg.settings()
	if err == nil {
		t.Fatal("a config without knockPath/redisAddr must not validate")
	}
	cfg.KnockPath = testKnockPath
	cfg.RedisAddr = "redis:6379"
	s, err = cfg.settingsFor("my-middleware")
	if err != nil {
		t.Fatalf("settingsFor: %v", err)
	}
	if s.grantMode != GrantModeIP {
		t.Fatalf("path-mode grantMode = %q, want ip", s.grantMode)
	}
	if s.realm != "my-middleware" {
		t.Fatalf("realm = %q, want my-middleware", s.realm)
	}
	if s.privateResponses {
		t.Fatal("path mode must default privateResponses to false for backward compatibility")
	}

	passwordCfg := CreateConfig()
	passwordCfg.KnockPath = testKnockPath
	passwordCfg.RedisAddr = "redis:6379"
	passwordCfg.AuthMode = AuthModePassword
	passwordCfg.Users = []User{{Username: "alice", Password: "secret"}}
	passwordCfg.CookieSecret = testCookieSecret
	passwordSettings, err := passwordCfg.settingsFor("my-middleware")
	if err != nil {
		t.Fatalf("password settingsFor: %v", err)
	}
	if passwordSettings.grantMode != GrantModeSession {
		t.Fatalf("password-mode grantMode = %q, want session", passwordSettings.grantMode)
	}
	if !passwordSettings.privateResponses {
		t.Fatal("password mode must default privateResponses to true")
	}
	if passwordSettings.loginPath != testKnockPath {
		t.Fatalf("loginPath = %q, want knockPath", passwordSettings.loginPath)
	}
}
