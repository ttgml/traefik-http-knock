package traefik_http_knock

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// testKnockPath is a 43 character path with a 128-bit-ish random secret. It
// only exists in tests.
const testKnockPath = "/__knock__/0123456789abcdef0123456789abcdef"

// testKey is the realm-scoped Redis key used by the test harness (name "test").
func testKey(ip string) string { return ipGrantKey(DefaultKeyPrefix, "test", ip) }

// recordingBackend captures how the plugin called the wrapped handler.
type recordingBackend struct {
	mu      sync.Mutex
	calls   int
	method  string
	url     string
	host    string
	headers http.Header
	body    string
}

func (b *recordingBackend) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)

	b.mu.Lock()
	b.calls++
	b.method = req.Method
	b.url = req.URL.String()
	b.host = req.Host
	b.headers = req.Header.Clone()
	b.body = string(body)
	b.mu.Unlock()

	rw.Header().Set("X-Backend", "reached")
	rw.WriteHeader(http.StatusOK)
	_, _ = rw.Write([]byte("backend"))
}

func (b *recordingBackend) callCount() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls
}

func (b *recordingBackend) snapshot() (method, url, host, body string, headers http.Header) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.method, b.url, b.host, b.body, b.headers
}

// newHarness wires the middleware to a fake Redis server and a recording
// backend.
func newHarness(t *testing.T, mutate func(*Config)) (http.Handler, *recordingBackend, *fakeRedisServer) {
	t.Helper()

	srv := startFakeRedis(t)
	cfg := CreateConfig()
	cfg.KnockPath = testKnockPath
	cfg.Realm = "test"
	cfg.RedisAddr = srv.addr()
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
	return handler, backend, srv
}

func newRequest(method, target, remoteAddr string) *http.Request {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = remoteAddr
	return req
}

func TestCreateConfigDefaults(t *testing.T) {
	cfg := CreateConfig()

	if cfg.KnockPath != "" {
		t.Fatalf("knockPath must have no default, got %q", cfg.KnockPath)
	}
	if cfg.TTL != "2h0m0s" {
		t.Fatalf("ttl default = %q, want 2h0m0s", cfg.TTL)
	}
	if cfg.KeyPrefix != DefaultKeyPrefix {
		t.Fatalf("keyPrefix default = %q, want %q", cfg.KeyPrefix, DefaultKeyPrefix)
	}
	if cfg.DialTimeout != "2s" || cfg.ReadTimeout != "1s" || cfg.WriteTimeout != "1s" {
		t.Fatalf("unexpected timeout defaults: %q %q %q", cfg.DialTimeout, cfg.ReadTimeout, cfg.WriteTimeout)
	}
	if cfg.RedisPoolSize != 16 {
		t.Fatalf("redisPoolSize default = %d, want 16", cfg.RedisPoolSize)
	}
	if cfg.FailClosed == nil || !*cfg.FailClosed {
		t.Fatal("failClosed must default to true")
	}
	if cfg.LogClientIP {
		t.Fatal("logClientIP must default to false")
	}
}

func TestConfigDefaultsSurviveValidation(t *testing.T) {
	cfg := CreateConfig()
	cfg.KnockPath = testKnockPath
	cfg.RedisAddr = "redis:6379"

	s, err := cfg.settings()
	if err != nil {
		t.Fatalf("settings: %v", err)
	}
	if s.ttl != 2*time.Hour {
		t.Fatalf("ttl = %s, want 2h", s.ttl)
	}
	if s.keyPrefix != DefaultKeyPrefix {
		t.Fatalf("keyPrefix = %q, want %q", s.keyPrefix, DefaultKeyPrefix)
	}
	if !s.failClosed {
		t.Fatal("failClosed must default to true")
	}
	if s.redisPoolSize != 16 {
		t.Fatalf("redisPoolSize = %d, want 16", s.redisPoolSize)
	}
}

func TestConfigValidate(t *testing.T) {
	valid := func() *Config {
		cfg := CreateConfig()
		cfg.KnockPath = testKnockPath
		cfg.RedisAddr = "redis:6379"
		return cfg
	}

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
	}{
		{name: "valid"},
		{name: "custom everything", mutate: func(c *Config) {
			c.TTL = "45m"
			c.RedisUsername = "knock"
			c.RedisPassword = "pw"
			c.RedisDB = 4
			c.KeyPrefix = "custom:"
			c.ClientIPHeader = "x-real-ip"
			c.FailClosed = boolPtr(false)
			c.DialTimeout = "500ms"
			c.ReadTimeout = "250ms"
			c.WriteTimeout = "250ms"
			c.RedisPoolSize = 2
			c.LogClientIP = true
			c.StaticAllowlist = []string{"10.0.0.1", "192.168.0.0/16", "2001:db8::/32"}
			c.RedirectURL = "/welcome"
		}},
		{name: "redirect to root path", mutate: func(c *Config) { c.RedirectURL = "/" }},
		{name: "redirect to same-origin path", mutate: func(c *Config) { c.RedirectURL = "/welcome" }},
		{name: "redirect to absolute https url", mutate: func(c *Config) { c.RedirectURL = "https://example.com/welcome" }},
		{name: "protocol-relative redirect", mutate: func(c *Config) { c.RedirectURL = "//evil.example/" }, wantErr: "protocol-relative"},
		{name: "redirect with non-http scheme", mutate: func(c *Config) { c.RedirectURL = "javascript:alert(1)" }, wantErr: "absolute http(s)"},
		{name: "redirect without scheme", mutate: func(c *Config) { c.RedirectURL = "example.com/welcome" }, wantErr: "absolute http(s)"},
		{name: "redirect with backslash", mutate: func(c *Config) { c.RedirectURL = `/\evil.example/` }, wantErr: "backslash"},
		{name: "static allowlist with a bad ip", mutate: func(c *Config) { c.StaticAllowlist = []string{"10.0.0.1", "not-an-ip"} }, wantErr: "staticAllowlist"},
		{name: "static allowlist with a bad cidr", mutate: func(c *Config) { c.StaticAllowlist = []string{"10.0.0.0/33"} }, wantErr: "staticAllowlist"},
		{name: "static allowlist with an empty entry", mutate: func(c *Config) { c.StaticAllowlist = []string{""} }, wantErr: "staticAllowlist"},
		{name: "empty knock path", mutate: func(c *Config) { c.KnockPath = "" }, wantErr: "knockPath must not be empty"},
		{name: "relative knock path", mutate: func(c *Config) { c.KnockPath = "__knock__/secret-value" }, wantErr: "must start with"},
		{name: "root knock path", mutate: func(c *Config) { c.KnockPath = "/" }, wantErr: "must not be \"/\""},
		{name: "short knock path", mutate: func(c *Config) { c.KnockPath = "/knoc" }, wantErr: "at least"},
		{name: "minimum length knock path", mutate: func(c *Config) { c.KnockPath = "/abcde" }},
		{name: "maximum length knock path", mutate: func(c *Config) { c.KnockPath = "/" + strings.Repeat("a", maxKnockPathLength-1) }},
		{name: "long knock path", mutate: func(c *Config) { c.KnockPath = "/" + strings.Repeat("a", maxKnockPathLength) }, wantErr: "at most"},
		{name: "knock path with query", mutate: func(c *Config) { c.KnockPath = "/__knock__/secret?x=1" }, wantErr: "must not contain"},
		{name: "empty redis addr", mutate: func(c *Config) { c.RedisAddr = "" }, wantErr: "redisAddr must not be empty"},
		{name: "redis addr without port", mutate: func(c *Config) { c.RedisAddr = "redis" }, wantErr: "host:port"},
		{name: "invalid client ip header", mutate: func(c *Config) { c.ClientIPHeader = "X Real IP" }, wantErr: "not a valid HTTP header name"},
		{name: "negative redis db", mutate: func(c *Config) { c.RedisDB = -1 }, wantErr: "redisDB"},
		{name: "bad ttl", mutate: func(c *Config) { c.TTL = "two hours" }, wantErr: "not a valid duration"},
		{name: "zero ttl", mutate: func(c *Config) { c.TTL = "0s" }, wantErr: "must be positive"},
		{name: "negative ttl", mutate: func(c *Config) { c.TTL = "-10m" }, wantErr: "must be positive"},
		{name: "bad dial timeout", mutate: func(c *Config) { c.DialTimeout = "soon" }, wantErr: "dialTimeout"},
		{name: "bad read timeout", mutate: func(c *Config) { c.ReadTimeout = "-1s" }, wantErr: "readTimeout"},
		{name: "bad write timeout", mutate: func(c *Config) { c.WriteTimeout = "0" }, wantErr: "writeTimeout"},
		{name: "negative pool size", mutate: func(c *Config) { c.RedisPoolSize = -2 }, wantErr: "redisPoolSize"},
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
			if err == nil {
				t.Fatalf("Validate() = nil, want error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestConfigNilIsRejected(t *testing.T) {
	var cfg *Config
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for a nil config")
	}
}

func TestNewRejectsBadInput(t *testing.T) {
	backend := &recordingBackend{}

	cfg := CreateConfig()
	cfg.KnockPath = testKnockPath
	cfg.RedisAddr = "redis:6379"

	if _, err := New(context.Background(), nil, cfg, "test"); err == nil {
		t.Fatal("expected an error for a nil next handler")
	}

	bad := CreateConfig()
	if _, err := New(context.Background(), backend, bad, "test"); err == nil {
		t.Fatal("expected an error for an invalid config")
	}
	var nilCfg *Config
	if _, err := New(context.Background(), backend, nilCfg, "test"); err == nil {
		t.Fatal("expected an error for a nil config")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := New(ctx, backend, cfg, "test"); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestKnockStoresClientIP(t *testing.T) {
	handler, backend, srv := newHarness(t, nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com"+testKnockPath, "10.0.0.1:40000"))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (body %q)", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != "" {
		t.Fatalf("204 response must have no body, got %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get(knockTTLHeader); got != "2h0m0s" {
		t.Fatalf("%s = %q, want 2h0m0s", knockTTLHeader, got)
	}
	if backend.callCount() != 0 {
		t.Fatal("the knock request must never reach the backend")
	}
	if !srv.get(testKey("10.0.0.1")) {
		t.Fatalf("expected the client IP to be stored, commands: %v", srv.recordedCommands())
	}
	if !contains(srv.recordedCommands(), "SET "+testKey("10.0.0.1")+" 1 EX 7200") {
		t.Fatalf("unexpected commands: %v", srv.recordedCommands())
	}
}

func TestKnockCustomPrefixAndTTL(t *testing.T) {
	handler, _, srv := newHarness(t, func(c *Config) {
		c.TTL = "45m"
		c.KeyPrefix = "custom:"
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com"+testKnockPath, "10.0.0.2:40000"))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get(knockTTLHeader); got != "45m0s" {
		t.Fatalf("%s = %q, want 45m0s", knockTTLHeader, got)
	}
	if !contains(srv.recordedCommands(), "SET custom:test:ip:10.0.0.2 1 EX 2700") {
		t.Fatalf("unexpected commands: %v", srv.recordedCommands())
	}
}

func TestKnockRedirectsToConfiguredTarget(t *testing.T) {
	handler, backend, srv := newHarness(t, func(c *Config) {
		c.RedirectURL = "/"
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com"+testKnockPath, "10.0.1.1:40000"))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303 (body %q)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/" {
		t.Fatalf("Location = %q, want /", got)
	}
	if got := rec.Body.String(); got != "" {
		t.Fatalf("303 response must have no body, got %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := rec.Header().Get(knockTTLHeader); got != "2h0m0s" {
		t.Fatalf("%s = %q, want 2h0m0s", knockTTLHeader, got)
	}
	if backend.callCount() != 0 {
		t.Fatal("a knock redirect must not reach the backend")
	}
	if !srv.get(testKey("10.0.1.1")) {
		t.Fatalf("expected the client IP to be stored, commands: %v", srv.recordedCommands())
	}
}

func TestKnockRedirectsToAbsoluteURL(t *testing.T) {
	const target = "https://example.com/welcome"

	handler, backend, _ := newHarness(t, func(c *Config) {
		c.RedirectURL = target
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com"+testKnockPath, "10.0.1.2:40000"))

	if rec.Code != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != target {
		t.Fatalf("Location = %q, want %q", got, target)
	}
	if backend.callCount() != 0 {
		t.Fatal("a knock redirect must not reach the backend")
	}
}

// TestKnockDoesNotRedirectWhenRedisFails proves the redirect is only sent
// after the allowlist entry was actually stored: a failed knock stays a 503.
func TestKnockDoesNotRedirectWhenRedisFails(t *testing.T) {
	handler, backend, srv := newHarness(t, func(c *Config) {
		c.RedirectURL = "/"
	})
	srv.failNext(1)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com"+testKnockPath, "10.0.1.3:40000"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when the knock cannot be stored", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "" {
		t.Fatalf("a failed knock must not redirect, Location = %q", got)
	}
	if backend.callCount() != 0 {
		t.Fatal("a failed knock must not reach the backend")
	}
}

func TestKnockSelectsRedisDB(t *testing.T) {
	srv := startFakeRedis(t, fakeRedisOptions{requireDB: 2})
	cfg := CreateConfig()
	cfg.KnockPath = testKnockPath
	cfg.RedisAddr = srv.addr()
	cfg.RedisDB = 2

	handler, err := New(context.Background(), &recordingBackend{}, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = handler.(interface{ Close() error }).Close() }()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com"+testKnockPath, "10.0.0.3:1234"))

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (the fake requires SELECT 2)", rec.Code)
	}
	if !contains(srv.recordedCommands(), "SELECT 2") {
		t.Fatalf("expected SELECT 2, got %v", srv.recordedCommands())
	}
}

func TestNonGetKnockIsNotASpecialCase(t *testing.T) {
	methods := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions}

	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			handler, backend, srv := newHarness(t, nil)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, newRequest(method, "https://example.com"+testKnockPath, "10.0.0.4:1234"))

			// A non-GET request to the secret path gets the same 403 as any
			// other unknown path, so it cannot be used to confirm the secret.
			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403", rec.Code)
			}
			if got := rec.Header().Get("Allow"); got != "" {
				t.Fatalf("Allow = %q, want no Allow header to avoid confirming the path", got)
			}
			if backend.callCount() != 0 {
				t.Fatal("a non-GET request to the knock path must not reach the backend")
			}
			if srv.get(testKey("10.0.0.4")) {
				t.Fatal("a non-GET request must not knock")
			}
		})
	}
}

// TestNonGetResponseDoesNotRevealKnockPath proves the oracle is gone: a non-GET
// request to the real secret path and one to an unrelated path are byte-for-byte
// indistinguishable.
func TestNonGetResponseDoesNotRevealKnockPath(t *testing.T) {
	handler, _, _ := newHarness(t, nil)

	onKnockPath := httptest.NewRecorder()
	handler.ServeHTTP(onKnockPath, newRequest(http.MethodPost, "https://example.com"+testKnockPath, "10.0.0.7:1234"))

	onOtherPath := httptest.NewRecorder()
	handler.ServeHTTP(onOtherPath, newRequest(http.MethodPost, "https://example.com/private", "10.0.0.7:1234"))

	if onKnockPath.Code != onOtherPath.Code {
		t.Fatalf("status differs: knock path %d, other path %d", onKnockPath.Code, onOtherPath.Code)
	}
	if onKnockPath.Body.String() != onOtherPath.Body.String() {
		t.Fatalf("body differs: knock path %q, other path %q", onKnockPath.Body.String(), onOtherPath.Body.String())
	}
	if got, want := onKnockPath.Header().Get("Content-Type"), onOtherPath.Header().Get("Content-Type"); got != want {
		t.Fatalf("Content-Type differs: %q vs %q", got, want)
	}
	if got, want := onKnockPath.Header().Get("X-Content-Type-Options"), onOtherPath.Header().Get("X-Content-Type-Options"); got != want {
		t.Fatalf("X-Content-Type-Options differs: %q vs %q", got, want)
	}
}

func TestKnockPathMustMatchExactly(t *testing.T) {
	paths := []string{
		testKnockPath + "/",
		testKnockPath + "/extra",
		"/prefix" + testKnockPath,
		"/__knock__/wrong-secret-value",
		"/__knock__",
		"/",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			handler, backend, srv := newHarness(t, nil)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com"+path, "10.0.0.5:1234"))

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 for %q", rec.Code, path)
			}
			if backend.callCount() != 0 {
				t.Fatal("an unauthorized request must not reach the backend")
			}
			if srv.get(testKey("10.0.0.5")) {
				t.Fatal("a non-matching path must not knock")
			}
		})
	}
}

func TestProtectedRequestAllowedAfterKnock(t *testing.T) {
	handler, backend, _ := newHarness(t, nil)

	knock := httptest.NewRecorder()
	handler.ServeHTTP(knock, newRequest(http.MethodGet, "https://example.com"+testKnockPath, "10.0.0.6:1234"))
	if knock.Code != http.StatusNoContent {
		t.Fatalf("knock status = %d, want 204", knock.Code)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com/private", "10.0.0.6:5678"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Body.String(); got != "backend" {
		t.Fatalf("body = %q, want the backend response", got)
	}
	if got := rec.Header().Get("X-Backend"); got != "reached" {
		t.Fatal("the backend must be reached after a knock")
	}
	if backend.callCount() != 1 {
		t.Fatalf("backend calls = %d, want 1", backend.callCount())
	}
}

func TestProtectedRequestDeniedWithoutKnock(t *testing.T) {
	handler, backend, _ := newHarness(t, nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com/private", "10.0.0.7:1234"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	if backend.callCount() != 0 {
		t.Fatal("an unknocked client must not reach the backend")
	}
}

func TestProtectedRequestDeniedForOtherClient(t *testing.T) {
	handler, backend, _ := newHarness(t, nil)

	knock := httptest.NewRecorder()
	handler.ServeHTTP(knock, newRequest(http.MethodGet, "https://example.com"+testKnockPath, "10.0.0.8:1234"))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com/private", "10.0.0.9:1234"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a different client", rec.Code)
	}
	if backend.callCount() != 0 {
		t.Fatal("another client must not reach the backend")
	}
}

func TestAllowlistEntriesExpire(t *testing.T) {
	handler, backend, srv := newHarness(t, nil)

	knock := httptest.NewRecorder()
	handler.ServeHTTP(knock, newRequest(http.MethodGet, "https://example.com"+testKnockPath, "10.0.0.10:1234"))
	if knock.Code != http.StatusNoContent {
		t.Fatalf("knock status = %d, want 204", knock.Code)
	}

	// Simulate Redis TTL expiry; the plugin keeps no state of its own, so the
	// next request must be denied.
	srv.expireAll()

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com/private", "10.0.0.10:1234"))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 after expiry", rec.Code)
	}
	if backend.callCount() != 0 {
		t.Fatal("the backend must not be reached after expiry")
	}
}

func TestFailClosedWhenRedisIsUnreachable(t *testing.T) {
	addr := closedAddr(t)

	tests := []struct {
		name       string
		path       string
		wantStatus int
	}{
		{name: "knock", path: testKnockPath, wantStatus: http.StatusServiceUnavailable},
		{name: "protected", path: "/private", wantStatus: http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &recordingBackend{}
			cfg := CreateConfig()
			cfg.KnockPath = testKnockPath
			cfg.RedisAddr = addr
			cfg.DialTimeout = "50ms"

			handler, err := New(context.Background(), backend, cfg, "test")
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com"+tt.path, "10.0.0.11:1234"))

			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
			if backend.callCount() != 0 {
				t.Fatal("fail closed must not reach the backend")
			}
		})
	}
}

func TestFailOpenWhenExplicitlyConfigured(t *testing.T) {
	backend := &recordingBackend{}
	cfg := CreateConfig()
	cfg.KnockPath = testKnockPath
	cfg.RedisAddr = closedAddr(t)
	cfg.DialTimeout = "50ms"
	cfg.FailClosed = boolPtr(false)

	handler, err := New(context.Background(), backend, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com/private", "10.0.0.12:1234"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 when failClosed is false", rec.Code)
	}
	if backend.callCount() != 1 {
		t.Fatalf("backend calls = %d, want 1", backend.callCount())
	}

	// A knock is never forwarded to the backend, even when failing open: its
	// URL carries the secret. It simply cannot be acknowledged while Redis is
	// down.
	knock := httptest.NewRecorder()
	handler.ServeHTTP(knock, newRequest(http.MethodGet, "https://example.com"+testKnockPath, "10.0.0.12:1234"))
	if knock.Code != http.StatusServiceUnavailable {
		t.Fatalf("knock status = %d, want 503 (a knock never reaches the backend)", knock.Code)
	}
	if backend.callCount() != 1 {
		t.Fatalf("backend calls = %d, want 1: the knock must not be forwarded when failing open", backend.callCount())
	}
}

func TestServerErrorFromRedisFailsClosed(t *testing.T) {
	handler, backend, srv := newHarness(t, nil)

	srv.failNext(1)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com/private", "10.0.0.13:1234"))

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
	if backend.callCount() != 0 {
		t.Fatal("a Redis error must not reach the backend")
	}
}

func TestKnockIPv6Client(t *testing.T) {
	handler, backend, srv := newHarness(t, nil)

	knock := httptest.NewRecorder()
	handler.ServeHTTP(knock, newRequest(http.MethodGet, "https://example.com"+testKnockPath, "[2001:0DB8::5]:1234"))
	if knock.Code != http.StatusNoContent {
		t.Fatalf("knock status = %d, want 204", knock.Code)
	}
	if !srv.get(testKey("2001:db8::5")) {
		t.Fatalf("expected a canonicalized IPv6 key, commands: %v", srv.recordedCommands())
	}

	// The same address in a different notation is the same client.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com/private", "[2001:db8:0:0:0:0:0:5]:9999"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for the same IPv6 client", rec.Code)
	}

	// A different IPv6 address stays denied.
	other := httptest.NewRecorder()
	handler.ServeHTTP(other, newRequest(http.MethodGet, "https://example.com/private", "[2001:db8::6]:1234"))
	if other.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a different IPv6 client", other.Code)
	}
	if backend.callCount() != 1 {
		t.Fatalf("backend calls = %d, want 1", backend.callCount())
	}
}

func TestClientIPHeaderIsUsedWhenConfigured(t *testing.T) {
	handler, backend, srv := newHarness(t, func(c *Config) {
		c.ClientIPHeader = "X-Forwarded-For"
	})

	knock := newRequest(http.MethodGet, "https://example.com"+testKnockPath, "192.0.2.1:1234")
	knock.Header.Set("X-Forwarded-For", "203.0.113.5, 70.41.3.18")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, knock)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("knock status = %d, want 204", rec.Code)
	}
	if !srv.get(testKey("203.0.113.5")) {
		t.Fatalf("expected the left-most X-Forwarded-For entry, commands: %v", srv.recordedCommands())
	}

	// The proxy in front of Traefik reports the same client again.
	allowed := newRequest(http.MethodGet, "https://example.com/private", "192.0.2.1:5678")
	allowed.Header.Set("X-Forwarded-For", "203.0.113.5")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, allowed)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if backend.callCount() != 1 {
		t.Fatalf("backend calls = %d, want 1", backend.callCount())
	}
}

func TestStaticAllowlistBypassesKnockAndRedis(t *testing.T) {
	handler, backend, srv := newHarness(t, func(c *Config) {
		c.StaticAllowlist = []string{"10.9.0.0/16", "203.0.113.5"}
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com/private", "10.9.1.2:1234"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a statically allowlisted client", rec.Code)
	}
	if backend.callCount() != 1 {
		t.Fatalf("backend calls = %d, want 1", backend.callCount())
	}
	for _, cmd := range srv.recordedCommands() {
		if strings.HasPrefix(cmd, "EXISTS") {
			t.Fatalf("a static allowlist hit must not touch Redis, saw %q", cmd)
		}
	}

	// A client outside the static allowlist still needs a knock.
	other := httptest.NewRecorder()
	handler.ServeHTTP(other, newRequest(http.MethodGet, "https://example.com/private", "10.10.0.1:1234"))
	if other.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 for a client outside the allowlist", other.Code)
	}
}

func TestStaticAllowlistMatchesExactIPv6(t *testing.T) {
	handler, backend, _ := newHarness(t, func(c *Config) {
		c.StaticAllowlist = []string{"2001:db8::1"}
	})

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com/private", "[2001:0DB8::1]:1234"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for a statically allowlisted IPv6 client", rec.Code)
	}
	if backend.callCount() != 1 {
		t.Fatalf("backend calls = %d, want 1", backend.callCount())
	}
}

func TestStaticAllowlistWorksWhenRedisIsUnreachable(t *testing.T) {
	backend := &recordingBackend{}
	cfg := CreateConfig()
	cfg.KnockPath = testKnockPath
	cfg.RedisAddr = closedAddr(t)
	cfg.DialTimeout = "50ms"
	cfg.StaticAllowlist = []string{"10.9.0.1"}

	handler, err := New(context.Background(), backend, cfg, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com/private", "10.9.0.1:1234"))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 even though Redis is down", rec.Code)
	}
	if backend.callCount() != 1 {
		t.Fatalf("backend calls = %d, want 1", backend.callCount())
	}
}

func TestRequestAndResponseAreNotMutated(t *testing.T) {
	handler, backend, _ := newHarness(t, nil)

	knock := httptest.NewRecorder()
	handler.ServeHTTP(knock, newRequest(http.MethodGet, "https://example.com"+testKnockPath, "10.0.0.14:1234"))

	req := newRequest(http.MethodGet, "https://internal.example.com:8443/private?x=1&y=2", "10.0.0.14:1234")
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("Cookie", "session=abc")
	req.Header.Set("X-Custom", "value")
	req.Host = "internal.example.com:8443"

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	method, url, host, _, headers := backend.snapshot()
	if method != http.MethodGet {
		t.Fatalf("method changed to %q", method)
	}
	if url != "https://internal.example.com:8443/private?x=1&y=2" {
		t.Fatalf("url changed to %q", url)
	}
	if host != "internal.example.com:8443" {
		t.Fatalf("host changed to %q", host)
	}
	if got := headers.Get("Authorization"); got != "Bearer token" {
		t.Fatalf("Authorization changed to %q", got)
	}
	if got := headers.Get("Cookie"); got != "session=abc" {
		t.Fatalf("Cookie changed to %q", got)
	}
	if got := headers.Get("X-Custom"); got != "value" {
		t.Fatalf("X-Custom changed to %q", got)
	}
}

func TestErrorResponsesDoNotLeakInfrastructure(t *testing.T) {
	handler, _, _ := newHarness(t, nil)

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com/private", "10.0.0.15:1234"))

	body := strings.ToLower(rec.Body.String())
	for _, needle := range []string{"redis", "traefik:http-knock", testKnockPath, "10.0.0.15"} {
		if strings.Contains(body, strings.ToLower(needle)) {
			t.Fatalf("403 body leaks %q: %q", needle, rec.Body.String())
		}
	}
}

func TestKnockLogsRedactClientIPByDefault(t *testing.T) {
	m := &middleware{cfg: &settings{logClientIP: false}}
	if got := m.clientLabel("10.0.0.1"); got != "redacted" {
		t.Fatalf("clientLabel = %q, want redacted", got)
	}
	m.cfg.logClientIP = true
	if got := m.clientLabel("10.0.0.1"); got != "10.0.0.1" {
		t.Fatalf("clientLabel = %q, want the IP", got)
	}
}

func TestConcurrentKnockAndProtectedRequests(t *testing.T) {
	handler, backend, _ := newHarness(t, func(c *Config) {
		c.RedisPoolSize = 4
	})

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := "10.1.0." + strconv.Itoa(i%8)
			for j := 0; j < 10; j++ {
				rec := httptest.NewRecorder()
				handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com"+testKnockPath, ip+":1234"))

				rec = httptest.NewRecorder()
				handler.ServeHTTP(rec, newRequest(http.MethodGet, "https://example.com/private", ip+":5678"))
			}
		}(i)
	}
	wg.Wait()

	if backend.callCount() == 0 {
		t.Fatal("expected some requests to be allowed")
	}
}
