// Package traefik_http_knock implements a Traefik v3 middleware plugin that
// temporarily allowlists client IP addresses after a successful "HTTP knock".
//
// The allowlist lives exclusively in Redis: a knock request stores
// "<keyPrefix><clientIP>" with a TTL, and any other request is allowed only
// while that key still exists. Redis owns expiry, so this plugin keeps no
// in-memory state, starts no background goroutines and needs no cleanup timers.
//
// The middleware never mutates the proxied request or the backend response; it
// only answers allow/deny decisions and handles the knock endpoint itself.
package traefik_http_knock

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	// DefaultKeyPrefix is prepended to the client IP to build the Redis key.
	DefaultKeyPrefix = "traefik:http-knock:"

	// DefaultTTL is the default lifetime of a successful knock.
	DefaultTTL = 2 * time.Hour

	defaultRedisDB       = 0
	defaultDialTimeout   = 2 * time.Second
	defaultReadTimeout   = time.Second
	defaultWriteTimeout  = time.Second
	defaultRedisPoolSize = 16

	// minKnockPathLength is a weak lower bound on the knock path length. The
	// real secret is the path itself, so a short path is only accepted to keep
	// the plugin usable in tests; production deployments should use a 128-bit
	// random secret (see README).
	minKnockPathLength = 16

	// knockTTLHeader advertises the configured TTL on a successful knock. It
	// never contains infrastructure details.
	knockTTLHeader = "X-Knock-TTL"

	// knockValue is the Redis value stored for an allowlisted IP. It is only
	// ever compared for existence, the value itself is not significant.
	knockValue = "1"
)

// Config is the Traefik plugin configuration. It is decoded by Traefik from the
// Middleware CRD (or the Helm/static configuration) on top of the struct
// returned by CreateConfig, so defaults declared there apply when a field is
// omitted.
type Config struct {
	// KnockPath is the exact request path that triggers a knock, for example
	// "/__knock__/9c4e2e4e3b6d0c0f...". It must start with "/" and should embed
	// a long random secret.
	KnockPath string `json:"knockPath,omitempty"`

	// TTL is the lifetime of an allowlist entry, expressed as a Go duration
	// ("90s", "10m", "2h"). Redis expires the key automatically.
	TTL string `json:"ttl,omitempty"`

	// RedisAddr is the "host:port" of the Redis server.
	RedisAddr string `json:"redisAddr,omitempty"`

	// RedisUsername is optional and only used when Redis ACLs are enabled.
	// Requires Redis >= 6.
	RedisUsername string `json:"redisUsername,omitempty"`

	// RedisPassword is optional. Prefer injecting it from a Secret.
	RedisPassword string `json:"redisPassword,omitempty"`

	// RedisDB is the Redis logical database (0-15). Defaults to 0.
	RedisDB int `json:"redisDB,omitempty"`

	// KeyPrefix is prepended to the normalized client IP. Defaults to
	// DefaultKeyPrefix.
	KeyPrefix string `json:"keyPrefix,omitempty"`

	// ClientIPHeader optionally overrides how the client IP is read, for
	// example "X-Real-IP", "CF-Connecting-IP" or "X-Forwarded-For".
	//
	// SECURITY: only configure this when a trusted reverse proxy in front of
	// Traefik always overwrites the header. Otherwise clients can spoof their
	// IP and allowlist themselves.
	//
	// When empty, the IP is taken from the TCP peer (req.RemoteAddr). For
	// X-Forwarded-For the left-most (client) entry is used.
	ClientIPHeader string `json:"clientIPHeader,omitempty"`

	// FailClosed controls what happens when Redis cannot be reached. It is a
	// pointer so that "unset" can be distinguished from an explicit false:
	// unset means fail closed (true), which is the safe default. An explicit
	// "failClosed: false" makes the middleware fail open.
	FailClosed *bool `json:"failClosed,omitempty"`

	// DialTimeout is the TCP dial timeout for Redis connections. Defaults to 2s.
	DialTimeout string `json:"dialTimeout,omitempty"`

	// ReadTimeout is the per-command Redis read timeout. Defaults to 1s.
	ReadTimeout string `json:"readTimeout,omitempty"`

	// WriteTimeout is the per-command Redis write timeout. Defaults to 1s.
	WriteTimeout string `json:"writeTimeout,omitempty"`

	// RedisPoolSize is the maximum number of Redis connections kept by the
	// plugin. Defaults to 16.
	RedisPoolSize int `json:"redisPoolSize,omitempty"`

	// LogClientIP includes the client IP in log lines. Off by default so that
	// logs do not necessarily contain end-user addresses.
	LogClientIP bool `json:"logClientIP,omitempty"`
}

// CreateConfig returns a Config pre-filled with the production-safe defaults.
// Traefik decodes user configuration on top of this value.
func CreateConfig() *Config {
	return &Config{
		TTL:           DefaultTTL.String(),
		KeyPrefix:     DefaultKeyPrefix,
		FailClosed:    boolPtr(true),
		DialTimeout:   defaultDialTimeout.String(),
		ReadTimeout:   defaultReadTimeout.String(),
		WriteTimeout:  defaultWriteTimeout.String(),
		RedisPoolSize: defaultRedisPoolSize,
		RedisDB:       defaultRedisDB,
	}
}

// settings is the validated, parsed form of Config. The middleware only ever
// reads this type, which keeps request handling free of string parsing.
type settings struct {
	knockPath      string
	ttl            time.Duration
	redisAddr      string
	redisUsername  string
	redisPassword  string
	redisDB        int
	keyPrefix      string
	clientIPHeader string
	failClosed     bool
	dialTimeout    time.Duration
	readTimeout    time.Duration
	writeTimeout   time.Duration
	redisPoolSize  int
	logClientIP    bool
}

// Validate checks the configuration and returns a descriptive error when it is
// unusable. It is safe to call on a Config returned by CreateConfig.
func (c *Config) Validate() error {
	_, err := c.settings()
	return err
}

// settings validates the configuration, applies defaults for any zero value
// that has one and returns the parsed result.
func (c *Config) settings() (*settings, error) {
	if c == nil {
		return nil, errors.New("http-knock: config must not be nil")
	}

	s := &settings{
		knockPath:      strings.TrimSpace(c.KnockPath),
		redisAddr:      strings.TrimSpace(c.RedisAddr),
		redisUsername:  c.RedisUsername,
		redisPassword:  c.RedisPassword,
		redisDB:        c.RedisDB,
		keyPrefix:      c.KeyPrefix,
		clientIPHeader: http.CanonicalHeaderKey(strings.TrimSpace(c.ClientIPHeader)),
		logClientIP:    c.LogClientIP,
	}

	switch {
	case s.knockPath == "":
		return nil, errors.New("http-knock: knockPath must not be empty")
	case !strings.HasPrefix(s.knockPath, "/"):
		return nil, fmt.Errorf("http-knock: knockPath %q must start with %q", s.knockPath, "/")
	case strings.ContainsAny(s.knockPath, "?#"):
		return nil, fmt.Errorf("http-knock: knockPath %q must not contain a query or fragment", s.knockPath)
	case strings.EqualFold(s.knockPath, "/"):
		return nil, errors.New("http-knock: knockPath must not be \"/\" (it would knock on every request)")
	case len(s.knockPath) < minKnockPathLength:
		return nil, fmt.Errorf("http-knock: knockPath must be at least %d characters long, preferably a 128-bit random secret", minKnockPathLength)
	}

	if s.redisAddr == "" {
		return nil, errors.New("http-knock: redisAddr must not be empty")
	}
	if !strings.Contains(s.redisAddr, ":") {
		return nil, fmt.Errorf("http-knock: redisAddr %q must be in host:port form", s.redisAddr)
	}
	if s.redisDB < 0 {
		return nil, fmt.Errorf("http-knock: redisDB must not be negative, got %d", s.redisDB)
	}
	if s.clientIPHeader != "" && !validHeaderName(s.clientIPHeader) {
		return nil, fmt.Errorf("http-knock: clientIPHeader %q is not a valid HTTP header name", c.ClientIPHeader)
	}

	ttl, err := parseDuration("ttl", c.TTL, DefaultTTL)
	if err != nil {
		return nil, err
	}
	s.ttl = ttl

	dialTimeout, err := parseDuration("dialTimeout", c.DialTimeout, defaultDialTimeout)
	if err != nil {
		return nil, err
	}
	s.dialTimeout = dialTimeout

	readTimeout, err := parseDuration("readTimeout", c.ReadTimeout, defaultReadTimeout)
	if err != nil {
		return nil, err
	}
	s.readTimeout = readTimeout

	writeTimeout, err := parseDuration("writeTimeout", c.WriteTimeout, defaultWriteTimeout)
	if err != nil {
		return nil, err
	}
	s.writeTimeout = writeTimeout

	switch {
	case c.RedisPoolSize == 0:
		s.redisPoolSize = defaultRedisPoolSize
	case c.RedisPoolSize < 1:
		return nil, fmt.Errorf("http-knock: redisPoolSize must be positive, got %d", c.RedisPoolSize)
	default:
		s.redisPoolSize = c.RedisPoolSize
	}

	if s.keyPrefix == "" {
		s.keyPrefix = DefaultKeyPrefix
	}

	s.failClosed = c.FailClosed == nil || *c.FailClosed

	return s, nil
}

// parseDuration parses a Go duration string. An empty value falls back to the
// default, a non-positive explicit value is rejected.
func parseDuration(field, value string, fallback time.Duration) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("http-knock: %s %q is not a valid duration: %w", field, value, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("http-knock: %s must be positive, got %q", field, value)
	}
	return d, nil
}

// knockVerifier decides whether a request is a knock attempt and whether it is
// authorized.
//
// This interface is the extension point for future schemes: an HMAC token
// verifier (for example "/__knock__?token=<timestamp>.<nonce>.<signature>")
// only has to provide another implementation, the middleware flow stays
// unchanged. The first release ships pathVerifier only.
type knockVerifier interface {
	// Matches reports whether the request targets the knock endpoint.
	Matches(req *http.Request) bool
	// Authorize validates a knock attempt for the given, already normalized
	// client IP. Returning false results in 403.
	Authorize(req *http.Request, clientIP string) bool
}

// pathVerifier authorizes a knock when the request path equals the configured
// secret path exactly.
type pathVerifier struct {
	path string
}

func (v pathVerifier) Matches(req *http.Request) bool {
	return constantTimeEqualString(req.URL.Path, v.path)
}

// Authorize always succeeds once the secret path matched: the path itself is
// the credential. It is kept separate from Matches so that a future verifier
// can bind an HMAC token to the client IP.
func (v pathVerifier) Authorize(_ *http.Request, _ string) bool { return true }

// middleware is the Traefik handler returned by New.
type middleware struct {
	next     http.Handler
	cfg      *settings
	verifier knockVerifier
	redis    *redisClient
	logger   *log.Logger
}

// New is the Traefik plugin constructor. Traefik calls it once per configured
// middleware instance.
//
// Redis is intentionally not contacted here: a Redis outage must not prevent
// Traefik from loading its configuration. Connectivity problems surface per
// request and are handled according to failClosed.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if next == nil {
		return nil, errors.New("http-knock: next handler must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("http-knock: %w", err)
	}

	cfg, err := config.settings()
	if err != nil {
		return nil, err
	}

	m := &middleware{
		next:     next,
		cfg:      cfg,
		verifier: pathVerifier{path: cfg.knockPath},
		redis: newRedisClient(redisOptions{
			addr:         cfg.redisAddr,
			username:     cfg.redisUsername,
			password:     cfg.redisPassword,
			db:           cfg.redisDB,
			dialTimeout:  cfg.dialTimeout,
			readTimeout:  cfg.readTimeout,
			writeTimeout: cfg.writeTimeout,
			maxConns:     cfg.redisPoolSize,
		}),
		logger: log.New(os.Stderr, fmt.Sprintf("[http-knock] %s: ", name), log.LstdFlags),
	}

	return m, nil
}

// ServeHTTP implements http.Handler.
func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if m.verifier.Matches(req) {
		m.handleKnock(rw, req)
		return
	}
	m.handleProtected(rw, req)
}

// handleKnock stores the client IP in Redis and terminates the request. The
// knock request is never forwarded to the backend.
func (m *middleware) handleKnock(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodGet {
		rw.Header().Set("Allow", http.MethodGet)
		m.logf("knock rejected: method %s is not allowed", req.Method)
		http.Error(rw, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	ip, err := clientIPFromRequest(req, m.cfg.clientIPHeader)
	if err != nil {
		// Deliberately 403 and not 400: do not confirm that the path matched.
		m.logf("knock rejected: %v", err)
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	if !m.verifier.Authorize(req, ip) {
		m.logf("knock rejected: invalid token for client %s", m.clientLabel(ip))
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	if err := m.redis.setEx(redisKey(m.cfg.keyPrefix, ip), knockValue, m.cfg.ttl); err != nil {
		m.logf("redis unavailable during knock for client %s: %v", m.clientLabel(ip), err)
		m.writeRedisFailure(rw, req)
		return
	}

	m.logf("knock succeeded for client %s", m.clientLabel(ip))
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")
	rw.Header().Set(knockTTLHeader, m.cfg.ttl.String())
	rw.WriteHeader(http.StatusNoContent)
}

// handleProtected allowlists a normal request when the client IP is still
// present in Redis.
func (m *middleware) handleProtected(rw http.ResponseWriter, req *http.Request) {
	ip, err := clientIPFromRequest(req, m.cfg.clientIPHeader)
	if err != nil {
		m.logf("request denied: %v", err)
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	allowed, err := m.redis.exists(redisKey(m.cfg.keyPrefix, ip))
	if err != nil {
		m.logf("redis unavailable for client %s: %v", m.clientLabel(ip), err)
		m.writeRedisFailure(rw, req)
		return
	}
	if !allowed {
		m.logf("request denied for client %s: no active knock", m.clientLabel(ip))
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}

	m.next.ServeHTTP(rw, req)
}

// writeRedisFailure applies the failClosed policy. Failure to reach the state
// store must never be treated as an allowlist hit unless the operator
// explicitly opted into fail open.
func (m *middleware) writeRedisFailure(rw http.ResponseWriter, req *http.Request) {
	if !m.cfg.failClosed {
		m.next.ServeHTTP(rw, req)
		return
	}
	http.Error(rw, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
}

// Close releases the Redis connection pool. Traefik does not require a plugin
// closer, but tests and embedded use benefit from deterministic cleanup.
func (m *middleware) Close() error {
	return m.redis.Close()
}

func (m *middleware) logf(format string, args ...interface{}) {
	if m.logger == nil {
		return
	}
	m.logger.Printf(format, args...)
}

// clientLabel hides the client IP unless the operator opted into logging it.
func (m *middleware) clientLabel(ip string) string {
	if m.cfg.logClientIP {
		return ip
	}
	return "redacted"
}

// constantTimeEqualString compares two strings without leaking the position of
// the first difference through timing. Lengths are public information.
func constantTimeEqualString(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func boolPtr(v bool) *bool { return &v }

// redisKey builds the Redis key for a normalized client IP. IPv4 and IPv6 are
// both stored as plain suffixes of the prefix, and because the IP is
// canonicalized before it reaches this function there is no ambiguity between
// e.g. "2001:db8::1" and "2001:0db8::1".
func redisKey(prefix, ip string) string {
	return prefix + ip
}

// redisTTLSeconds converts a duration to the integer seconds used by Redis
// "SET ... EX". Redis requires at least 1 second.
func redisTTLSeconds(ttl time.Duration) int64 {
	seconds := int64(ttl / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}
