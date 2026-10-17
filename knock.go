// Package traefik_http_knock implements a Traefik v3 middleware plugin with
// path-secret, password and HTTP Basic authentication.
//
// Path mode temporarily allowlists client IP addresses after a successful
// "HTTP knock". Password mode verifies one or more users and issues a
// Redis-backed session cookie/token (or an IP grant, depending on GrantMode).
// Redis owns expiry, so the plugin keeps no background goroutines and needs no
// cleanup timers.
//
// By default the middleware does not mutate proxied requests. Two explicit
// opt-ins can change response/request headers: PrivateResponses adds
// cache-isolation headers to protected responses, and ForwardUserHeader passes
// the authenticated username to the backend (stripping any client value).
package traefik_http_knock

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
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

	// minKnockPathLength and maxKnockPathLength bound the knock path. The real
	// secret is the path itself, so a short path is only accepted to keep the
	// plugin usable in tests; production deployments should use a 128-bit
	// random secret (see README). The upper bound keeps the path well inside
	// the request-line limits of Go's net/http, proxies and browsers.
	minKnockPathLength = 6
	maxKnockPathLength = 80

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
	// KnockPath is the exact path of the path-mode knock endpoint, for example
	// "/__knock__/9c4e2e4e3b6d0c0f...". It must start with "/", must not be
	// protocol-relative or contain "?", "#", backslashes, percent-encoding,
	// whitespace or control characters, and must be between 6 and 80
	// characters long. In path mode it should embed a long random secret. In
	// password mode it is used as the default login endpoint when LoginPath is
	// empty.
	KnockPath string `json:"knockPath,omitempty"`

	// TTL is the lifetime of an IP grant, expressed as a Go duration ("90s",
	// "10m", "2h"). Redis expires the key automatically. Password sessions use
	// SessionTTL instead (which defaults to TTL).
	TTL string `json:"ttl,omitempty"`

	// RedirectURL is where a browser is sent after a successful knock or
	// password login, so the visitor does not have to open the site manually.
	// Set it to "/" to land on the homepage, or to any same-origin path
	// ("https://example.com/" for an absolute URL).
	//
	// When empty (the default) successful path knocks answer 204 No Content.
	// Only absolute http(s) URLs and paths starting with "/" are accepted, so
	// the middleware cannot be turned into an open redirect to javascript: or
	// protocol-relative "//evil.example" targets.
	RedirectURL string `json:"redirectURL,omitempty"`

	// RedisAddr is the "host:port" of the Redis server.
	RedisAddr string `json:"redisAddr,omitempty"`

	// RedisUsername is optional and only used when Redis ACLs are enabled.
	// Requires Redis >= 6.
	RedisUsername string `json:"redisUsername,omitempty"`

	// RedisPassword is optional. Prefer injecting it from a Secret.
	RedisPassword string `json:"redisPassword,omitempty"`

	// RedisDB is the Redis logical database. Defaults to 0. Redis enables 0-15 by
	// default; a higher value must also be enabled in the Redis server.
	RedisDB int `json:"redisDB,omitempty"`

	// KeyPrefix is prepended to every realm-scoped Redis key (IP grants,
	// sessions and login counters). Defaults to DefaultKeyPrefix.
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

	// StaticAllowlist is an optional list of IP addresses and CIDR ranges that
	// are always allowed, independently of knocks and of Redis. Entries are
	// single IPs ("10.0.0.1", "2001:db8::1") or CIDR ranges ("10.0.0.0/8",
	// "2001:db8::/32").
	//
	// In password and Basic mode a match bypasses authentication entirely: the
	// request is forwarded without checking credentials. This is intentional,
	// so only list networks you fully trust.
	//
	// SECURITY: static entries are matched against the resolved client IP, so
	// they inherit the trust of how that IP is determined. When ClientIPHeader
	// is set without a trusted proxy overwriting it, a client can spoof an IP
	// and match a static entry.
	StaticAllowlist []string `json:"staticAllowlist,omitempty"`

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

	// AuthMode selects how credentials are verified:
	//
	//   - "path" (default): the original GET <knockPath> secret-path knock.
	//   - "password": a login form on LoginPath, session cookies and Bearer
	//     session tokens (only for grantMode session/both). Basic auth is not
	//     accepted in this mode; use the login endpoint to obtain a token for
	//     CLI/API clients.
	//   - "basic": HTTP Basic auth on every request. This mode is stateless
	//     and does not use Redis for access decisions. Each request performs a
	//     password verification, so it is CPU-bound and has no login rate
	//     limit (only the MaxConcurrentLogins bound); use it behind a Traefik
	//     rateLimit middleware and preferably on a trusted network.
	AuthMode string `json:"authMode,omitempty"`

	// GrantMode controls what a successful password login grants:
	//
	//   - "ip": the client IP is stored in Redis (NAT users share access).
	//     Sessions/Bearer tokens are neither issued nor accepted.
	//   - "session": a Redis-backed session cookie/token is issued.
	//   - "both": both of the above; either grant allows the request.
	//   - "none": no grant (used by basic auth).
	//
	// When omitted, path mode defaults to "ip" and password mode defaults to
	// "session".
	GrantMode string `json:"grantMode,omitempty"`

	// LoginPath is the password login endpoint. It defaults to KnockPath in
	// password mode. GET/HEAD render the login page, POST logs in, and a POST
	// with action=logout revokes the current session. It must be a plain
	// absolute path: protocol-relative ("//host"), backslashes, percent-
	// encoding, whitespace and control characters are rejected.
	LoginPath string `json:"loginPath,omitempty"`

	// Realm scopes Redis keys, cookies and signed session tokens to one
	// middleware configuration. It defaults to the middleware name plus a short
	// digest of the auth endpoints, so same-named middlewares with different
	// endpoints do not share grants. Set it explicitly to keep keys stable
	// across configuration changes and whenever several deployments share the
	// same Redis database and keyPrefix.
	Realm string `json:"realm,omitempty"`

	// Users contains inline password entries. Multiple users/passwords are
	// supported. Prefer PasswordHash over Password, and prefer CredentialsFile
	// over inline values in production.
	Users []User `json:"users,omitempty"`

	// CredentialsFile points to a file containing one credential per line:
	//
	//   username:pbkdf2-sha256$...
	//   pbkdf2-sha256$...            # shared password, no username
	//   username:plain:password      # development only
	//
	// Blank lines and lines starting with "#" are ignored. The file is read at
	// middleware creation time; mount a Kubernetes Secret read-only.
	CredentialsFile string `json:"credentialsFile,omitempty"`

	// CredentialsEnv names an environment variable with the same line format
	// as CredentialsFile. It is a fallback for environments where a file mount
	// is not available.
	CredentialsEnv string `json:"credentialsEnv,omitempty"`

	// CookieName is the session cookie name. When empty it is derived from the
	// realm, so multiple middlewares on one host do not overwrite each other.
	CookieName string `json:"cookieName,omitempty"`

	// CookieSecret signs session cookies/tokens. It must be at least 32 bytes
	// and should be shared by all Traefik replicas. It is required when
	// GrantMode is "session" or "both"; "ip" does not issue sessions, so the
	// secret is optional there.
	CookieSecret string `json:"cookieSecret,omitempty"`

	// CookieSecretFile reads CookieSecret from a file. It takes precedence over
	// CookieSecretEnv and CookieSecret.
	CookieSecretFile string `json:"cookieSecretFile,omitempty"`

	// CookieSecretEnv names an environment variable containing CookieSecret.
	CookieSecretEnv string `json:"cookieSecretEnv,omitempty"`

	// CookieSecure marks the session cookie Secure. It defaults to true. It
	// must be true when CookieSameSite is None or the cookie name uses the
	// __Host- prefix.
	CookieSecure *bool `json:"cookieSecure,omitempty"`

	// CookieSameSite is Lax (default), Strict or None.
	CookieSameSite string `json:"cookieSameSite,omitempty"`

	// SessionTTL is the lifetime of a password session. It defaults to TTL.
	SessionTTL string `json:"sessionTTL,omitempty"`

	// MaxLoginAttempts is the number of login attempts allowed per client IP
	// inside LoginWindow. Every attempt counts before password verification;
	// a successful login clears the counter. It defaults to 5; 0 disables the
	// limit. Basic auth does not use this counter.
	MaxLoginAttempts int `json:"maxLoginAttempts,omitempty"`

	// LoginWindow is the login-attempt counter window. It defaults to 15m.
	LoginWindow string `json:"loginWindow,omitempty"`

	// MaxConcurrentLogins bounds concurrent password verifications per Traefik
	// process for both the login form and Basic auth, protecting CPU-intensive
	// KDFs. It defaults to 4; 0 disables the limit.
	MaxConcurrentLogins int `json:"maxConcurrentLogins,omitempty"`

	// PrivateResponses forces Cache-Control: private and Vary: Cookie,
	// Authorization on protected responses, so a CDN cannot cache content
	// authorized by a cookie/header and serve it to someone else. Stronger
	// backend directives (no-store, no-cache, must-revalidate) are preserved.
	// It defaults to true in every auth mode; set it to false only when a
	// shared cache is intentionally allowed to store protected responses.
	PrivateResponses *bool `json:"privateResponses,omitempty"`

	// ForwardUserHeader optionally forwards the authenticated username to the
	// backend in this header. Any client-supplied value is removed first. It is
	// empty by default; do not point it at a header the backend trusts unless
	// the backend is only reachable through Traefik.
	ForwardUserHeader string `json:"forwardUserHeader,omitempty"`
}

// CreateConfig returns a Config pre-filled with the production-safe defaults.
// Traefik decodes user configuration on top of this value.
func CreateConfig() *Config {
	return &Config{
		TTL:                 DefaultTTL.String(),
		KeyPrefix:           DefaultKeyPrefix,
		FailClosed:          boolPtr(true),
		DialTimeout:         defaultDialTimeout.String(),
		ReadTimeout:         defaultReadTimeout.String(),
		WriteTimeout:        defaultWriteTimeout.String(),
		RedisPoolSize:       defaultRedisPoolSize,
		RedisDB:             defaultRedisDB,
		AuthMode:            AuthModePath,
		CookieSecure:        boolPtr(true),
		CookieSameSite:      defaultCookieSameSite,
		MaxLoginAttempts:    defaultMaxLoginAttempts,
		LoginWindow:         defaultLoginWindow.String(),
		MaxConcurrentLogins: defaultMaxConcurrent,
		PrivateResponses:    boolPtr(true),
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
	redirectURL    string
	allowlist      *staticAllowlist

	authMode            string
	grantMode           string
	loginPath           string
	realm               string
	users               *userSet
	cookieName          string
	cookieSecret        []byte
	cookieSecure        bool
	cookieSameSite      http.SameSite
	sessionTTL          time.Duration
	maxLoginAttempts    int
	loginWindow         time.Duration
	maxConcurrentLogins int
	privateResponses    bool
	forwardUserHeader   string
}

// sessionGrantsEnabled reports whether this configuration accepts and issues
// Redis-backed sessions. With grantMode "ip" only IP grants are valid, even if
// a session token was created by an earlier configuration or a JSON login.
func (s *settings) sessionGrantsEnabled() bool {
	return s.grantMode == GrantModeSession || s.grantMode == GrantModeBoth
}

// Validate checks the configuration and returns a descriptive error when it is
// unusable. It is safe to call on a Config returned by CreateConfig.
func (c *Config) Validate() error {
	_, err := c.settingsFor("")
	return err
}

// settings validates the configuration with the default realm. New() uses
// settingsFor(name) so the realm defaults to the middleware name plus an
// endpoint digest.
func (c *Config) settings() (*settings, error) {
	return c.settingsFor("")
}

// settingsFor validates the configuration, applies defaults for any zero value
// that has one and returns the parsed result. name is the Traefik middleware
// name and is used as the default realm.
//
// The integer limits MaxLoginAttempts and MaxConcurrentLogins are pre-filled by
// CreateConfig; a Config built by hand gets 0, which disables those limits.
func (c *Config) settingsFor(name string) (*settings, error) {
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
		authMode:       strings.ToLower(strings.TrimSpace(c.AuthMode)),
		loginPath:      strings.TrimSpace(c.LoginPath),
		realm:          strings.TrimSpace(c.Realm),
	}

	if s.knockPath == "" {
		return nil, errors.New("http-knock: knockPath must not be empty")
	}
	if err := validateEndpointPath("knockPath", s.knockPath, minKnockPathLength); err != nil {
		return nil, err
	}

	if s.authMode == "" {
		s.authMode = AuthModePath
	}
	switch s.authMode {
	case AuthModePath:
	case AuthModePassword:
	case AuthModeBasic:
	default:
		return nil, fmt.Errorf("http-knock: authMode %q must be %q, %q or %q", c.AuthMode, AuthModePath, AuthModePassword, AuthModeBasic)
	}

	s.grantMode = strings.ToLower(strings.TrimSpace(c.GrantMode))
	if s.grantMode == "" {
		switch s.authMode {
		case AuthModePassword:
			s.grantMode = GrantModeSession
		case AuthModeBasic:
			s.grantMode = GrantModeNone
		default:
			s.grantMode = GrantModeIP
		}
	}
	switch s.grantMode {
	case GrantModeIP:
	case GrantModeSession:
	case GrantModeBoth:
	case GrantModeNone:
	default:
		return nil, fmt.Errorf("http-knock: grantMode %q must be %q, %q, %q or %q", c.GrantMode, GrantModeIP, GrantModeSession, GrantModeBoth, GrantModeNone)
	}

	if s.authMode == AuthModePath && s.grantMode != GrantModeIP {
		return nil, errors.New("http-knock: authMode path only supports grantMode ip")
	}
	if s.authMode == AuthModeBasic && s.grantMode != GrantModeNone {
		return nil, errors.New("http-knock: authMode basic does not use a grant mode")
	}
	if s.authMode == AuthModePassword && s.grantMode == GrantModeNone {
		return nil, errors.New("http-knock: authMode password requires grantMode ip, session or both")
	}

	if s.loginPath == "" {
		if s.authMode == AuthModePassword {
			s.loginPath = s.knockPath
		}
	} else {
		if err := validateEndpointPath("loginPath", s.loginPath, 2); err != nil {
			return nil, err
		}
	}

	if s.realm == "" {
		s.realm = defaultRealm(name, s.authMode, s.knockPath, s.loginPath)
	}
	if !validRealm(s.realm) {
		return nil, fmt.Errorf("http-knock: realm %q contains unsupported characters", s.realm)
	}

	if s.authMode == AuthModePath {
		if len(c.Users) > 0 || c.CredentialsFile != "" || c.CredentialsEnv != "" {
			return nil, errors.New("http-knock: users/credentialsFile/credentialsEnv require authMode password or basic")
		}
	} else {
		users, err := buildUserSet(c.Users, c.CredentialsFile, c.CredentialsEnv)
		if err != nil {
			return nil, err
		}
		s.users = users
	}

	needRedis := s.authMode == AuthModePath || s.authMode == AuthModePassword
	needCookies := s.authMode == AuthModePassword
	needSessionSecret := needCookies && s.sessionGrantsEnabled()

	if needRedis {
		if s.redisAddr == "" {
			return nil, errors.New("http-knock: redisAddr must not be empty")
		}
		if _, _, err := net.SplitHostPort(s.redisAddr); err != nil {
			return nil, fmt.Errorf("http-knock: redisAddr must be in host:port form: %v", err)
		}
		if s.redisDB < 0 {
			return nil, fmt.Errorf("http-knock: redisDB must not be negative, got %d", s.redisDB)
		}
	}
	if s.clientIPHeader != "" && !validHeaderName(s.clientIPHeader) {
		return nil, fmt.Errorf("http-knock: clientIPHeader %q is not a valid HTTP header name", c.ClientIPHeader)
	}

	if needRedis {
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

		poolSize, err := parsePoolSize(c.RedisPoolSize)
		if err != nil {
			return nil, err
		}
		s.redisPoolSize = poolSize
	} else {
		// Basic auth is stateless and never contacts Redis. Keep the defaults so
		// settings has no zero-value surprises, but do not reject Redis settings
		// that this mode does not use.
		s.ttl = DefaultTTL
		s.dialTimeout = defaultDialTimeout
		s.readTimeout = defaultReadTimeout
		s.writeTimeout = defaultWriteTimeout
		s.redisPoolSize = defaultRedisPoolSize
	}

	if needRedis {
		if s.keyPrefix == "" {
			s.keyPrefix = DefaultKeyPrefix
		}
		if !validKeyPrefix(s.keyPrefix) {
			return nil, errors.New("http-knock: keyPrefix must not contain whitespace or control characters")
		}
	} else {
		s.keyPrefix = DefaultKeyPrefix
	}

	redirectURL, err := parseRedirectURL(c.RedirectURL)
	if err != nil {
		return nil, err
	}
	s.redirectURL = redirectURL

	allowlist, err := parseStaticAllowlist(c.StaticAllowlist)
	if err != nil {
		return nil, err
	}
	s.allowlist = allowlist

	s.failClosed = c.FailClosed == nil || *c.FailClosed

	if needSessionSecret {
		sessionTTL, err := parseDuration("sessionTTL", c.SessionTTL, s.ttl)
		if err != nil {
			return nil, err
		}
		s.sessionTTL = sessionTTL
	} else {
		// grantMode ip issues no session/token, so sessionTTL is not used.
		s.sessionTTL = s.ttl
	}

	if s.authMode == AuthModePassword && c.MaxLoginAttempts > 0 {
		loginWindow, err := parseDuration("loginWindow", c.LoginWindow, defaultLoginWindow)
		if err != nil {
			return nil, err
		}
		s.loginWindow = loginWindow
	} else {
		// Basic and path mode never reserve login attempts, and setting
		// maxLoginAttempts to 0 disables the limiter entirely.
		s.loginWindow = defaultLoginWindow
	}
	if c.MaxLoginAttempts < 0 {
		return nil, fmt.Errorf("http-knock: maxLoginAttempts must not be negative, got %d", c.MaxLoginAttempts)
	}
	s.maxLoginAttempts = c.MaxLoginAttempts
	if c.MaxConcurrentLogins < 0 {
		return nil, fmt.Errorf("http-knock: maxConcurrentLogins must not be negative, got %d", c.MaxConcurrentLogins)
	}
	s.maxConcurrentLogins = c.MaxConcurrentLogins

	s.cookieSecure = true
	s.cookieSameSite = http.SameSiteLaxMode
	if needCookies {
		if c.CookieSecure != nil {
			s.cookieSecure = *c.CookieSecure
		}
		sameSite, err := parseSameSite(c.CookieSameSite)
		if err != nil {
			return nil, err
		}
		s.cookieSameSite = sameSite

		s.cookieName = strings.TrimSpace(c.CookieName)
		if s.cookieName == "" {
			s.cookieName = cookieNameFor(s.realm, s.cookieSecure)
		}
		if !validCookieName(s.cookieName) {
			return nil, fmt.Errorf("http-knock: cookieName %q is not a valid cookie name", s.cookieName)
		}
		if strings.HasPrefix(s.cookieName, "__Host-") && !s.cookieSecure {
			return nil, errors.New("http-knock: a __Host- cookie requires cookieSecure: true")
		}
		if s.cookieSameSite == http.SameSiteNoneMode && !s.cookieSecure {
			return nil, errors.New("http-knock: cookieSameSite None requires cookieSecure: true")
		}

		// A session secret is mandatory only when sessions are issued/accepted
		// (grantMode session or both). In grantMode ip nothing is signed, but a
		// secret that the operator did provide is still validated so a future
		// switch to session mode cannot silently run with a weak value.
		providedSecret := c.CookieSecret != "" || c.CookieSecretFile != "" || c.CookieSecretEnv != ""
		if needSessionSecret || providedSecret {
			secret, err := loadSecret(c.CookieSecret, c.CookieSecretFile, c.CookieSecretEnv, "cookieSecret")
			if err != nil {
				return nil, err
			}
			if len(secret) < minCookieSecretLength {
				return nil, fmt.Errorf("http-knock: cookieSecret must be at least %d bytes", minCookieSecretLength)
			}
			s.cookieSecret = secret
		}
	}

	s.forwardUserHeader = http.CanonicalHeaderKey(strings.TrimSpace(c.ForwardUserHeader))
	if s.forwardUserHeader != "" {
		if !validHeaderName(s.forwardUserHeader) {
			return nil, fmt.Errorf("http-knock: forwardUserHeader %q is not a valid HTTP header name", c.ForwardUserHeader)
		}
		switch strings.ToLower(s.forwardUserHeader) {
		case "authorization":
			return nil, errors.New("http-knock: forwardUserHeader must not overwrite Authorization")
		case "cookie":
			return nil, errors.New("http-knock: forwardUserHeader must not overwrite Cookie")
		case "host":
			return nil, errors.New("http-knock: forwardUserHeader must not overwrite Host")
		}
	}

	if c.PrivateResponses != nil {
		s.privateResponses = *c.PrivateResponses
	} else {
		s.privateResponses = true
	}

	return s, nil
}

// validateEndpointPath validates an exact-match endpoint path. Error messages
// deliberately do not include the configured value: knockPath is a secret and
// must not leak into startup logs just because it is malformed.
func validateEndpointPath(field, value string, minLength int) error {
	if value == "" {
		return fmt.Errorf("http-knock: %s must not be empty", field)
	}
	if !strings.HasPrefix(value, "/") {
		return fmt.Errorf("http-knock: %s must start with %q", field, "/")
	}
	if strings.HasPrefix(value, "//") {
		return fmt.Errorf("http-knock: %s must not be protocol-relative (start with %q)", field, "//")
	}
	if strings.ContainsAny(value, "?#") {
		return fmt.Errorf("http-knock: %s must not contain a query or fragment", field)
	}
	// Reject characters that are ambiguous in URLs or HTTP headers. In
	// particular a backslash is normalised to "/" by browsers (so "/\evil"
	// becomes "//evil"), and percent-encoded paths never match req.URL.Path,
	// which is decoded.
	for _, r := range value {
		if r <= 0x20 || r == 0x7f || r == '\\' || r == '%' {
			return fmt.Errorf("http-knock: %s must not contain whitespace, control characters, backslashes or percent-encoding", field)
		}
	}
	if strings.EqualFold(value, "/") {
		return fmt.Errorf("http-knock: %s must not be \"/\"", field)
	}
	if len(value) < minLength {
		return fmt.Errorf("http-knock: %s must be at least %d characters long", field, minLength)
	}
	if len(value) > maxKnockPathLength {
		return fmt.Errorf("http-knock: %s must be at most %d characters long", field, maxKnockPathLength)
	}
	return nil
}

// defaultRealm scopes Redis keys, cookies and signed tokens to one middleware
// configuration. The middleware name alone can be identical in two deployments
// that share Redis (for example separate clusters or providers that pass a bare
// name), so a short digest of the endpoint configuration is appended. The digest
// does not contain the endpoint values, but a deliberately weak path secret
// could still be brute-forced by someone who can read Redis; use a 128-bit
// random path. An explicit realm is still required to isolate deployments that
// share both the name and the endpoints.
func defaultRealm(name, authMode, knockPath, loginPath string) string {
	if name == "" {
		name = "default"
	}
	seed := authMode + "\x00" + knockPath + "\x00" + loginPath
	return name + "-" + sha256Hex(seed)[:16]
}

func validRealm(realm string) bool {
	if realm == "" || len(realm) > 128 {
		return false
	}
	for i := 0; i < len(realm); i++ {
		c := realm[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '.':
		case c == '_':
		case c == '-':
		case c == '@':
		case c == ':':
		case c == '/':
		default:
			return false
		}
	}
	return true
}

func validKeyPrefix(prefix string) bool {
	if prefix == "" {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if c <= 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func parsePoolSize(value int) (int, error) {
	if value == 0 {
		return defaultRedisPoolSize, nil
	}
	if value < 1 {
		return 0, fmt.Errorf("http-knock: redisPoolSize must be positive, got %d", value)
	}
	return value, nil
}

// parseRedirectURL validates the post-knock redirect target. An empty value
// disables the redirect. Only absolute http(s) URLs and same-origin absolute
// paths are accepted; protocol-relative ("//host") and non-HTTP schemes are
// rejected so a misconfiguration cannot become an open redirect.
func parseRedirectURL(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}

	// Reject control characters and backslashes outright. Browsers normalise
	// "\" to "/" for http(s) URLs, so "/\evil.example" would otherwise be
	// parsed as the protocol-relative "//evil.example" and escape the origin.
	for _, r := range value {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return "", fmt.Errorf("http-knock: redirectURL %q must not contain control characters or backslashes", value)
		}
	}

	if strings.HasPrefix(value, "/") {
		if strings.HasPrefix(value, "//") {
			return "", fmt.Errorf("http-knock: redirectURL %q must not be protocol-relative; use an absolute http(s) URL", value)
		}
		return value, nil
	}

	u, err := url.Parse(value)
	if err != nil {
		return "", fmt.Errorf("http-knock: redirectURL %q is not a valid URL: %w", value, err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", fmt.Errorf("http-knock: redirectURL %q must be an absolute http(s) URL or a path starting with %q", value, "/")
	}
	return value, nil
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

// knockVerifier decides whether a request is a path-mode knock attempt and
// whether it is authorized. Password, Basic and Bearer authentication live in
// the dedicated handlers in auth.go and knock.go.
type knockVerifier interface {
	// Matches reports whether the request targets the knock endpoint.
	Matches(req *http.Request) bool
	// Authorize validates a knock attempt for the given, already normalized
	// client IP. Returning false results in 403.
	Authorize(req *http.Request, clientIP string) bool
}

// pathVerifier authorizes a knock when the request path equals the configured
// secret path exactly. The middleware only calls it for GET requests, so a
// non-GET request to the path is handled like any other protected request and
// cannot confirm a guessed secret through a distinct status code.
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
	next       http.Handler
	cfg        *settings
	verifier   knockVerifier
	redis      *redisClient
	logger     *log.Logger
	loginSlots chan struct{}
}

// New is the Traefik plugin constructor. Traefik calls it once per configured
// middleware instance.
//
// Redis is intentionally not contacted here: a Redis outage must not prevent
// Traefik from loading its configuration. Connectivity problems surface per
// request and are handled according to failClosed (or always fail closed for
// session lookups).
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if next == nil {
		return nil, errors.New("http-knock: next handler must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("http-knock: %w", err)
	}

	cfg, err := config.settingsFor(name)
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
	if cfg.maxConcurrentLogins > 0 {
		m.loginSlots = make(chan struct{}, cfg.maxConcurrentLogins)
	}

	return m, nil
}

// ServeHTTP dispatches to the configured authentication mode.
func (m *middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	switch m.cfg.authMode {
	case AuthModePassword:
		if m.isLoginPath(req) {
			m.handleLogin(rw, req)
			return
		}
		m.handlePasswordProtected(rw, req)
	case AuthModeBasic:
		m.handleBasicProtected(rw, req)
	default:
		// A path knock is "GET <knockPath>". Requiring GET keeps a non-GET
		// request to the secret path indistinguishable from any other
		// protected path, so it cannot confirm a guessed secret.
		if req.Method == http.MethodGet && m.verifier.Matches(req) {
			m.handlePathKnock(rw, req)
			return
		}
		m.handlePathProtected(rw, req)
	}
}

func (m *middleware) isLoginPath(req *http.Request) bool {
	return m.cfg.loginPath != "" && constantTimeEqualString(req.URL.Path, m.cfg.loginPath)
}

// handlePathKnock is the original secret-path knock. It stores the client IP in
// the realm-scoped Redis key and never forwards the request to the backend.
func (m *middleware) handlePathKnock(rw http.ResponseWriter, req *http.Request) {
	ip, err := clientIPFromRequest(req, m.cfg.clientIPHeader)
	if err != nil {
		// Deliberately 403 and not 400: do not confirm that the path matched.
		m.logf("knock rejected: %v", err)
		m.writeError(rw, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		return
	}

	if !m.verifier.Authorize(req, ip) {
		m.logf("knock rejected: invalid token for client %s", m.clientLabel(ip))
		m.writeError(rw, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		return
	}

	if err := m.redis.setEx(ipGrantKey(m.cfg.keyPrefix, m.cfg.realm, ip), knockValue, m.cfg.ttl); err != nil {
		m.logf("redis unavailable during knock for client %s: %v", m.clientLabel(ip), err)
		m.writeKnockFailure(rw)
		return
	}

	m.logf("knock succeeded for client %s", m.clientLabel(ip))
	setNoStore(rw.Header())
	rw.Header().Set(knockTTLHeader, m.cfg.ttl.String())

	if m.cfg.redirectURL != "" {
		rw.Header().Set("Location", m.cfg.redirectURL)
		rw.WriteHeader(http.StatusSeeOther)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// handlePathProtected is the original IP allowlist check, now with a
// realm-scoped key and cache isolation for CDN deployments.
func (m *middleware) handlePathProtected(rw http.ResponseWriter, req *http.Request) {
	ip, err := clientIPFromRequest(req, m.cfg.clientIPHeader)
	if err != nil {
		m.logf("request denied: %v", err)
		m.writeError(rw, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		return
	}

	if m.cfg.allowlist.contains(ip) {
		m.logf("request allowed for client %s: static allowlist", m.clientLabel(ip))
		m.serveNext(rw, req, "")
		return
	}

	allowed, err := m.ipGrantAllowed(ip)
	if err != nil {
		m.logf("redis unavailable for client %s: %v", m.clientLabel(ip), err)
		m.writeRedisFailure(rw, req)
		return
	}
	if !allowed {
		m.logf("request denied for client %s: no active knock", m.clientLabel(ip))
		m.writeError(rw, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		return
	}

	m.serveNext(rw, req, "")
}

// handleBasicProtected verifies HTTP Basic credentials on every request. It
// deliberately does not use Redis: this mode is for API/CLI clients that should
// keep working independently of the session store.
func (m *middleware) handleBasicProtected(rw http.ResponseWriter, req *http.Request) {
	ip, err := clientIPFromRequest(req, m.cfg.clientIPHeader)
	if err != nil {
		m.logf("request denied: %v", err)
		m.writeError(rw, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		return
	}
	if m.cfg.allowlist.contains(ip) {
		m.logf("request allowed for client %s: static allowlist", m.clientLabel(ip))
		m.serveNext(rw, req, "")
		return
	}

	username, password, ok := req.BasicAuth()
	if !ok {
		m.writeBasicChallenge(rw)
		return
	}

	// Every Basic request verifies the password with PBKDF2. Without a bound an
	// unauthenticated client could pin all CPU cores with a burst of requests
	// and flood the log with failures, so Basic uses the same KDF semaphore as
	// the login form.
	if !m.acquireLoginSlot() {
		rw.Header().Set("Retry-After", "1")
		m.writeError(rw, http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests))
		return
	}
	defer m.releaseLoginSlot()

	user, ok := m.cfg.users.authenticate(username, password)
	if !ok {
		m.logf("basic auth failed for client %s", m.clientLabel(ip))
		m.writeBasicChallenge(rw)
		return
	}

	m.serveNext(rw, req, user.username)
}

// handlePasswordProtected validates a Bearer session token, a session cookie,
// or an IP grant, in that order. Sessions are only accepted when grantMode is
// "session" or "both"; with grantMode "ip" a token from an earlier
// configuration must not keep working.
func (m *middleware) handlePasswordProtected(rw http.ResponseWriter, req *http.Request) {
	ip, err := clientIPFromRequest(req, m.cfg.clientIPHeader)
	if err != nil {
		m.logf("request denied: %v", err)
		m.writeError(rw, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		return
	}

	if m.cfg.allowlist.contains(ip) {
		m.logf("request allowed for client %s: static allowlist", m.clientLabel(ip))
		m.serveNext(rw, req, "")
		return
	}

	if m.cfg.sessionGrantsEnabled() {
		// An explicit Authorization header is authoritative: if it is present
		// but invalid we do not silently fall back to a cookie/IP grant.
		if hasAuthorization(req) {
			token, ok := bearerToken(req)
			if !ok {
				m.writeUnauthorized(rw, "bearer")
				return
			}
			user, ok, err := m.lookupSession(token)
			if err != nil {
				m.logf("redis unavailable for session of client %s: %v", m.clientLabel(ip), err)
				// Session cookies/tokens are unusable while Redis is down, even
				// when failClosed is false: otherwise a password session would
				// silently turn into a fail-open bypass.
				m.writeError(rw, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
				return
			}
			if !ok {
				m.writeUnauthorized(rw, "bearer")
				return
			}
			m.serveNext(rw, req, user.username)
			return
		}

		if token, ok := m.sessionCookie(req); ok {
			user, valid, err := m.lookupSession(token)
			if err != nil {
				m.logf("redis unavailable for session of client %s: %v", m.clientLabel(ip), err)
				m.writeError(rw, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
				return
			}
			if valid {
				m.serveNext(rw, req, user.username)
				return
			}
			m.clearSessionCookie(rw)
		}
	}

	if m.cfg.grantMode == GrantModeIP || m.cfg.grantMode == GrantModeBoth {
		allowed, err := m.ipGrantAllowed(ip)
		if err != nil {
			m.logf("redis unavailable for client %s: %v", m.clientLabel(ip), err)
			m.writeRedisFailure(rw, req)
			return
		}
		if allowed {
			m.serveNext(rw, req, "")
			return
		}
	}

	m.logf("request denied for client %s: no valid session or grant", m.clientLabel(ip))
	m.writeError(rw, http.StatusForbidden, http.StatusText(http.StatusForbidden))
}

func (m *middleware) handleLogin(rw http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodGet || req.Method == http.MethodHead {
		if m.cfg.sessionGrantsEnabled() {
			if token, ok := m.sessionCookie(req); ok {
				_, valid, err := m.lookupSession(token)
				if err != nil {
					m.writeError(rw, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
					return
				}
				if valid {
					m.redirectAfterAuth(rw)
					return
				}
				m.clearSessionCookie(rw)
			}
		}
		m.renderLoginPage(rw, http.StatusOK, "")
		return
	}

	if req.Method != http.MethodPost {
		rw.Header().Set("Allow", "GET, HEAD, POST")
		m.writeError(rw, http.StatusMethodNotAllowed, http.StatusText(http.StatusMethodNotAllowed))
		return
	}

	m.handleLoginPost(rw, req)
}

type loginResponse struct {
	OK        bool   `json:"ok"`
	Username  string `json:"username,omitempty"`
	Token     string `json:"token,omitempty"`
	ExpiresIn int    `json:"expiresIn,omitempty"`
}

func (m *middleware) handleLoginPost(rw http.ResponseWriter, req *http.Request) {
	// Browsers send Origin (and Sec-Fetch-Site) on cross-origin POSTs. Reject
	// those before touching any state: SameSite cookies do not prevent a
	// cross-site form from logging a victim into an attacker's account.
	if !sameOriginPost(req) {
		m.logf("login/logout rejected: cross-origin request")
		m.writeLoginError(rw, req, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		return
	}

	req.Body = http.MaxBytesReader(rw, req.Body, maxLoginBodyBytes)
	if err := req.ParseForm(); err != nil {
		m.writeLoginError(rw, req, http.StatusBadRequest, "invalid form")
		return
	}

	if strings.EqualFold(req.PostFormValue("action"), "logout") {
		m.handleLogout(rw, req)
		return
	}

	ip, err := clientIPFromRequest(req, m.cfg.clientIPHeader)
	if err != nil {
		m.logf("login rejected: %v", err)
		m.writeLoginError(rw, req, http.StatusForbidden, http.StatusText(http.StatusForbidden))
		return
	}

	// Bound concurrent KDF work before reserving an attempt, so a burst that is
	// rejected for concurrency does not consume the client's login budget.
	if !m.acquireLoginSlot() {
		rw.Header().Set("Retry-After", "1")
		m.writeLoginError(rw, req, http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests))
		return
	}
	defer m.releaseLoginSlot()

	allowed, err := m.reserveLoginAttempt(ip)
	if err != nil {
		m.logf("redis unavailable during login for client %s: %v", m.clientLabel(ip), err)
		m.writeLoginError(rw, req, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
		return
	}
	if !allowed {
		rw.Header().Set("Retry-After", fmt.Sprintf("%d", durationSeconds(m.cfg.loginWindow)))
		m.writeLoginError(rw, req, http.StatusTooManyRequests, http.StatusText(http.StatusTooManyRequests))
		return
	}

	// Only accept credentials from the POST body, never from the query string:
	// a password in the URL would leak into access logs and Referer headers.
	username := strings.TrimSpace(req.PostFormValue("username"))
	password := req.PostFormValue("password")
	user, ok := m.cfg.users.authenticate(username, password)
	if !ok {
		// The failed attempt was already counted by reserveLoginAttempt.
		m.logf("login failed for client %s", m.clientLabel(ip))
		if wantsJSON(req) {
			m.writeJSON(rw, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
			return
		}
		m.renderLoginPage(rw, http.StatusUnauthorized, "Invalid username or password.")
		return
	}

	if err := m.clearLoginFailures(ip); err != nil {
		m.logf("cannot clear failed-login counter for client %s: %v", m.clientLabel(ip), err)
	}
	m.logf("login succeeded for client %s", m.clientLabel(ip))

	// Sessions are only issued and accepted for grantMode session/both. In ip
	// mode a JSON login deliberately returns no token: an IP grant is the only
	// credential, and a token issued here would outlive a switch to ip mode.
	sessionNeeded := m.cfg.sessionGrantsEnabled()
	token := ""
	if sessionNeeded {
		var err error
		token, err = m.createSession(user)
		if err != nil {
			m.logf("cannot create session for client %s: %v", m.clientLabel(ip), err)
			m.writeLoginError(rw, req, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
			return
		}
	}

	if m.cfg.grantMode == GrantModeIP || m.cfg.grantMode == GrantModeBoth {
		if err := m.redis.setEx(ipGrantKey(m.cfg.keyPrefix, m.cfg.realm, ip), sessionValue(user), m.cfg.ttl); err != nil {
			m.logf("redis unavailable during login for client %s: %v", m.clientLabel(ip), err)
			if token != "" {
				if sessionID, ok := parseSessionToken(m.cfg.cookieSecret, m.cfg.realm, token); ok {
					_ = m.redis.del(sessionRedisKey(m.cfg.keyPrefix, m.cfg.realm, sessionID))
				}
			}
			m.writeLoginError(rw, req, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
			return
		}
	}

	// Set the cookie only after every grant has been persisted, so a failed IP
	// grant cannot leave a valid session cookie in a 503 response.
	if sessionNeeded && token != "" {
		m.setSessionCookie(rw, token)
	}

	setNoStore(rw.Header())
	if wantsJSON(req) {
		response := loginResponse{OK: true, Username: user.username}
		if token != "" {
			response.Token = token
			response.ExpiresIn = durationSeconds(m.cfg.sessionTTL)
		}
		m.writeJSON(rw, http.StatusOK, response)
		return
	}

	if m.cfg.redirectURL != "" {
		rw.Header().Set("Location", m.cfg.redirectURL)
		rw.WriteHeader(http.StatusSeeOther)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

func (m *middleware) handleLogout(rw http.ResponseWriter, req *http.Request) {
	ip, _ := clientIPFromRequest(req, m.cfg.clientIPHeader)
	var tokens []string
	// Session tokens only exist when session grants are enabled. A secret can
	// still be configured in grantMode ip (to revoke sessions left by an older
	// configuration), but without one there is nothing this mode can parse.
	if m.cfg.sessionGrantsEnabled() || len(m.cfg.cookieSecret) > 0 {
		if cookieToken, ok := m.sessionCookie(req); ok {
			tokens = append(tokens, cookieToken)
		}
		if bearer, ok := bearerToken(req); ok && (len(tokens) == 0 || tokens[0] != bearer) {
			tokens = append(tokens, bearer)
		}
	}

	var deleteErr error
	for _, token := range tokens {
		if sessionID, ok := parseSessionToken(m.cfg.cookieSecret, m.cfg.realm, token); ok {
			if err := m.redis.del(sessionRedisKey(m.cfg.keyPrefix, m.cfg.realm, sessionID)); err != nil {
				deleteErr = err
			}
		}
	}
	if ip != "" && (m.cfg.grantMode == GrantModeIP || m.cfg.grantMode == GrantModeBoth) {
		if err := m.redis.del(ipGrantKey(m.cfg.keyPrefix, m.cfg.realm, ip)); err != nil {
			deleteErr = err
		}
	}

	if deleteErr != nil {
		m.logf("logout could not revoke state for client %s: %v", m.clientLabel(ip), deleteErr)
		// Keep the cookie: the server-side session is still valid, so clearing
		// it locally would only make a retry impossible while leaving a stolen
		// token usable until TTL.
		m.writeLoginError(rw, req, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
		return
	}

	m.clearSessionCookie(rw)
	m.logf("logout succeeded for client %s", m.clientLabel(ip))
	if wantsJSON(req) {
		m.writeJSON(rw, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	m.redirectAfterLogout(rw)
}

func (m *middleware) createSession(user *userCredential) (string, error) {
	sessionID, err := newSessionID()
	if err != nil {
		return "", err
	}
	if err := m.redis.setEx(sessionRedisKey(m.cfg.keyPrefix, m.cfg.realm, sessionID), sessionValue(user), m.cfg.sessionTTL); err != nil {
		return "", err
	}
	return signSessionToken(m.cfg.cookieSecret, m.cfg.realm, sessionID), nil
}

// ipGrantAllowed reports whether the client IP has a live grant. Path-mode
// grants must contain the legacy "1" marker; a value written by password mode
// (or anything else) cannot authorize them. Password-mode grants store the
// credential fingerprint, so changing a password or removing a user also
// revokes the IP grant.
func (m *middleware) ipGrantAllowed(ip string) (bool, error) {
	key := ipGrantKey(m.cfg.keyPrefix, m.cfg.realm, ip)
	value, ok, err := m.redis.getValue(key)
	if err != nil {
		return false, err
	}
	if !ok {
		return false, nil
	}

	if m.cfg.authMode != AuthModePassword {
		if value != knockValue {
			_ = m.redis.del(key)
			return false, nil
		}
		return true, nil
	}

	username, fingerprint, ok := parseSessionValue(value)
	if !ok {
		// A path-mode ("1") or otherwise malformed value cannot authorize a
		// password-mode request; drop it so it cannot linger until TTL.
		_ = m.redis.del(key)
		return false, nil
	}
	if _, valid := m.cfg.users.findByFingerprint(username, fingerprint); !valid {
		// The password changed or the user was removed.
		_ = m.redis.del(key)
		return false, nil
	}
	return true, nil
}

func (m *middleware) lookupSession(token string) (*userCredential, bool, error) {
	sessionID, ok := parseSessionToken(m.cfg.cookieSecret, m.cfg.realm, token)
	if !ok {
		return nil, false, nil
	}
	value, ok, err := m.redis.getValue(sessionRedisKey(m.cfg.keyPrefix, m.cfg.realm, sessionID))
	if err != nil {
		return nil, false, err
	}
	if !ok {
		return nil, false, nil
	}

	username, fingerprint, ok := parseSessionValue(value)
	if !ok {
		_ = m.redis.del(sessionRedisKey(m.cfg.keyPrefix, m.cfg.realm, sessionID))
		return nil, false, nil
	}
	user, ok := m.cfg.users.findByFingerprint(username, fingerprint)
	if !ok {
		// The password changed or the user was removed: revoke the session.
		_ = m.redis.del(sessionRedisKey(m.cfg.keyPrefix, m.cfg.realm, sessionID))
		return nil, false, nil
	}
	return user, true, nil
}

func (m *middleware) redirectAfterAuth(rw http.ResponseWriter) {
	setNoStore(rw.Header())
	if m.cfg.redirectURL != "" {
		rw.Header().Set("Location", m.cfg.redirectURL)
		rw.WriteHeader(http.StatusSeeOther)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

// redirectAfterLogout sends the browser back to the login page, not to a
// protected page that would immediately answer 403 after the cookie is gone.
func (m *middleware) redirectAfterLogout(rw http.ResponseWriter) {
	setNoStore(rw.Header())
	if m.cfg.loginPath != "" {
		rw.Header().Set("Location", m.cfg.loginPath)
		rw.WriteHeader(http.StatusSeeOther)
		return
	}
	rw.WriteHeader(http.StatusNoContent)
}

func (m *middleware) writeBasicChallenge(rw http.ResponseWriter) {
	setNoStore(rw.Header())
	rw.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q, charset=\"UTF-8\"", m.cfg.realm))
	http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func (m *middleware) writeUnauthorized(rw http.ResponseWriter, scheme string) {
	setNoStore(rw.Header())
	if scheme == "bearer" {
		rw.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer realm=%q", m.cfg.realm))
	}
	http.Error(rw, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
}

func (m *middleware) writeJSON(rw http.ResponseWriter, status int, value interface{}) {
	setNoStore(rw.Header())
	rw.Header().Set("Content-Type", "application/json; charset=utf-8")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.WriteHeader(status)
	_ = json.NewEncoder(rw).Encode(value)
}

// writeLoginError returns JSON to API clients and plain text to browsers.
func (m *middleware) writeLoginError(rw http.ResponseWriter, req *http.Request, status int, message string) {
	if wantsJSON(req) {
		m.writeJSON(rw, status, map[string]string{"error": message})
		return
	}
	m.writeError(rw, status, message)
}

func (m *middleware) writeError(rw http.ResponseWriter, status int, message string) {
	setNoStore(rw.Header())
	http.Error(rw, message, status)
}

func (m *middleware) serveNext(rw http.ResponseWriter, req *http.Request, username string) {
	m.applyForwardUser(req, username)
	if m.cfg.privateResponses {
		// Set the headers before the backend runs as well, so a backend that
		// returns without writing still cannot leave an implicit 200 cacheable.
		// The wrapper re-applies them at WriteHeader time in case the backend
		// overwrites or weakens them.
		applyPrivateHeaders(rw.Header())
		private := newPrivateResponseWriter(rw)
		m.next.ServeHTTP(private, req)
		private.finish()
		return
	}
	m.next.ServeHTTP(rw, req)
}

func (m *middleware) applyForwardUser(req *http.Request, username string) {
	if m.cfg.forwardUserHeader == "" {
		return
	}
	// Never trust a value supplied by the client.
	req.Header.Del(m.cfg.forwardUserHeader)
	if username != "" {
		req.Header.Set(m.cfg.forwardUserHeader, username)
	}
}

// writeRedisFailure applies the failClosed policy for IP allowlist lookups.
// Session lookups always fail closed, because a password cookie must not keep
// working while the session store is unavailable.
func (m *middleware) writeRedisFailure(rw http.ResponseWriter, req *http.Request) {
	if !m.cfg.failClosed {
		m.logf("redis unavailable: failClosed is false, forwarding request")
		m.serveNext(rw, req, "")
		return
	}
	m.writeError(rw, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
}

// writeKnockFailure reports a state-store failure for a knock. A knock is never
// forwarded to the backend, even when failClosed is false: the knock URL
// carries the secret.
func (m *middleware) writeKnockFailure(rw http.ResponseWriter) {
	m.writeError(rw, http.StatusServiceUnavailable, http.StatusText(http.StatusServiceUnavailable))
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

// redisTTLSeconds converts a duration to the integer seconds used by Redis
// "SET ... EX". Redis requires at least 1 second.
func redisTTLSeconds(ttl time.Duration) int64 {
	seconds := int64(ttl / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}
