package traefik_http_knock

import (
	"errors"
	"fmt"
	"html"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
	// AuthModePath is the original secret-path knock mode.
	AuthModePath = "path"
	// AuthModePassword enables the password login form, session cookies and
	// Bearer session tokens.
	AuthModePassword = "password"
	// AuthModeBasic verifies HTTP Basic credentials on every request. It keeps
	// no server-side state and therefore does not use Redis for access.
	AuthModeBasic = "basic"

	// GrantModeIP stores the client IP in Redis (the original behaviour).
	GrantModeIP = "ip"
	// GrantModeSession stores a session in Redis and sends a session cookie.
	GrantModeSession = "session"
	// GrantModeBoth issues both an IP grant and a session grant.
	GrantModeBoth = "both"
	// GrantModeNone is used by stateless Basic authentication.
	GrantModeNone = "none"

	defaultCookieSameSite   = "Lax"
	defaultLoginWindow      = 15 * time.Minute
	defaultMaxLoginAttempts = 5
	defaultMaxConcurrent    = 4

	minCookieSecretLength = 32
	maxLoginBodyBytes     = 8 << 10 // 8 KiB is enough for a login form
)

// User is one password entry. Multiple users/passwords can be configured:
//
//	users:
//	  - username: alice
//	    passwordHash: "pbkdf2-sha256$600000$...$..."
//	  - username: bob
//	    passwordHash: "pbkdf2-sha256$600000$...$..."
//
// Username may be empty for a shared password. Password may be set instead of
// PasswordHash for local development/tests; production deployments should use
// PasswordHash or CredentialsFile.
type User struct {
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	PasswordHash string `json:"passwordHash,omitempty"`
}

// userCredential is the parsed, ready-to-verify form of a User.
type userCredential struct {
	username    string
	plain       string
	hash        *passwordHash
	fingerprint string
}

func (u *userCredential) verifyPassword(password string) bool {
	if u == nil || password == "" {
		return false
	}
	if u.hash != nil {
		return u.hash.verifyPassword(password)
	}
	return constantTimeEqualString(u.plain, password)
}

// userSet indexes credentials for form, Basic and session lookups.
type userSet struct {
	all          []*userCredential
	byName       map[string]*userCredential
	shared       []*userCredential
	hasUsernames bool
}

// buildUserSet combines inline users with the optional credentials file and
// environment variable. File/env lines use "username:secret"; a line without a
// colon is a shared password. Blank lines and lines starting with "#" are
// ignored. A secret prefixed with "plain:" is treated as a plaintext password.
func buildUserSet(inline []User, file, envName string) (*userSet, error) {
	var entries []User
	entries = append(entries, inline...)

	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("http-knock: cannot read credentialsFile: %w", err)
		}
		parsed, err := parseCredentialLines(string(data))
		if err != nil {
			return nil, err
		}
		entries = append(entries, parsed...)
	}

	if envName != "" {
		value, ok := os.LookupEnv(envName)
		if !ok || strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("http-knock: credentialsEnv %q is empty or not set", envName)
		}
		parsed, err := parseCredentialLines(value)
		if err != nil {
			return nil, err
		}
		entries = append(entries, parsed...)
	}

	if len(entries) == 0 {
		return nil, errors.New("http-knock: password/basic auth requires at least one user")
	}

	set := &userSet{byName: make(map[string]*userCredential)}
	for _, entry := range entries {
		user, err := newUserCredential(entry)
		if err != nil {
			return nil, err
		}
		if user.username != "" {
			if _, exists := set.byName[user.username]; exists {
				return nil, fmt.Errorf("http-knock: duplicate username %q", user.username)
			}
			set.byName[user.username] = user
			set.hasUsernames = true
		} else {
			set.shared = append(set.shared, user)
		}
		set.all = append(set.all, user)
	}
	return set, nil
}

func parseCredentialLines(value string) ([]User, error) {
	var users []User
	for _, rawLine := range strings.Split(value, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(rawLine, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// A line that starts with "plain:" is a shared plaintext password.
		// Check it before splitting on ":", otherwise "plain" would be
		// interpreted as a username.
		if strings.HasPrefix(line, "plain:") {
			users = append(users, User{Password: line[len("plain:"):]})
			continue
		}

		username := ""
		secret := line
		if i := strings.IndexByte(line, ':'); i >= 0 {
			username = strings.TrimSpace(line[:i])
			secret = strings.TrimSpace(line[i+1:])
		}
		if secret == "" {
			return nil, errors.New("http-knock: credentials file contains an empty password/hash")
		}

		if strings.HasPrefix(secret, "plain:") {
			users = append(users, User{Username: username, Password: secret[len("plain:"):]})
			continue
		}
		users = append(users, User{Username: username, PasswordHash: secret})
	}
	return users, nil
}

func newUserCredential(entry User) (*userCredential, error) {
	username := strings.TrimSpace(entry.Username)
	if !validUsername(username) {
		return nil, fmt.Errorf("http-knock: username %q contains unsupported characters", username)
	}
	if entry.Password != "" && entry.PasswordHash != "" {
		return nil, fmt.Errorf("http-knock: user %q must set only one of password and passwordHash", username)
	}
	if entry.Password == "" && entry.PasswordHash == "" {
		return nil, fmt.Errorf("http-knock: user %q has no password or passwordHash", username)
	}

	user := &userCredential{username: username}
	if entry.Password != "" {
		user.plain = entry.Password
		user.fingerprint = sha256Hex("plain:" + entry.Password)
		return user, nil
	}

	hashValue := strings.TrimSpace(entry.PasswordHash)
	parsed, err := parsePasswordHash(hashValue)
	if err != nil {
		return nil, err
	}
	user.hash = parsed
	user.fingerprint = sha256Hex("hash:" + hashValue)
	return user, nil
}

// authenticate verifies a username/password pair. An empty username tries the
// shared (username-less) credentials. An unknown named user may still match a
// shared password so Basic clients can use a single shared secret.
func (s *userSet) authenticate(username, password string) (*userCredential, bool) {
	if s == nil || password == "" {
		return nil, false
	}

	if username != "" {
		if user, ok := s.byName[username]; ok {
			if user.verifyPassword(password) {
				return user, true
			}
			return nil, false
		}
	}

	var matched *userCredential
	for _, user := range s.shared {
		if user.verifyPassword(password) && matched == nil {
			matched = user
		}
	}
	if matched != nil {
		return matched, true
	}

	// With no shared credential there was no PBKDF2 work above. Run one dummy
	// derivation with the configured iteration count so an unknown/empty
	// username is not distinguishable from a known user with a wrong password
	// by response time. (With shared credentials the loop already did KDF work.)
	if len(s.shared) == 0 {
		s.dummyVerify(password)
	}
	return nil, false
}

// dummyVerify performs the same key-derivation work as a real hash check but
// discards the result. It is used only to flatten the timing difference for
// unknown usernames.
func (s *userSet) dummyVerify(password string) {
	iterations := 0
	for _, user := range s.all {
		if user.hash != nil {
			iterations = user.hash.iterations
			break
		}
	}
	if iterations == 0 {
		// Plaintext-only development configuration: a wrong password check is
		// constant-time and cheap, so there is no expensive work to mimic.
		return
	}
	_ = pbkdf2SHA256([]byte(password), []byte("http-knock-dummy-salt"), iterations, pbkdf2KeyLength)
}

// findByFingerprint resolves the user stored in a session value. The
// fingerprint changes when the password hash changes, so changing a password
// invalidates existing sessions without a separate revocation list.
func (s *userSet) findByFingerprint(username, fingerprint string) (*userCredential, bool) {
	if s == nil {
		return nil, false
	}
	if username != "" {
		user, ok := s.byName[username]
		if !ok {
			return nil, false
		}
		if constantTimeEqualString(user.fingerprint, fingerprint) {
			return user, true
		}
		return nil, false
	}

	for _, user := range s.shared {
		if constantTimeEqualString(user.fingerprint, fingerprint) {
			return user, true
		}
	}
	return nil, false
}

func sessionValue(user *userCredential) string {
	if user == nil {
		return "|"
	}
	return user.username + "|" + user.fingerprint
}

func parseSessionValue(value string) (string, string, bool) {
	if i := strings.IndexByte(value, '|'); i >= 0 {
		return value[:i], value[i+1:], true
	}
	return "", "", false
}

// loadSecret resolves a secret from a file, environment variable or inline
// value, in that order of precedence. A configured higher-priority source is
// authoritative: an unset environment variable does not mask a valid file.
func loadSecret(inline, file, envName, field string) ([]byte, error) {
	value := strings.TrimSpace(inline)
	if file != "" {
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("http-knock: cannot read %s: %w", field, err)
		}
		value = strings.TrimSpace(string(data))
	} else if envName != "" {
		envValue, ok := os.LookupEnv(envName)
		if !ok || strings.TrimSpace(envValue) == "" {
			return nil, fmt.Errorf("http-knock: %s environment variable %q is empty or not set", field, envName)
		}
		value = strings.TrimSpace(envValue)
	}
	if value == "" {
		return nil, fmt.Errorf("http-knock: %s must not be empty", field)
	}
	return []byte(value), nil
}

// cookieNameFor derives a cookie name from the realm so multiple middlewares
// on the same host do not overwrite each other's cookie. The suffix is a
// 64-bit digest, which makes an accidental collision between unrelated
// middlewares on one host very unlikely.
func cookieNameFor(realm string, secure bool) string {
	suffix := sha256Hex(realm)[:16]
	if secure {
		return "__Host-http-knock-" + suffix
	}
	return "http-knock-" + suffix
}

func parseSameSite(value string) (http.SameSite, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return http.SameSiteLaxMode, nil
	case "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	default:
		return http.SameSiteDefaultMode, fmt.Errorf("http-knock: cookieSameSite %q must be Lax, Strict or None", value)
	}
}

func validCookieName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '!':
		case c == '#':
		case c == '$':
		case c == '%':
		case c == '&':
		case c == '\'':
		case c == '*':
		case c == '+':
		case c == '-':
		case c == '.':
		case c == '^':
		case c == '_':
		case c == '`':
		case c == '|':
		case c == '~':
		default:
			return false
		}
	}
	return true
}

func (m *middleware) setSessionCookie(rw http.ResponseWriter, token string) {
	http.SetCookie(rw, &http.Cookie{
		Name:     m.cfg.cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   durationSeconds(m.cfg.sessionTTL),
		Expires:  time.Now().Add(m.cfg.sessionTTL),
		HttpOnly: true,
		Secure:   m.cfg.cookieSecure,
		SameSite: m.cfg.cookieSameSite,
	})
}

func (m *middleware) clearSessionCookie(rw http.ResponseWriter) {
	http.SetCookie(rw, &http.Cookie{
		Name:     m.cfg.cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(1, 0),
		HttpOnly: true,
		Secure:   m.cfg.cookieSecure,
		SameSite: m.cfg.cookieSameSite,
	})
}

func (m *middleware) sessionCookie(req *http.Request) (string, bool) {
	cookie, err := req.Cookie(m.cfg.cookieName)
	if err != nil || cookie.Value == "" {
		return "", false
	}
	return cookie.Value, true
}

func bearerToken(req *http.Request) (string, bool) {
	value := req.Header.Get("Authorization")
	if len(value) < len("Bearer ") {
		return "", false
	}
	if !strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
		return "", false
	}
	token := strings.TrimSpace(value[len("Bearer "):])
	if token == "" {
		return "", false
	}
	return token, true
}

func hasAuthorization(req *http.Request) bool {
	return strings.TrimSpace(req.Header.Get("Authorization")) != ""
}

// sameOriginPost rejects cross-origin login and logout POSTs. A cross-site HTML
// form can make a victim's browser submit attacker credentials (login CSRF) or
// log the victim out; SameSite cookies do not prevent either, because the
// response can still set/clear cookies and the handler runs server-side.
//
// Modern browsers send Sec-Fetch-Site, Origin or Referer on form POSTs. Requests
// from non-browser clients usually send none of them and are allowed; the
// protected state changes still require valid credentials or a valid token.
func sameOriginPost(req *http.Request) bool {
	if site := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Site"))); site != "" {
		if site != "same-origin" && site != "none" {
			return false
		}
	}
	if origin := strings.TrimSpace(req.Header.Get("Origin")); origin != "" {
		return sameOriginURL(req, origin)
	}
	if referer := strings.TrimSpace(req.Header.Get("Referer")); referer != "" {
		return sameOriginURL(req, referer)
	}
	return true
}

// sameOriginURL compares the scheme/host of an Origin or Referer value with the
// request authority, including the default port for the scheme.
func sameOriginURL(req *http.Request, raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	scheme := requestScheme(req)
	if !strings.EqualFold(u.Scheme, scheme) {
		return false
	}

	originHost := strings.ToLower(u.Host)
	requestHost := strings.ToLower(req.Host)
	if originHost == requestHost {
		return true
	}

	originName, originPort := splitAuthority(originHost)
	requestName, requestPort := splitAuthority(requestHost)
	if originName != requestName {
		return false
	}
	if originPort == "" {
		originPort = defaultPort(u.Scheme)
	}
	if requestPort == "" {
		requestPort = defaultPort(scheme)
	}
	return originPort == requestPort
}

// requestScheme returns the scheme the client used. Traefik normally sets TLS
// itself for HTTPS entrypoints; X-Forwarded-Proto covers a TLS-terminating
// proxy in front of Traefik.
func requestScheme(req *http.Request) string {
	if req.TLS != nil {
		return "https"
	}
	if proto := req.Header.Get("X-Forwarded-Proto"); proto != "" {
		if i := strings.IndexByte(proto, ','); i >= 0 {
			proto = proto[:i]
		}
		switch strings.ToLower(strings.TrimSpace(proto)) {
		case "http":
			return "http"
		case "https":
			return "https"
		}
	}
	return "http"
}

func splitAuthority(host string) (string, string) {
	if name, port, err := net.SplitHostPort(host); err == nil {
		return strings.ToLower(name), port
	}
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")), ""
	}
	return host, ""
}

func defaultPort(scheme string) string {
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	return "80"
}

func wantsJSON(req *http.Request) bool {
	if strings.Contains(strings.ToLower(req.Header.Get("Accept")), "application/json") {
		return true
	}
	if strings.EqualFold(req.URL.Query().Get("format"), "token") {
		return true
	}
	return false
}

func durationSeconds(d time.Duration) int {
	seconds := int(d / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

// renderLoginPage writes the self-contained login form. The page intentionally
// uses no JavaScript or external resources; CSP and frame protection are set on
// every response.
func (m *middleware) renderLoginPage(rw http.ResponseWriter, status int, message string) {
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Cache-Control", "no-store")
	rw.Header().Set("Pragma", "no-cache")
	rw.Header().Set("X-Frame-Options", "DENY")
	// Browsers apply the login page's referrer policy to the form submission
	// that follows. Chrome sends "Origin: null" on a form POST when the page is
	// served with "no-referrer", which sameOriginPost correctly rejects as a
	// cross-origin attempt. "same-origin" keeps credentials out of cross-origin
	// Referer headers while preserving a verifiable Origin on the same-origin
	// login POST.
	rw.Header().Set("Referrer-Policy", "same-origin")
	rw.Header().Set("X-Content-Type-Options", "nosniff")
	rw.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	rw.WriteHeader(status)

	action := html.EscapeString(m.cfg.loginPath)
	errorBlock := ""
	if message != "" {
		errorBlock = `<p class="error">` + html.EscapeString(message) + `</p>`
	}
	usernameField := ""
	if m.cfg.users != nil && m.cfg.users.hasUsernames {
		usernameField = `<label for="username">Username</label>
<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required>`
	}

	page := `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in</title>
<style>
:root { color-scheme: light dark; }
body { margin: 0; min-height: 100vh; display: grid; place-items: center; font: 16px/1.5 system-ui, sans-serif; background: #f5f5f4; color: #1c1917; }
main { width: min(92vw, 22rem); padding: 1.5rem; background: #fff; border-radius: .75rem; box-shadow: 0 10px 30px #0002; }
h1 { margin: 0 0 1rem; font-size: 1.25rem; }
label { display: block; margin: .75rem 0 .25rem; font-weight: 600; }
input { box-sizing: border-box; width: 100%%; padding: .6rem .7rem; border: 1px solid #d6d3d1; border-radius: .4rem; font: inherit; }
button { margin-top: 1rem; width: 100%%; padding: .65rem .7rem; border: 0; border-radius: .4rem; background: #1c1917; color: #fff; font: inherit; font-weight: 600; cursor: pointer; }
.error { margin: 0 0 .75rem; padding: .5rem .65rem; border-radius: .35rem; background: #fee2e2; color: #991b1b; }
@media (prefers-color-scheme: dark) {
  body { background: #0c0a09; color: #f5f5f4; }
  main { background: #1c1917; box-shadow: none; }
  input { background: #0c0a09; color: #f5f5f4; border-color: #44403c; }
  button { background: #f5f5f4; color: #1c1917; }
  .error { background: #450a0a; color: #fecaca; }
}
</style>
</head>
<body>
<main>
<h1>Sign in</h1>
%s
<form method="post" action="%s">
%s
<label for="password">Password</label>
<input id="password" name="password" type="password" autocomplete="current-password" required autofocus>
<button type="submit">Continue</button>
</form>
</main>
</body>
</html>
`
	_, _ = fmt.Fprintf(rw, page, errorBlock, action, usernameField)
}
