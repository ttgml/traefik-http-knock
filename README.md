# traefik-http-knock

`traefik-http-knock` is a Traefik v3 middleware plugin that keeps a website
closed to everyone except clients that authenticate first.

It supports three authentication modes:

* **path** (the original mode): `GET /__knock__/<secret>` is the credential.
* **password**: a login form verifies one or more usernames/passwords and issues
  a Redis-backed session cookie; CLI/API clients can use HTTP Basic
  (`authMode: basic`) or, with `grantMode: session`/`both`, exchange credentials
  for a Bearer session token.
* **basic**: HTTP Basic authentication on every request, without Redis state.
  Every request performs a PBKDF2 verification, so this mode is CPU-bound and has
  no login rate limit; use a Traefik `rateLimit` in front of it.

A successful password login can grant access in three ways:

* `grantMode: session` (default for password mode): a session cookie/token,
  revocable with logout and stored in Redis.
* `grantMode: ip`: the original per-IP Redis allowlist.
* `grantMode: both`: either grant allows the request.

Every grant is scoped to a **realm**. The default realm is the middleware name
plus a short digest of the auth endpoints, so two same-named configurations with
different endpoints do not share grants. Deployments that intentionally share a
Redis database and `keyPrefix` (for example staging and production, or several
clusters) must still set a unique `realm` explicitly. Password sessions are
always validated against Redis: when Redis is unavailable, a password
cookie/token is unusable, even with `failClosed: false`.

- Traefik v3 middleware plugin (`CreateConfig`, `New`, `ServeHTTP`)
- Go standard library only, no third-party dependencies (Yaegi friendly)
- Minimal RESP client: `AUTH`, `SELECT`, `PING`, `EXISTS`, `GET`,
  `SET ... EX`, `SET ... EX NX`, `INCR`, `EXPIRE`, `DEL`
- Bounded Redis connection pool with dial/read/write timeouts
- Fail closed by default: a Redis outage returns `503`, never `allow`
- Multiple password users, PBKDF2-HMAC-SHA256 hashes, credentials file/env
- Redis-backed sessions with logout and password-change revocation
- HTTP Basic and Bearer session tokens for CLI/API clients
- Per-IP login attempt limiting and bounded concurrent password verification
  (login form and Basic auth)
- Realm-scoped Redis keys and cookies; password-mode IP grants are tied to the
  credential fingerprint
- CDN-safe protected responses (`Cache-Control: private`, `Vary`)

Path mode was verified end to end against Traefik v3.2.5 (local plugin, Yaegi)
and Redis 7.4: `403` before the knock, `204` + `Cache-Control: no-store` for a
successful knock (`303 See Other` when `redirectURL` is set), `200` afterwards,
`403` for non-GET requests (identical to any other path), and `503` while Redis
was unreachable.

Password mode was also verified end to end against Traefik v3.2.5 + Redis 7.4:
`403` before login, `204` + session cookie on login by default (`303` when
`redirectURL` is set), `200` on the protected route, `303` on logout, and `403`
afterwards; the JSON login returned a Bearer token that produced `200`, and
protected responses carried `Cache-Control: private` /
`Vary: Cookie, Authorization`. PBKDF2/HMAC/session behavior was additionally
exercised directly under Yaegi v0.16.1.

Path mode (the default):

```text
                   Internet
                       |
                       v
                  +---------+
                  | Traefik |
                  +----+----+
                       |
                HTTP Knock Plugin
                       |
          +------------+-------------+
          |                          |
   GET /__knock__/secret        protected request
          |                          |
          v                          v
      verify knock              Redis GET grant
          |                          |
          v                    +-----+-----+
      Redis SETEX              |           |
          |                   YES          NO
          v                    |           |
     204/303                    v           v
                         Backend       HTTP 403
```

---

## 0. Module path

The module path is **`github.com/ttgml/traefik-http-knock`** and is already
consistent everywhere: `go.mod`, `.traefik.yml`, `Dockerfile`, `Makefile`,
`.github/workflows/ci.yml`, `docker-compose.yml`,
`deploy/helmchartconfig.yaml`, `deploy/traefik-static-config.yml`,
`deploy/traefik-compose.yml` and `cmd/knockhash/main.go`.

Traefik requires the module path to match the repository path, the local plugin
directory (`/plugins-local/src/<module>`) and the catalog `import`, so if you
fork or rename the repository, change **all** of those places together:

```bash
grep -rl 'github.com/ttgml/traefik-http-knock' . \
  --exclude-dir=.git | xargs sed -i 's|github.com/ttgml/traefik-http-knock|github.com/<you>/traefik-http-knock|g'
```

(Image tags use `ghcr.io/ttgml/traefik-http-knock` in the `Makefile`,
`Dockerfile` comment and `deploy/helmchartconfig.yaml`; adjust those too if you
push somewhere else.)

---

## 1. Features

| Feature | Status |
| --- | --- |
| Secret path knock (`GET /__knock__/<secret>`) | implemented |
| Password login form + session cookie | implemented |
| Multiple users/passwords, PBKDF2 hashes | implemented |
| Credentials file/environment, cookie-secret file/environment | implemented |
| HTTP Basic auth (`authMode: basic`) | implemented |
| Bearer session token for CLI/API (`Accept: application/json`, `grantMode: session`/`both`) | implemented |
| Logout (`POST` + `action=logout`) and password-change revocation | implemented |
| Login attempt limiting per IP and bounded concurrent KDFs (form and Basic) | implemented |
| Login/logout CSRF protection (same-origin header check) | implemented |
| Password-mode IP grants tied to the credential fingerprint | implemented |
| Redis session store with TTL and hashed session keys | implemented |
| Realm-scoped Redis keys and signed tokens | implemented |
| CDN-safe `Cache-Control: private` / `Vary` on protected responses | implemented |
| Redis TTL allowlist (state store only, no Go timers) | implemented |
| Non-GET requests to the path endpoint are not a path oracle | implemented |
| `204`/`303` + `Cache-Control: no-store` on successful authentication | implemented |
| Optional post-authentication redirect (`redirectURL`) | implemented |
| Client IP from `RemoteAddr` or a configured header | implemented |
| Static allowlist of IPs and CIDR ranges (always allowed) | implemented |
| IPv4 and IPv6, canonicalized (`2001:0DB8::1` == `2001:db8::1`) | implemented |
| Fail closed on Redis errors (`503`) | implemented |
| Bounded connection pool, timeouts, connection reuse | implemented |
| Constant-time secret/password/hash comparison | implemented |
| Client IP logging toggle (`logClientIP`, off by default) | implemented |
| Optional authenticated-user header to the backend | implemented |

The implementation stays standard-library only so it remains loadable by
Traefik's Yaegi interpreter. Password and session support add no external
dependencies.

## 2. How it works

### 2.1 Authentication modes

`authMode` selects how a request proves that it is allowed to continue. Only one
mode is active per middleware instance; path and password knocks are not
combined in the same instance.

**`path` (default, backward compatible)**

1. `GET <knockPath>` is the credential.
2. The client IP is stored in Redis with a TTL.
3. Protected requests are allowed while the IP key exists.
4. Non-GET requests to the secret path are handled like any other protected
   request, so they do not reveal that the path matched.

**`password`**

1. `GET <loginPath>` renders a small login form. `loginPath` defaults to
   `knockPath`.
2. `POST <loginPath>` verifies `username` and `password` against one or more
   configured users.
3. On success, the configured `grantMode` decides what is issued:
   * `session` (default): a Redis-backed session cookie is set. The same
     session token can be used as `Authorization: Bearer <token>` for API
     clients.
   * `ip`: the client IP is stored in Redis, as in path mode. No session or
     Bearer token is issued or accepted in this mode.
   * `both`: both grants are issued; either one allows the request.
4. `POST <loginPath>` with `action=logout` deletes the Redis session and the IP
   grant (when applicable), and clears the cookie after the revocation succeeds.
5. JSON clients can send `Accept: application/json` (or `?format=token`) to
   receive a token when `grantMode` is `session` or `both`:

```json
{"ok":true,"username":"alice","token":"v1....","expiresIn":43200}
```

   With `grantMode: ip` the response contains `ok`/`username` but no token.
6. Changing a user's password changes the credential fingerprint stored in the
   session value and in password-mode IP grants. Existing sessions and IP grants
   for that user are then rejected and deleted on their next use.

Login and logout POSTs from a browser must be same-origin. The middleware checks
`Sec-Fetch-Site`, `Origin` and `Referer` (in that order) and rejects cross-origin
submissions with `403`; non-browser clients that send none of these headers are
allowed. This is the CSRF defense for both login and logout. If a TLS-terminating
proxy sits in front of Traefik, make sure it sets `X-Forwarded-Proto` so the
same-origin comparison sees the `https` scheme.

**`basic`**

HTTP Basic credentials are verified on every request. This mode is stateless
and does not use Redis for access decisions. It is intended for CLI/API clients;
browsers will show a native credential dialog and have no logout button. Every
request runs a PBKDF2 verification (the default hash costs tens of milliseconds),
so Basic is CPU-bound; `maxConcurrentLogins` bounds concurrent verifications, but
there is no per-IP rate limit. Compose a Traefik `rateLimit` middleware and use
Basic only where that cost is acceptable.

### 2.2 Protected request flow

1. Resolve the client IP from `RemoteAddr` or `clientIPHeader`.
2. If the IP is on `staticAllowlist`, forward the request immediately. Static
   entries do not need Redis, so they keep working during a Redis outage.
3. Otherwise, depending on the mode:
   * **path**: check that `<prefix><realm>:ip:<clientIP>` contains the legacy
     `1` marker.
   * **password**: with `grantMode: session`/`both`, check a Bearer token, then
     the session cookie; then, for `grantMode: ip`/`both`, check the IP key.
     With `grantMode: ip`, session cookies/tokens are ignored.
   * **basic**: verify the `Authorization: Basic` header.
4. On success call `next.ServeHTTP()`. Otherwise return `401` (Basic/Bearer
   challenge), `403` (no grant), or `429` (login/attempt or KDF-concurrency
   limit).

Session lookups always fail closed: if Redis is unavailable, a password session
cookie/token is unusable even when `failClosed: false`. This prevents a Redis
outage from silently turning a password session into a fail-open bypass.

By default, protected responses in password/basic mode are marked
`Cache-Control: private` and `Vary: Cookie, Authorization`, so a CDN cannot
cache an authenticated response and serve it to another client. A backend's
stronger `Cache-Control: no-store` is preserved. Set `privateResponses: false`
only if you have another cache-isolation mechanism.

The plugin never forwards a login request or a path-mode `GET` knock to the
backend. A non-GET request to the path-mode knock URL is deliberately treated as
an ordinary protected request (so it is indistinguishable from any other path)
and may reach the backend once the client is authorized. Password fields, session
cookies and bearer tokens are not written to logs.

## 3. Redis data model

All keys are realm-scoped. `realm` defaults to the middleware name plus a short
digest of the auth endpoints; set it explicitly when several deployments share
the same Redis database.

| Key | Value | TTL |
| --- | --- | --- |
| `<keyPrefix><realm>:ip:<clientIP>` | path mode: `1`; password mode: `<username>|<credential-fingerprint>` | `ttl` |
| `<keyPrefix><realm>:session:<sha256(sessionID)>` | `<username>|<credential-fingerprint>` | `sessionTTL` |
| `<keyPrefix><realm>:login:<clientIP>` | login-attempt counter | `loginWindow` |

Examples:

```text
traefik:http-knock:app-a:ip:192.168.1.10       -> 1 (path mode)
traefik:http-knock:app-a:ip:2001:db8::1        -> alice|8f2a... (password mode)
traefik:http-knock:app-a:session:59c4...       -> alice|8f2a...
traefik:http-knock:app-a:login:203.0.113.5     -> 2
```

* The IP is normalized (`net.ParseIP(...).String()`) before the key is built, so
  different spellings of the same IPv6 address cannot create two entries.
* The raw session id is never stored in Redis; only its SHA-256 is used as key
  material. A Redis dump cannot be replayed as a valid cookie/token. Path-mode
  IP grants must contain exactly the legacy `1` marker, so a value written by
  password mode (or another application) cannot authorize path mode.
* Session and password-mode IP values contain the username and a fingerprint of
  the current credential. Changing the password or removing the user invalidates
  both on their next use. A path-mode IP value is the legacy `1`.
* Login counters are created with `SET ... EX NX`, incremented with `INCR`, and
  always receive an `EXPIRE`; a successful login deletes the counter. `INCR`
  itself is never retried automatically because it is not idempotent.

Inspect state manually:

```bash
kubectl -n traefik-http-knock exec deploy/redis -- \
  redis-cli -a "$REDIS_PASSWORD" --scan --pattern 'traefik:http-knock:*'
kubectl -n traefik-http-knock exec deploy/redis -- \
  redis-cli -a "$REDIS_PASSWORD" TTL traefik:http-knock:app-a:ip:203.0.113.5
```

## 4. Security model

The plugin is an authentication and temporary-grant layer, not a full identity
provider. The shared password is the credential; anyone who knows it can log
in. Use per-user passwords and rotate them when someone leaves.

| Risk | Mitigation |
| --- | --- |
| Guessable path secret | Use a 128-bit random secret (`openssl rand -hex 32`); length is enforced at config time (6–80 chars) |
| Timing side channel on secrets/passwords | Constant-time path, password and hash comparisons; unknown usernames run a dummy PBKDF2 derivation |
| Weak password brute force | PBKDF2-HMAC-SHA256 hashes, per-IP login attempt limiting, bounded concurrent KDFs. Basic auth has no rate limit; compose a Traefik `rateLimit` |
| Login/logout CSRF | Login and logout POSTs require a same-origin `Sec-Fetch-Site`/`Origin`/`Referer`; cross-origin submissions get `403` |
| Password leak in config/dashboard | Prefer `passwordHash` or a `credentialsFile` mounted from a Secret; `password` plaintext is for development only |
| Password in URLs/logs | Login uses POST bodies, never query strings; authentication endpoints are never forwarded to the backend |
| Session theft | 256-bit random ids, HMAC-signed cookie/token, `HttpOnly`, `Secure`, `SameSite=Lax`, `__Host-` cookie by default |
| Session fixation | A new session id is generated on every login |
| Logout/revocation | Redis `DEL` on logout; password change or user removal invalidates sessions and password-mode IP grants via the credential fingerprint |
| Redis outage turning into an allow | Session lookups always return `503`; IP allowlist follows `failClosed` |
| Cookie/token replay across apps | HMAC and Redis keys include the realm; cookies include a realm-derived name. Set a unique realm when deployments share Redis |
| CDN caching authenticated content | `Cache-Control: private` + `Vary: Cookie, Authorization` on protected responses by default |
| Open redirect via `redirectURL`/`loginPath` | Only same-origin paths and absolute `http`/`https` URLs; `//host`, backslashes, percent-encoding, control characters and (for login/knock paths) whitespace are rejected |
| Header spoofing (`X-Forwarded-For` etc.) | Off by default. `clientIPHeader` must only be set behind a trusted proxy that overwrites it |
| Static allowlist matching a spoofed IP | Static entries use the same resolved IP; keep `clientIPHeader` empty unless the proxy is trusted |
| Secret leaking into startup logs | `knockPath`/`loginPath` validation errors do not echo the configured value |
| Log flooding from denials | Login attempts are limited; Basic verification is concurrency-bounded, but Basic failures are logged per request. Use `logClientIP` only if you accept logging client IPs |
| Redis compromise | Password, NetworkPolicy, and ideally TLS for cross-network Redis |

Residual risks:

* A shared password identifies a group, not an individual. Use one username per
  person if you need attribution or per-person revocation.
* Password sessions are valid for the whole `sessionTTL`. Use a short TTL for
  sensitive services and rotate `cookieSecret` to invalidate every session.
* Basic auth sends the password on every request and has no logout; every request
  costs a PBKDF2 verification, and there is no per-IP rate limit. Use it only
  over TLS, preferably for API/CLI clients, and compose a Traefik `rateLimit`.
* A stolen session token remains usable until logout, password change, or TTL
  expiry.
* Behind carrier-grade NAT, `grantMode: ip` shares access with other users of
  the same public IP. `grantMode: session` avoids that. The password-mode IP
  value holds the last login's credential fingerprint, so if that user's
  password changes the whole shared IP loses access until someone logs in again.
* The CSRF check relies on browser headers. A client that sends no
  `Sec-Fetch-Site`, `Origin` or `Referer` is treated as non-browser and allowed;
  use a signed CSRF token in front of the login endpoint if that residual risk is
  not acceptable.

## 5. Configuration reference

### 5.1 Path mode (original behaviour)

```yaml
httpKnock:
  # Required. Exact path that triggers the knock. Must start with "/",
  # must not be protocol-relative or contain "?", "#", backslashes,
  # percent-encoding, whitespace or control characters; 6 to 80 chars.
  knockPath: "/__knock__/9c4e2e4e3b6d0c0f7b1a2c3d4e5f60718293a4b5c6d7e8f9"
  # Allowlist entry lifetime (Go duration). Redis expires the key.
  ttl: "2h"

  # Optional. Where a browser is sent after a successful knock. Set it to "/"
  # to land on the homepage (same origin), or to an absolute http(s) URL.
  redirectURL: ""

  # Required for path/password modes. "host:port" of Redis.
  redisAddr: "redis.traefik-http-knock.svc.cluster.local:6379"
  redisUsername: ""
  redisPassword: ""
  redisDB: 0                    # Redis enables 0-15 by default

  keyPrefix: "traefik:http-knock:"
  clientIPHeader: ""
  staticAllowlist: []
  #  - "203.0.113.7"
  #  - "192.168.0.0/16"

  failClosed: true
  dialTimeout: "2s"
  readTimeout: "1s"
  writeTimeout: "1s"
  redisPoolSize: 16
  logClientIP: false
```

### 5.2 Password mode

```yaml
httpKnock:
  # The login form and token endpoint. Defaults to knockPath.
  knockPath: "/__knock__"
  loginPath: "/__knock__"
  authMode: password
  # Send the browser to the homepage after login. Logout redirects back to
  # loginPath.
  redirectURL: "/"

  # Use one of:
  #
  # 1) Inline hashes. Generate a bare hash with `make hash-password` or
  #    `go run ./cmd/knockhash`; use `-username alice` only when generating a
  #    "username:hash" line for a credentials file.
  users:
    - username: alice
      passwordHash: "pbkdf2-sha256$120000$BASE64_SALT$BASE64_HASH"
    - username: bob
      passwordHash: "pbkdf2-sha256$120000$BASE64_SALT$BASE64_HASH"
  #
  # 2) A Secret-mounted credentials file. Lines are "username:hash" or
  #    "username:plain:password" (development only). A line without a colon is
  #    a shared password. Blank lines and "#" comments are ignored.
  # credentialsFile: "/etc/traefik/secrets/http-knock-credentials"
  #
  # 3) An environment variable with the same line format.
  # credentialsEnv: "HTTP_KNOCK_CREDENTIALS"

  # ip | session | both. Defaults to session for password mode.
  # With ip, no session/Bearer token is issued or accepted (JSON login returns
  # no token); with both, either grant allows the request.
  grantMode: session
  sessionTTL: "12h"

  # At least 32 bytes, shared by all Traefik replicas. Prefer a file mount.
  cookieSecret: ""
  cookieSecretFile: "/etc/traefik/secrets/http-knock-cookie-secret"
  # cookieSecretEnv: "HTTP_KNOCK_COOKIE_SECRET"
  cookieName: ""            # empty = realm-derived __Host- name
  cookieSecure: true
  cookieSameSite: "Lax"     # Lax | Strict | None

  # Realm defaults to the middleware name plus a short digest of the auth
  # endpoints. Set it explicitly to keep keys stable across config changes and
  # whenever several deployments share this Redis database/keyPrefix.
  realm: ""

  # Login protection. Every attempt counts; success clears the counter.
  # 0 disables the individual limit. maxConcurrentLogins also bounds Basic auth.
  maxLoginAttempts: 5
  loginWindow: "15m"
  maxConcurrentLogins: 4

  # CDN safety. Defaults to true for password/basic mode.
  privateResponses: true

  # Optional: forward the authenticated username to the backend. Any
  # client-supplied value is removed first.
  forwardUserHeader: ""

  # Redis and other common fields are the same as in path mode.
  ttl: "2h"
  redisAddr: "redis.traefik-http-knock.svc.cluster.local:6379"
  redisPassword: ""
  keyPrefix: "traefik:http-knock:"
  failClosed: true
  logClientIP: false
```

### 5.3 Basic auth mode (CLI/API)

```yaml
httpKnock:
  knockPath: "/__knock__"         # still required by the config schema
  authMode: basic
  users:
    - username: api
      passwordHash: "pbkdf2-sha256$120000$BASE64_SALT$BASE64_HASH"
  staticAllowlist:
    - "10.0.0.0/8"
  privateResponses: true
  logClientIP: false
```

Basic mode is stateless and does not need Redis. Every request performs a
PBKDF2 verification, and `maxConcurrentLogins` bounds concurrent verifications,
but login rate limiting is not applied to Basic requests. Compose a Traefik
`rateLimit` middleware if the endpoint is exposed to untrusted networks, and keep
the request rate in mind: a default 120000-iteration hash costs tens of
milliseconds per request.

### 5.4 Notes

* Upgrading from v0.1.x: Redis keys are now realm-scoped, for example
  `traefik:http-knock:<realm>:ip:<clientIP>` instead of
  `traefik:http-knock:<clientIP>`. The default realm is derived from the
  middleware name plus a digest of the auth endpoints, so old grants are ignored
  after the upgrade; clients simply knock/log in again. Set `realm` explicitly
  if the Middleware name or endpoints may change, or if several deployments
  share the same Redis database.
* Password-mode IP grants store the credential fingerprint, so changing a
  password or removing a user also revokes IP access (not only sessions).
* Login and logout POSTs are rejected with `403` when the browser says the
  request is cross-origin (`Sec-Fetch-Site`/`Origin`/`Referer`). API clients
  that send none of these headers are allowed.
* `loginPath` is only routed in password mode; setting it in path/basic mode has
  no effect. It must be a plain absolute path (no `//host`, backslashes, `%`
  escapes, whitespace or control characters).
* `cookieSecretFile` takes precedence over `cookieSecretEnv` and `cookieSecret`;
  an empty or unset env var does not mask a valid file.
* Invalid values make Traefik reject the middleware at load time with a
  descriptive error; no request is served with a half-applied configuration.
* `failClosed` uses a `*bool` so that "unset" means `true`.
* Password sessions always fail closed when Redis is unavailable, regardless of
  `failClosed`. Password mode also needs Redis for the login attempt limiter and
  the session/IP grant, so `failClosed: false` does not make login work during a
  Redis outage.
* Redis is not contacted when the middleware is created, so a Redis outage
  cannot break Traefik startup.
* Multiple users with the same non-empty username are rejected.
* Usernames may contain letters, digits, `.`, `_`, `-` and `@` (max 64 bytes).
* On plain HTTP (local development only), set `cookieSecure: false`. The
  realm-derived default cookie name then drops the `__Host-` prefix, because
  browsers reject `__Host-` cookies that are not Secure. Never disable
  `cookieSecure` on an internet-facing HTTPS site.
* Traefik can print the full dynamic configuration at `DEBUG` log level,
  including inline `cookieSecret`, `passwordHash` and Redis credentials. Keep
  Traefik at `INFO` in production and prefer `credentialsFile`,
  `cookieSecretFile` and Secret-mounted Redis configuration.

## 6. Security considerations (detail)

### 6.1 Generate a strong secret

```bash
openssl rand -hex 32
# 9c4e2e4e3b6d0c0f7b1a2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061
```

```yaml
knockPath: "/__knock__/9c4e2e4e3b6d0c0f7b1a2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d3e4f5061"
```

Rotate the secret by changing this value (rolling the Middleware is enough).

For password mode, also generate a separate cookie-signing secret:

```bash
openssl rand -base64 32
```

Store it in `cookieSecretFile` or `cookieSecretEnv`. Rotating it invalidates all
existing sessions.

### 6.2 `X-Forwarded-For` and friends

> **WARNING**: only set `clientIPHeader` when a reverse proxy or load balancer
> in front of Traefik *always overwrites* that header. Otherwise any client can
> send `X-Forwarded-For: 1.2.3.4`, knock, and allowlist an address that is not
> theirs — including bypassing the whole mechanism.

Recommendations:

* Behind Cloudflare, use `CF-Connecting-IP` and lock origin access to Cloudflare
  IP ranges, or install the Cloudflare Tunnel/proxy so the header cannot be
  injected directly.
* Behind an L7 load balancer, use `X-Real-IP` and configure the load balancer to
  replace it.
* For `X-Forwarded-For`, the left-most entry is used (`client, proxy1, proxy2` →
  `client`). This is only meaningful if the first entry is written by the
  trusted edge.
* If you cannot guarantee that, leave `clientIPHeader` empty: `RemoteAddr`
  (the TCP peer) is the safe default.
* Always block direct access to the Traefik pod/service from outside the
  cluster (NetworkPolicy, security groups), otherwise header spoofing wins.

### 6.3 IPv4 and IPv6

Client IPs come from `net.SplitHostPort` + `net.ParseIP` and are stored in
canonical form:

```text
192.168.1.10     -> traefik:http-knock:<realm>:ip:192.168.1.10
[2001:db8::1]:443-> traefik:http-knock:<realm>:ip:2001:db8::1
2001:0DB8:0::1   -> traefik:http-knock:<realm>:ip:2001:db8::1
```

Zones (`fe80::1%eth0`) are stripped. IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`)
normalize to `10.0.0.1`, which is what Go's `net` package reports too, so a
client seen over IPv4 and IPv4-mapped IPv6 shares one IP grant.

### 6.4 Logging

Logged events (never the secret, never credentials):

```text
knock succeeded for client <redacted|IP>
login succeeded for client <redacted|IP>
login failed for client <redacted|IP>
logout succeeded for client <redacted|IP>
request denied for client <redacted|IP>: no valid session or grant
redis unavailable for session of client <redacted|IP>: <error>
```

`logClientIP: false` (default) replaces the IP with `redacted`. Passwords,
password hashes, session ids, cookie values and bearer tokens are never logged.

## 7. Project tree

```text
traefik-http-knock/
├── .dockerignore
├── .github/
│   └── workflows/ci.yml
├── .gitignore
├── .traefik.yml                  # plugin manifest (catalog + local plugins)
├── Dockerfile                    # Traefik image with the plugin baked in
├── LICENSE
├── Makefile
├── README.md
├── go.mod
├── knock.go                      # Config, CreateConfig, New, ServeHTTP
├── auth.go                       # users, login form, cookies, sessions
├── crypto.go                     # PBKDF2, HMAC, token signing, constant time
├── ratelimit.go                  # per-IP login attempt reservation
├── response.go                   # CDN-safe response writer
├── ip.go                         # client IP extraction, normalization, keys
├── redis.go                      # minimal RESP client + bounded pool
├── cmd/knockhash/main.go         # password-hash generator
├── knock_test.go                 # middleware behaviour tests
├── auth_test.go                  # password, session, Basic and realm tests
├── auth_hardening_test.go        # CSRF, IP-grant and config hardening tests
├── response_test.go              # private response writer tests
├── crypto_test.go                # hash/token tests
├── ip_test.go                    # IP parsing tests
├── redis_test.go                 # RESP client/pool tests + Redis integration test
├── testserver_test.go            # in-process fake Redis used by the tests
├── yaegi_compat_test.go          # guards the Yaegi/stdlib-only constraints
├── docker-compose.yml            # local Traefik+Redis demo (curl examples)
└── deploy/
    ├── namespace.yaml
    ├── plugin-configmap.yaml     # generated by `make k8s-plugin-configmap`
    ├── redis.yaml
    ├── middleware.yaml
    ├── middleware-password.yaml
    ├── ingressroute.yaml
    ├── helmchartconfig.yaml
    ├── traefik-static-config.yml # static config for the custom image / docker run
    ├── traefik-compose.yml       # static config for docker-compose.yml
    └── traefik-compose-dynamic.yml # routers/middleware/service for the demo
```

Deviations from the originally sketched tree, and why:

* `ip.go`, `ip_test.go`, `testserver_test.go` — IP handling and the fake Redis
  server are separate concerns; keeping them out of `knock.go` / `redis.go`
  keeps each file focused and reviewable.
* `yaegi_compat_test.go` — local plugins run inside the Yaegi interpreter, which
  is not a complete Go implementation. This test enforces the constraints that
  keep the plugin loadable (standard library only, no `errors.Is`/`errors.As`,
  entry points intact) so a regression fails in CI instead of in production.
* `deploy/traefik-static-config.yml`, `deploy/traefik-compose.yml`,
  `deploy/traefik-compose-dynamic.yml`, `docker-compose.yml` — the plugin needs
  a static config that enables `experimental.localPlugins`; the compose files
  give a runnable end-to-end demo for the `curl` examples in section 14.
* `deploy/plugin-configmap.yaml` is **generated** (`make k8s-plugin-configmap`)
  rather than committed, so the plugin source is not duplicated in the repo. A
  ConfigMap is capped at 1 MiB and is a convenience path; the custom image is
  the recommended production option.
* `.github/workflows/ci.yml` — `fmt`, `vet`, `test`, `test -race` on every push and pull request; publishing runs only for `v*` tags.

## 8. Traefik v3 configuration

### 8.1 Plugin Catalog (published releases)

```yaml
experimental:
  plugins:
    httpKnock:
      moduleName: github.com/ttgml/traefik-http-knock
      version: v0.2.0
```

Requirements for a catalog release:

* repository path equals the module path in `go.mod`,
* `.traefik.yml` at the repository root with `import:` equal to that module
  path,
* a semver tag such as `v0.2.0` that Traefik can resolve through the Go module proxy,
* no `replace` directives and no dependencies outside the standard library
  (this plugin has none).

Then release:

```bash
make release PLUGIN_VERSION=v0.2.0   # runs the checks and creates an annotated tag
git push origin v0.2.0
```

### 8.2 Local plugin (source mounted into the container)

Static configuration:

```yaml
experimental:
  localPlugins:
    httpKnock:
      moduleName: github.com/ttgml/traefik-http-knock
```

The plugin source must be at
`/plugins-local/src/github.com/ttgml/traefik-http-knock` (Traefik's fixed
local plugin directory) and that directory must contain `go.mod`.

### 8.3 Middleware resource

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: http-knock
  namespace: traefik-http-knock
spec:
  plugin:
    httpKnock:
      knockPath: "/__knock__/REPLACE_WITH_64_HEX_CHARS"
      ttl: "2h"
      # Optional: send the browser to the homepage after a successful knock.
      redirectURL: "/"
      redisAddr: "redis.traefik-http-knock.svc.cluster.local:6379"
      redisPassword: "REPLACE_WITH_REDIS_PASSWORD"
      keyPrefix: "traefik:http-knock:"
      failClosed: true
      dialTimeout: "2s"
      readTimeout: "1s"
      writeTimeout: "1s"
      redisPoolSize: 16
```

Attach it to a router:

```yaml
spec:
  routes:
    - match: Host(`example.com`)
      kind: Rule
      middlewares:
        - name: http-knock
```

Every request matching the router (including the login/knock endpoint on the
same host) passes through the middleware. The authentication endpoint must be
reachable on the same router, otherwise it never arrives.

Password mode uses the same Middleware shape. Generate a bare hash first:

```bash
go run ./cmd/knockhash
# pbkdf2-sha256$120000$...
```

For a credentials file, generate a full line instead:

```bash
go run ./cmd/knockhash -username alice
# alice:pbkdf2-sha256$120000$...
```

```yaml
spec:
  plugin:
    httpKnock:
      knockPath: "/__knock__"
      loginPath: "/__knock__"
      authMode: password
      grantMode: session
      users:
        - username: alice
          passwordHash: "pbkdf2-sha256$120000$BASE64_SALT$BASE64_HASH"
      cookieSecretFile: "/etc/traefik/secrets/http-knock-cookie-secret"
      sessionTTL: "12h"
      redisAddr: "redis.traefik-http-knock.svc.cluster.local:6379"
      redisPassword: "REPLACE_WITH_REDIS_PASSWORD"
      realm: "example-com"
      maxLoginAttempts: 5
      loginWindow: "15m"
      privateResponses: true
```

Mount the cookie secret and credentials as read-only Secret volumes in the
Traefik pod. The Middleware CRD cannot reference a Secret directly, so use
`credentialsFile`/`cookieSecretFile` rather than putting secrets in the CRD.

## 9. k3s deployment

`deploy/` contains a complete example for a k3s cluster whose Traefik runs in
`kube-system` (the k3s default).

```bash
# 1. Namespace + Redis + demo app + Middleware + IngressRoute
kubectl apply -f deploy/namespace.yaml
kubectl apply -f deploy/redis.yaml
kubectl apply -f deploy/ingressroute.yaml

# 2. Path mode: set a real knock secret and the Redis password
SECRET=$(openssl rand -hex 32)
REDIS_PASSWORD=$(kubectl -n traefik-http-knock get secret redis-auth -o jsonpath='{.data.password}' | base64 -d)
sed -e "s|REPLACE_WITH_64_HEX_CHARS|${SECRET}|" \
    -e "s|REPLACE_WITH_REDIS_PASSWORD|${REDIS_PASSWORD}|" \
    deploy/middleware.yaml | kubectl apply -f -

# Password mode instead:
#   go run ./cmd/knockhash          # bare hash for inline users
#   # or: go run ./cmd/knockhash -username alice   # for a credentials file
#   COOKIE_SECRET=$(openssl rand -base64 32)
#   render deploy/middleware-password.yaml with the hash, cookie secret and
#   Redis password, then kubectl apply -f -

# 3. Give Traefik the plugin (pick one of the two options below)
kubectl apply -f deploy/helmchartconfig.yaml

# 4. Check
kubectl -n kube-system logs deploy/traefik | grep -i plugin
curl -i http://<node-ip>/                        # 403
curl -i "http://<node-ip>/__knock__/$SECRET"     # 204, or 303 when redirectURL is set
curl -i http://<node-ip>/                        # 200
```

### 9.1 Option A (recommended): custom Traefik image

```bash
docker build -t ghcr.io/<user>/traefik-http-knock:v0.2.0 .
docker push ghcr.io/<user>/traefik-http-knock:v0.2.0
```

Point the k3s Traefik at it (see `deploy/helmchartconfig.yaml`, Option A block).
The plugin source is copied into `/plugins-local/src/github.com/ttgml/traefik-http-knock`
at build time, so no ConfigMap size limit and no source copies at runtime.

### 9.2 Option B: ConfigMap mount (no custom image)

```bash
make k8s-plugin-configmap MODULE=github.com/ttgml/traefik-http-knock
kubectl apply -f deploy/plugin-configmap.yaml
```

Then use the Option B block in `deploy/helmchartconfig.yaml`. Use this only if
you cannot build/push an image: ConfigMaps are capped at 1 MiB and every plugin
change requires a ConfigMap refresh plus a Traefik pod restart.

### 9.3 HelmChartConfig

`HelmChartConfig` only edits the values of the k3s-managed `traefik` chart, so it
must live in the chart's namespace (`kube-system`) while Redis and the
`Middleware` live in the application namespace (`traefik-http-knock`).

```yaml
apiVersion: helm.cattle.io/v1
kind: HelmChartConfig
metadata:
  name: traefik
  namespace: kube-system
spec:
  valuesContent: |-
    additionalArguments:
      - "--experimental.localPlugins.httpKnock.moduleName=github.com/ttgml/traefik-http-knock"
    deployment:
      additionalVolumes:
        - name: http-knock-plugin
          configMap:
            name: http-knock-plugin
      additionalVolumeMounts:
        - name: http-knock-plugin
          mountPath: /plugins-local/src/github.com/ttgml/traefik-http-knock
```

k3s auto-restarts Traefik when the `HelmChartConfig` changes.

### 9.4 Namespaces, volumes and credentials

* `traefik-http-knock` — Redis, demo app, `Middleware`, `IngressRoute`.
* `kube-system` — k3s Traefik and the plugin ConfigMap (if used).
* The Redis password lives in the `redis-auth` Secret. The Traefik `Middleware`
  CRD **cannot** reference a Secret, so the rendered manifest must come from
  your GitOps/secret pipeline (SOPS, sealed-secrets, `envsubst` at apply time as
  shown above). Never commit the real password or knock secret.
* For password mode, mount a Secret containing `credentials` and
  `cookie-secret` into the Traefik pod, then point `credentialsFile` and
  `cookieSecretFile` at those paths. `HelmChartConfig` additionalVolumes/
  additionalVolumeMounts can do this; the files are read when the middleware is
  created.

## 10. Redis configuration

The deployment uses an ephemeral Redis: grants and sessions are intentionally
expendable, and restarting Redis only means clients have to authenticate again.

```yaml
args:
  - "--requirepass"
  - "$(REDIS_PASSWORD)"   # from the redis-auth Secret, not from the image
  - "--save"
  - ""
  - "--appendonly"
  - "no"
  - "--maxmemory"
  - "128mb"
  - "--maxmemory-policy"
  - "noeviction"
```

Operational notes:

* `noeviction` so that a full Redis never silently drops grants/sessions
  earlier than their TTL. Size `maxmemory` for peak session load
  (`clients × ~150 bytes`).
* No persistence: grants and sessions are not worth a volume.
* A password plus a `NetworkPolicy` (only Traefik's namespace may connect) is the
  minimum in-cluster hardening.
* For larger installations use a managed/external Redis (HA, auth, TLS) and
  point `redisAddr` at it. The plugin currently speaks plain RESP over TCP; if
  you need TLS to Redis, terminate it in a sidecar/socat proxy or add
  `crypto/tls` support.
* IP/session keys are written with `SET ... EX`. Login counters are created with
  `SET ... EX NX`, incremented, and refreshed with `EXPIRE` on every attempt; a
  failed `EXPIRE` deletes the counter instead of leaving a TTL-less key. A
  successful login deletes it. Redis therefore expires all login state even if
  the plugin disappears mid-flight.

## 11. Cloudflare / load balancer scenarios

Behind Cloudflare (or any reverse proxy / ingress in front of Traefik):

1. Terminate TLS at the edge, then forward to Traefik.
2. Configure the edge to set the real client IP header (`CF-Connecting-IP` for
   Cloudflare, `X-Real-IP` for nginx/HAProxy) and set
   `clientIPHeader: "CF-Connecting-IP"`.
3. Prevent direct access to Traefik: Cloudflare IP allowlist / Tunnel, a
   `NetworkPolicy`, or a cloud firewall. Otherwise anyone can bypass the edge
   and spoof the header.
4. Keep `X-Forwarded-For` handling in mind: Traefik appends the peer to it, so
   the left-most entry is only trustworthy if the edge replaced the header.
5. If Cloudflare's proxy sends IPv6 when a client prefers IPv6, IP grants and
   access must use the same family or the key differs. Password sessions are
   not IP-bound, so `grantMode: session` avoids this issue.
6. If Cloudflare caches HTML/API responses, keep `privateResponses: true`
   (password/basic default) or add a cache rule that bypasses protected paths.
   Otherwise a response authorized by Alice's cookie could be served to Bob.
   The plugin sets `Cache-Control: private` and `Vary: Cookie, Authorization`,
   but a cache rule that ignores those headers still wins.

## 12. Failure modes and troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Every request `403` after a successful knock | Knock and access use different source IPs (proxy, NAT, IPv6/IPv4 mix) | Use `grantMode: session` for password auth, or log the resolved IP (`logClientIP: true`) and compare with `redis-cli --scan` |
| Password login returns `429` | `maxLoginAttempts` reached for this IP, or too many concurrent KDFs | Wait for `loginWindow`/the KDF slot, or clear `<prefix><realm>:login:<ip>` in Redis |
| Login succeeds but the next request is `403` | Cookie not sent (wrong host/Secure/Path), or the session was revoked | Check the cookie in devtools; confirm `cookieSecure` matches HTTPS; inspect the session key in Redis |
| Password cookie stops working with `503` | Redis is down; sessions always fail closed | Restore Redis; this is intentional even with `failClosed: false` |
| Every request `503` | Redis unreachable, wrong `redisAddr`, auth failure, or `SELECT` to a disabled DB | `kubectl -n traefik-http-knock logs deploy/redis`, check the Secret, test with `redis-cli -h ... -a ...` |
| `403` on the path knock URL with a non-GET method | Only `GET` is a path knock; other methods are protected requests | Use `curl -i` (a `GET`); `curl -I` sends `HEAD` and will not knock |
| Knock returns `204` but nothing is stored | Wrong Redis DB/prefix or you are looking at another Redis | Compare `keyPrefix` and `redisDB`, inspect with `redis-cli --scan --pattern '<prefix>*'` |
| Traefik logs `command not found` / plugin not loaded | `moduleName` does not match `go.mod`, or source is not in `/plugins-local/src/<moduleName>` | Check the mount path and the `additionalArguments` value (case-sensitive) |
| Plugin config rejected at startup | Invalid path/ttl/timeouts, missing users, missing cookie secret | The error message names the field; see section 5 |
| Grant or session disappears too early | TTL too short, or Redis evicted the key | Check `TTL <key>`; use `noeviction` and enough `maxmemory` |
| Can allowlist arbitrary IPs | `clientIPHeader` set without a trusted proxy overwriting it | Remove `clientIPHeader` and rely on `RemoteAddr` |

Useful checks:

```bash
kubectl -n kube-system logs deploy/traefik --tail=100 | grep http-knock
kubectl -n traefik-http-knock exec deploy/redis -- redis-cli INFO stats | grep keyspace
kubectl -n traefik-http-knock exec deploy/redis -- redis-cli --scan --pattern 'traefik:http-knock:*'
```

## 13. Local development and tests

```bash
go fmt ./...
go vet ./...
go test ./...
go test -race ./...
```

The unit tests use an in-process fake Redis server (`testserver_test.go`), so no
Docker is required. They cover path mode, password login, multiple users,
sessions, logout/revocation, Basic auth, Bearer tokens, realm isolation, login
rate limiting and KDF concurrency, CSRF/origin checks, password-change IP-grant
revocation, CDN headers, PBKDF2/HMAC, and the RESP client.

Generate a password hash for local tests or deployment:

```bash
make hash-password
# or: go run ./cmd/knockhash
# For a credentials file line:
go run ./cmd/knockhash -username alice
```

The Redis integration test is opt-in:

```bash
docker run --rm -d -p 6379:6379 --name knock-redis redis:7.4-alpine \
  redis-server --requirepass devpassword
REDIS_ADDR=127.0.0.1:6379 REDIS_PASSWORD=devpassword \
  go test -run TestRedisIntegrationTTL -v ./...
```

### 13.1 End-to-end demo with docker compose

```bash
docker compose up -d --build
curl -i http://localhost:8000/                # 403
curl -i http://localhost:8000/__knock__/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
                                              # 204
curl -i http://localhost:8000/                # 200 (whoami output)
```

The compose secret is a development placeholder — never reuse it. The compose
demo uses path mode; for a password demo, point the Middleware at
`authMode: password`, add a `users` entry, and mount/set a `cookieSecret`.

### 13.2 Yaegi constraints (important for contributors)

Local plugins are executed by Yaegi (`github.com/traefik/yaegi` v0.16.1 in
Traefik v3.2 and v3.7), not by the Go runtime. Three rules follow:

1. **Standard library only.** Every import must be resolvable inside the Traefik
   image. `yaegi_compat_test.go` fails the build on any import whose first path
   segment contains a dot.
2. **No `errors.Is` / `errors.As` / `errors.Unwrap`.** Yaegi v0.16.1 panics on
   them (`*target must be interface or implement error`), and Traefik recovers
   the panic into an HTTP `500`. This plugin classifies errors with direct type
   assertions on unwrapped errors instead; `yaegi_compat_test.go` enforces it.
3. **One expression per `case` clause.** Yaegi v0.16.1 evaluates only the
   *first* expression of a comma-separated case list instead of OR-ing the
   entries, so the rest is dead code. Unlike rules 1 and 2 this produces no
   panic and no error: `case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':`
   silently accepted lowercase letters only, which made `clientIPHeader` reject
   every real header name (because `http.CanonicalHeaderKey` capitalises the
   first letter) and left `403` on all protected routes.
   `TestYaegiCompatAvoidsMultiExpressionCases` enforces it.

Because rules 2 and 3 only misbehave under the interpreter, `go test` cannot
catch them on its own - the static guards above are what keep the plugin inside
the Yaegi subset.

Verified live against **Traefik v3.2.5 + Redis 7.4** during development:

| Scenario | Result |
| --- | --- |
| Protected request before any knock | `403` |
| `POST` to the knock path | `403`, no Redis write, no backend call (same response as any other path) |
| `GET` to the knock path | `204`, `Cache-Control: no-store`, `Pragma: no-cache`, `X-Knock-Ttl`, Redis key `1` with `TTL 7200` |
| `GET` to the knock path with `redirectURL: /` | `303`, `Location: /`, same `Cache-Control`/`X-Knock-Ttl`, Redis key stored |
| Protected request after the knock | `200`, backend reached |
| Redis stopped | `503` for both knock and protected requests, no panic |
| Redis `-NOPERM` on `SET` (server error) | `503`, connection reused, no panic |

Password, session, Basic, Bearer, realm, CSRF/origin, IP-grant revocation and
CDN-header behavior is covered by the unit tests (`auth_test.go`,
`auth_hardening_test.go`, `crypto_test.go`, `redis_test.go`,
`response_test.go`). The password login, Redis session cookie, protected
request, logout/revocation, JSON Bearer flow, PBKDF2 hash verification and Basic
auth were also exercised under Yaegi v0.16.1 and against Traefik v3.2.5 + Redis
7.4 end to end.

## 14. Usage with curl

```bash
# 1. Not allowlisted yet
$ curl -i https://example.com/
HTTP/2 403
forbidden

# 2. Knock
$ curl -i https://example.com/__knock__/9c4e2e4e3b6d0c0f7b1a2c3d4e5f60718293a4b5c6d7e8f9
HTTP/2 204
cache-control: no-store
pragma: no-cache
x-knock-ttl: 2h0m0s

# With redirectURL: "/" the same knock answers 303 and sends a browser to
# the homepage, so the secret never stays in the address bar:
$ curl -i https://example.com/__knock__/9c4e...f9
HTTP/2 303
location: /

# 3. Access works until the TTL expires
$ curl -i https://example.com/
HTTP/2 200

# 4. After the TTL (default 2h), access is denied again
$ curl -i https://example.com/
HTTP/2 403
```

Wrong method (only `GET` knocks; a `POST` — and `curl -I`, which sends `HEAD` —
is treated as a protected request and answers the same status as any other path
(`403` until the client is authorized), so it does not confirm the secret):

```bash
$ curl -i -X POST https://example.com/__knock__/9c4e...f9
HTTP/2 403
forbidden
```

Wrong path (no knock, no access):

```bash
$ curl -i https://example.com/__knock__/guess
HTTP/2 403
```

### 14.1 Password mode with curl

```bash
# Browser flow: GET the login page, POST the form, keep the cookie jar.
curl -c cookies.txt -b cookies.txt -i https://example.com/__knock__
curl -c cookies.txt -b cookies.txt -i -X POST \
  -d 'username=alice' -d 'password=...' https://example.com/__knock__
curl -c cookies.txt -b cookies.txt -i https://example.com/

# API flow: exchange credentials for a Bearer session token.
TOKEN=$(curl -s -X POST \
  -H 'Accept: application/json' \
  -d 'username=alice' -d 'password=...' \
  https://example.com/__knock__ | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
curl -i -H "Authorization: Bearer $TOKEN" https://example.com/

# Logout (revokes the Redis session).
curl -i -X POST -d 'action=logout' -H "Authorization: Bearer $TOKEN" \
  https://example.com/__knock__
```

Basic auth mode:

```bash
curl -i -u alice:'...' https://example.com/
```

In basic mode, a request without credentials gets `401` with a
`WWW-Authenticate` challenge. In password mode, a protected request without a
session/IP grant gets `403`; a login with a wrong password gets `401`, and
repeated failures get `429` once `maxLoginAttempts` is reached.

## 15. Production checklist

* [ ] In path mode, `knockPath` uses `openssl rand -hex 32` and is stored as a
      secret, not in a public manifest.
* [ ] In password mode, use per-user `passwordHash` values and a separate random
      `cookieSecret` (>= 32 bytes) shared by all Traefik replicas.
* [ ] Prefer `credentialsFile`/`cookieSecretFile` mounted from a Secret over
      inline values in the Middleware CRD.
* [ ] `sessionTTL` is short enough for your risk model; rotate `cookieSecret` to
      invalidate all sessions.
* [ ] `privateResponses: true` (default for password/basic) and the CDN is
      configured not to cache protected responses.
* [ ] Login attempt limiting (`maxLoginAttempts`, `loginWindow`) and a bounded
      `maxConcurrentLogins` are enabled. Compose a Traefik `rateLimit`
      middleware for Basic/API endpoints; Basic itself has no per-IP limit.
* [ ] `realm` is set explicitly (and unique) if several deployments or
      same-named middlewares share a Redis database and `keyPrefix`.
* [ ] Login/logout CSRF is covered by the same-origin header check; if you need
      protection against clients that omit the headers, put a signed CSRF token
      or an edge WAF in front of the login endpoint.
* [ ] The knock URL/login endpoint is shared over a secure channel and rotated
      when leaked.
* [ ] `ttl` is the shortest acceptable window (minutes for admin panels, hours
      for personal sites).
* [ ] `failClosed: true` (default) — never set it to `false` on a security
      boundary.
* [ ] `clientIPHeader` is empty unless a trusted proxy always overwrites it.
* [ ] Traefik is not directly reachable from the internet (NetworkPolicy,
      security group, Cloudflare-only ingress).
* [ ] Redis has a password, a `NetworkPolicy`, `noeviction`, and no persistence
      requirement.
* [ ] Redis credentials and knock secrets are injected from a Secret-based
      pipeline (SOPS/sealed-secrets/CI), never committed.
* [ ] `logClientIP` matches your privacy policy.
* [ ] A `rateLimit` middleware is composed in front of the middleware to slow
      down path-secret guessing and Basic-auth brute force.
* [ ] `redisPoolSize` and Redis `maxmemory` are sized for peak traffic.
* [ ] `go test -race ./...` is green in CI.
* [ ] Alerts exist for `503` responses (Redis outage = total outage when failing
      closed).
* [ ] In path mode, the knock path is excluded from access logs if your log
      pipeline stores full URLs (otherwise the secret is written to logs).
      Password mode does not put credentials in URLs.

## 16. License

MIT — see [LICENSE](LICENSE).
