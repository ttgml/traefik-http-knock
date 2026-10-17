# traefik-http-knock

`traefik-http-knock` is a Traefik v3 middleware plugin that keeps a website
closed to everyone except clients that authenticate first.

It supports three authentication modes:

| Mode | Credential | Grant |
| --- | --- | --- |
| `path` (default) | `GET /__knock__/<secret>` | Redis-backed IP allowlist for `ttl` |
| `password` | login form; Bearer token for CLI/API | session cookie/token, IP grant, or both (`grantMode`) |
| `basic` | HTTP Basic on every request | nothing stored (stateless, no Redis) |

Every grant is scoped to a **realm**. The default realm is the middleware name
plus a short digest of the auth endpoints, so two same-named configurations with
different endpoints do not share grants. Set a unique `realm` when several
deployments share the same Redis database and `keyPrefix`.

Password sessions are always validated against Redis: when Redis is unavailable,
a password cookie/token is unusable and protected requests get `503`, even with
`failClosed: false`. IP-grant lookups follow `failClosed` (default `true`).

## Requirements

* Traefik v3 (verified with v3.2.5 and v3.7, local plugin under Yaegi)
* Redis 6+ for `path` and `password` modes (verified with Redis 7.4)
* Go 1.22+ only when building from source

The plugin uses the Go standard library only, so Traefik can load it as a local
plugin.

## Quick start

### 1. Install the plugin

From the plugin catalog:

```yaml
experimental:
  plugins:
    httpKnock:
      moduleName: github.com/ttgml/traefik-http-knock
      version: v0.2.1
```

Or from source: copy this repository to
`/plugins-local/src/github.com/ttgml/traefik-http-knock` inside the Traefik
container and enable it as a local plugin:

```yaml
experimental:
  localPlugins:
    httpKnock:
      moduleName: github.com/ttgml/traefik-http-knock
```

Password and Basic modes are not part of the v0.2.1 release yet; use the
local-plugin or custom-image setup from `main` until v0.3.0 is published.

### 2. Define the middleware

Path mode, the original behaviour:

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: http-knock
  namespace: traefik-http-knock
spec:
  plugin:
    httpKnock:
      # Must start with "/". 6-80 chars; use 128 bits of randomness.
      knockPath: "/__knock__/REPLACE_WITH_64_HEX_CHARS"
      ttl: "2h"
      # Optional: send the browser to the homepage after a successful knock.
      redirectURL: "/"
      redisAddr: "redis.traefik-http-knock.svc.cluster.local:6379"
      redisPassword: "REPLACE_WITH_REDIS_PASSWORD"
      failClosed: true
      privateResponses: true
```

Generate the secret with:

```bash
openssl rand -hex 32
```

### 3. Attach it to a router

```yaml
spec:
  routes:
    - match: Host(`example.com`)
      kind: Rule
      middlewares:
        - name: http-knock
```

The authentication endpoint must be reachable through the same router.

### 4. Try it

```bash
curl -i https://example.com/                        # 403
curl -i https://example.com/__knock__/<secret>      # 204, or 303 with redirectURL
curl -i https://example.com/                        # 200
```

The grant lasts for `ttl`. Use `GET` for the knock; `POST` and `HEAD` are treated
as ordinary protected requests and do not reveal whether the path matched.

## Password mode

Password mode renders a small login form, verifies one or more users, and issues
a Redis-backed session cookie by default. CLI/API clients can either exchange
their credentials for a Bearer session token (`grantMode: session`/`both`) or use
a separate middleware instance with `authMode: basic`.

Generate a password hash from a repository checkout:

```bash
go run ./cmd/knockhash
# pbkdf2-sha256$600000$...
```

Or a full credentials-file line:

```bash
go run ./cmd/knockhash -username alice
# alice:pbkdf2-sha256$600000$...
```

Minimal middleware:

```yaml
spec:
  plugin:
    httpKnock:
      knockPath: "/__knock__"
      loginPath: "/__knock__"        # defaults to knockPath
      authMode: password
      grantMode: session             # session | ip | both
      users:
        - username: alice
          passwordHash: "pbkdf2-sha256$600000$BASE64_SALT$BASE64_HASH"
      cookieSecretFile: "/etc/traefik/secrets/http-knock-cookie-secret"
      sessionTTL: "12h"
      redisAddr: "redis.traefik-http-knock.svc.cluster.local:6379"
      redisPassword: "REPLACE_WITH_REDIS_PASSWORD"
      realm: "example-com"
      maxLoginAttempts: 5
      loginWindow: "15m"
      privateResponses: true
```

With `grantMode: session` or `both`, `cookieSecret` must be at least 32 bytes and
shared by all Traefik replicas. Prefer the file mount over inline values.
`grantMode: ip` issues no session or token, so it does not require a secret;
`grantMode: both` accepts either.

Login with curl (browser flow):

```bash
curl -c cookies.txt -b cookies.txt -i https://example.com/__knock__
curl -c cookies.txt -b cookies.txt -i -X POST \
  -d 'username=alice' -d 'password=...' https://example.com/__knock__
curl -c cookies.txt -b cookies.txt -i https://example.com/
```

Token flow for API clients:

```bash
TOKEN=$(curl -s -X POST -H 'Accept: application/json' \
  -d 'username=alice' -d 'password=...' \
  https://example.com/__knock__ | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
curl -i -H "Authorization: Bearer $TOKEN" https://example.com/
```

Logout revokes the session in Redis:

```bash
curl -i -X POST -d 'action=logout' -H "Authorization: Bearer $TOKEN" \
  https://example.com/__knock__
```

Login and logout POSTs from a browser must be same-origin. The middleware checks
`Sec-Fetch-Site`, `Origin` and `Referer` and returns `403` for cross-origin
submissions; non-browser clients that send none of these headers are allowed. If
a TLS-terminating proxy sits in front of Traefik, make sure it sets
`X-Forwarded-Proto`.

## Basic mode

For CLI/API clients that can send HTTP Basic credentials on every request:

```yaml
spec:
  plugin:
    httpKnock:
      knockPath: "/__knock__"        # still required by the schema
      authMode: basic
      users:
        - username: api
          passwordHash: "pbkdf2-sha256$600000$BASE64_SALT$BASE64_HASH"
      privateResponses: true
```

```bash
curl -i -u api:'...' https://example.com/
```

Basic mode is stateless and does not use Redis. Every request runs a PBKDF2
verification (tens to low hundreds of milliseconds with the default 600,000
iterations), so it is CPU-bound
and has no per-IP login rate limit; `maxConcurrentLogins` only bounds concurrent
verifications. Put a Traefik `rateLimit` middleware in front of it, and prefer it
for API/CLI clients over HTTPS. A request without credentials gets `401` with a
`WWW-Authenticate` challenge.

## Configuration reference

Common fields:

| Field | Default | Description |
| --- | --- | --- |
| `knockPath` | — (required) | Exact auth path. Starts with `/`; no `?`, `#`, backslashes, percent-encoding or whitespace; 6-80 chars. |
| `authMode` | `path` | `path`, `password` or `basic`. |
| `grantMode` | `ip` (path) / `session` (password) | `ip`, `session`, `both`, or `none` for Basic. |
| `loginPath` | `knockPath` | Password login endpoint; only used in password mode. |
| `redirectURL` | empty | Send the browser to `/` or an absolute `http(s)` URL after a successful knock/login. |
| `ttl` | `2h` | Lifetime of an IP grant. |
| `sessionTTL` | `ttl` | Lifetime of a password session (`session`/`both`). |
| `realm` | middleware name + endpoint digest | Scope for Redis keys, cookies and tokens. Set explicitly when sharing Redis. |
| `keyPrefix` | `traefik:http-knock:` | Prefix for all Redis keys (path/password). |
| `redisAddr` | — | `host:port`; required for `path`/`password`. |
| `redisUsername` / `redisPassword` / `redisDB` | empty / empty / `0` | Redis connection settings. |
| `staticAllowlist` | empty | IPs/CIDRs that bypass the knock and, in password/basic mode, authentication. No Redis lookup. |
| `clientIPHeader` | empty (use `RemoteAddr`) | Only set behind a trusted proxy that overwrites it. |
| `failClosed` | `true` | Return `503` when Redis is unreachable. |
| `dialTimeout` / `readTimeout` / `writeTimeout` | `2s` / `1s` / `1s` | Redis timeouts. |
| `redisPoolSize` | `16` | Maximum pooled Redis connections. |
| `logClientIP` | `false` | Log client IPs instead of `redacted`. |
| `privateResponses` | `true` | Add `Cache-Control: private` and `Vary` to protected responses. Set `false` only when shared caching is intentional. |
| `forwardUserHeader` | empty | Forward the authenticated username (session/Basic only; IP grants are anonymous). Client values are stripped first. |

Password-related fields:

| Field | Default | Description |
| --- | --- | --- |
| `users` | — | Inline `username` + `passwordHash` (or `password`, development only). |
| `credentialsFile` / `credentialsEnv` | empty | `username:hash` lines, or a shared `hash` line. `#` comments and blank lines are ignored. |
| `cookieSecret` / `cookieSecretFile` / `cookieSecretEnv` | — | Session-signing secret, at least 32 bytes; required for `grantMode: session`/`both`, optional for `ip`. File takes precedence. |
| `cookieName` | realm-derived `__Host-` name | Session cookie name. |
| `cookieSecure` / `cookieSameSite` | `true` / `Lax` | Cookie flags. Set `cookieSecure: false` only for local HTTP. |
| `maxLoginAttempts` / `loginWindow` | `5` / `15m` | Per-IP login attempt limit in password mode; `0` disables it. |
| `maxConcurrentLogins` | `4` | Bound on concurrent PBKDF2 verifications (form and Basic); `0` disables it. |

Notes:

* Invalid configuration is rejected by Traefik at load time with an error naming
  the field.
* `loginPath` is only routed in password mode and defaults to `knockPath`. If
  you set a different `loginPath`, the login form, login POST and logout POST
  live there, and `knockPath` becomes an ordinary protected path — it is not a
  second secret gate. In path/basic mode `loginPath` is not routed, but it is
  still validated and still contributes to the default realm digest.
* The auth mode and both endpoint paths are part of the default realm digest,
  so changing any of them invalidates existing grants/sessions unless `realm` is
  set explicitly.
* `credentialsFile`, `cookieSecretFile` and Secret-mounted Redis settings keep
  secrets out of the Middleware CRD. Traefik at `DEBUG` level can print the full
  dynamic configuration, so keep it at `INFO` in production.
* Password changes and user removals revoke existing sessions and password-mode
  IP grants on their next use.
* A `cookieSecret` rotation invalidates every session.
* `grantMode: ip` issues no session/token, so `cookieSecret` is optional there;
  it is still validated if provided. Basic and path mode ignore cookie settings.
* `staticAllowlist` bypasses authentication in password and Basic mode, not
  just the Redis lookup. Only list networks you fully trust.
* New password hashes use 600,000 PBKDF2 iterations by default. Existing hashes
  keep the iteration count stored in the hash and continue to verify.
* Path mode now defaults `privateResponses` to `true` like the other modes. Set
  it to `false` explicitly only if a shared cache is allowed to store protected
  responses; older path-mode configs that relied on the previous default need
  that opt-out.
* Upgrading from v0.1.x: Redis keys are now realm-scoped, so old grants are
  ignored and clients simply knock/log in again.

## Deployment

### Docker Compose

A local Traefik + Redis demo lives in `docker-compose.yml`:

```bash
docker compose up -d --build
curl -i http://localhost:8000/          # 403
curl -i http://localhost:8000/__knock__/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
                                        # 204
curl -i http://localhost:8000/          # 200
```

The compose secret is a development placeholder — never reuse it.

### Kubernetes

`deploy/` contains a complete k3s example (Traefik runs in `kube-system`).
The recommended setup is a custom Traefik image with the plugin baked in:

```bash
docker build -t ghcr.io/<you>/traefik-http-knock:<tag> .
docker push ghcr.io/<you>/traefik-http-knock:<tag>
```

Then apply the example manifests:

```bash
kubectl apply -f deploy/namespace.yaml
kubectl apply -f deploy/redis.yaml
kubectl apply -f deploy/ingressroute.yaml

SECRET=$(openssl rand -hex 32)
REDIS_PASSWORD=$(kubectl -n traefik-http-knock get secret redis-auth \
  -o jsonpath='{.data.password}' | base64 -d)
sed -e "s|REPLACE_WITH_64_HEX_CHARS|${SECRET}|" \
    -e "s|REPLACE_WITH_REDIS_PASSWORD|${REDIS_PASSWORD}|" \
    deploy/middleware.yaml | kubectl apply -f -

# Give Traefik the plugin: custom image (recommended) or ConfigMap mount.
# Edit deploy/helmchartconfig.yaml to pick the option and image tag, then apply.
kubectl apply -f deploy/helmchartconfig.yaml
```

For password mode, render `deploy/middleware-password.yaml` instead, and mount
the credentials and cookie secret as read-only Secret volumes. That example uses
`cookieSecure: true`, so route it through the `websecure` entrypoint (the TLS
IngressRoute at the bottom of `deploy/ingressroute.yaml`); over plain HTTP the
browser drops the cookie and login appears to succeed but protected requests
stay `403`.

To install the plugin without a custom image, build a ConfigMap and apply it
before the `HelmChartConfig`:

```bash
make k8s-plugin-configmap MODULE=github.com/ttgml/traefik-http-knock
kubectl apply -f deploy/plugin-configmap.yaml
```

Use the ConfigMap path only when you cannot build/push an image: ConfigMaps are
capped at 1 MiB and every plugin change needs a refresh plus a Traefik restart.
`HelmChartConfig` must live in the Traefik chart namespace (`kube-system`), while
the Middleware and Redis can live in the application namespace.

The `Middleware` CRD cannot reference a Secret directly, so inject the rendered
Redis password and hashes from your GitOps/secret pipeline (SOPS, sealed-secrets,
CI) and never commit real secrets.

### Redis

* A password plus a `NetworkPolicy` (only Traefik's namespace may connect) is the
  minimum in-cluster hardening.
* No persistence is required: grants and sessions are expendable and clients
  simply authenticate again after a restart.
* Use `maxmemory-policy noeviction` and size `maxmemory` for peak session load
  (`clients × ~150 bytes`) so grants are not evicted before their TTL.
* For larger installations use a managed Redis (HA, auth, TLS) and point
  `redisAddr` at it. The plugin speaks plain RESP; terminate TLS in a sidecar if
  needed.

## Troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Every request `403` after a successful knock | Knock and access use different source IPs (proxy, NAT, IPv6/IPv4 mix) | Use `grantMode: session`, or log the resolved IP with `logClientIP: true` and compare |
| Password login returns `429` | `maxLoginAttempts` reached, or too many concurrent KDFs | Wait for `loginWindow`, or clear `<prefix><realm>:login:<ip>` in Redis |
| Login succeeds but the next request is `403` | Cookie not sent (host/`Secure`/`Path`), or the session was revoked | Check the cookie in devtools; confirm `cookieSecure` matches HTTPS |
| Password cookie stops working with `503` | Redis is down; sessions always fail closed | Restore Redis; this is intentional |
| Every request `503` | Redis unreachable, wrong `redisAddr`, auth failure, disabled DB | Check the Redis logs and secret, then test with `redis-cli` |
| `403` on the knock URL with a non-GET method | Only `GET` is a knock | Use `curl -i`; `curl -I` sends `HEAD` |
| Knock returns `204` but nothing is stored | Wrong Redis DB/prefix, or a different Redis | Compare `keyPrefix` and `redisDB` |
| Plugin not loaded | `moduleName` mismatch or wrong mount path | Check `/plugins-local/src/<moduleName>` and the `additionalArguments` value |
| Plugin config rejected at startup | Invalid path/ttl/timeouts, missing users, or a missing/invalid session cookie secret | The error names the field |
| Grant or session disappears too early | TTL too short, or Redis evicted the key | Check `TTL <key>`; use `noeviction` and enough `maxmemory` |
| Arbitrary IPs can be allowlisted | `clientIPHeader` set without a trusted proxy overwriting it | Remove `clientIPHeader` and rely on `RemoteAddr` |

Useful checks:

```bash
kubectl -n kube-system logs deploy/traefik --tail=100 | grep http-knock
kubectl -n traefik-http-knock exec deploy/redis -- \
  redis-cli --scan --pattern 'traefik:http-knock:*'
```

## Security notes

* **Secret strength.** Use `openssl rand -hex 32` for `knockPath`; the plugin
  enforces 6-80 characters but only a random secret is hard to guess. Rotate it
  by changing the value and rolling the middleware.
* **Passwords.** Prefer `passwordHash` or a Secret-mounted `credentialsFile` over
  plaintext. New hashes default to 600,000 PBKDF2-HMAC-SHA256 iterations (the
  OWASP recommendation); per-IP login attempt limiting and bounded concurrent
  KDFs are built in. Use one username per person if you need attribution or
  per-person revocation.
* **Session cookie.** Requires a separate random `cookieSecret` (≥ 32 bytes)
  shared by all replicas, and HTTPS. Cookies are `HttpOnly`, `Secure`,
  `SameSite=Lax` and use a realm-derived `__Host-` name by default.
* **Client IP header.** Only set `clientIPHeader` when a trusted proxy or load
  balancer always overwrites it; otherwise clients can spoof their IP and
  allowlist themselves. Keep Traefik unreachable except through that edge
  (NetworkPolicy, security group, Cloudflare Tunnel). For `X-Forwarded-For`, only
  the left-most entry is used.
* **Fail closed.** Keep `failClosed: true`. Password sessions always fail closed
  regardless of this setting.
* **CDN caching.** `privateResponses` defaults to `true` in every mode; leave it
  enabled so a response authorized by one client cannot be cached and served to
  another.
* **CSRF.** Login/logout POSTs are checked against same-origin headers. A client
  that sends none of them is treated as non-browser and allowed; add a signed
  CSRF token or an edge WAF if that residual risk is unacceptable.
* **Basic auth.** Sends the password on every request, has no logout, and costs
  a PBKDF2 verification per request. Use it over TLS, for API/CLI clients, behind
  a `rateLimit`.
* **Shared IPs.** With `grantMode: ip`, users behind the same NAT/CGNAT share
  access, and changing one user's password revokes the whole shared IP grant.
  `grantMode: session` avoids both. IP grants are anonymous, so
  `forwardUserHeader` is empty for requests authorized that way.
* **Logging.** Secrets, passwords, session ids and tokens are never logged.
  `logClientIP` is off by default. In path mode, exclude the knock URL from
  access logs if your pipeline stores full URLs.
* **Redis.** Use a password and a `NetworkPolicy`, and consider TLS for
  cross-network access. A Redis compromise exposes sessions and IP grants.

## API summary

| Request | Result |
| --- | --- |
| `GET <knockPath>` (path mode) | `204`, or `303` with `redirectURL`; sets the IP grant |
| `GET <loginPath>` (password mode) | login form |
| `POST <loginPath>` with `username`/`password` | session cookie (`session`/`both`), IP grant (`ip`/`both`); JSON token with `Accept: application/json` |
| `POST <loginPath>` with `action=logout` | revokes the session/IP grant, clears the cookie, `303` |
| Protected request without a grant | `403` (password/path), `401` + challenge (Basic/Bearer) |
| Login/KDF limits exceeded | `429` |
| Redis unavailable | `503` |

Successful authentication responses carry `Cache-Control: no-store`; protected
responses are marked private by default in every mode.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the project layout, tests, Yaegi
constraints and release process. Quick checks:

```bash
go test ./...
go test -race ./...
make e2e            # Traefik + Yaegi + Redis compose smoke test
```

## License

MIT — see [LICENSE](LICENSE).
