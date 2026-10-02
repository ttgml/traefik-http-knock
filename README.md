# traefik-http-knock

`traefik-http-knock` is a Traefik v3 middleware plugin that keeps a website
closed to everyone except clients that first performed a secret **HTTP knock**.

A knock is a request to a private path, for example:

```
GET /__knock__/9c4e2e4e3b6d0c0f...64-hex-chars...
```

When the request matches, the plugin stores the client IP in Redis with a TTL,
answers `204 No Content` (or redirects to a configured `redirectURL`, for
example `/` for the homepage) and never forwards the request to the backend.
Every
other request is allowed only while that Redis key exists; otherwise the plugin
answers `403 Forbidden`. Redis expires the key on its own, so the plugin keeps
no in-memory state and starts no cleanup goroutines.

- Traefik v3 middleware plugin (`CreateConfig`, `New`, `ServeHTTP`)
- Go standard library only, no third-party dependencies (Yaegi friendly)
- Minimal RESP client: `AUTH`, `SELECT`, `PING`, `EXISTS`, `SET ... EX`
- Bounded Redis connection pool with dial/read/write timeouts
- Fail closed by default: a Redis outage returns `503`, never `allow`

Verified end to end against Traefik v3.2.5 (local plugin, Yaegi) and Redis 7.4:
`403` before the knock, `204` + `Cache-Control: no-store` for a successful knock
(`303 See Other` when `redirectURL` is set), `200` afterwards, `403` for non-GET
requests (identical to any other path), and `503` while Redis was unreachable.

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
      verify knock              Redis EXISTS
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
`deploy/helmchartconfig.yaml`, `deploy/traefik-static-config.yml` and
`deploy/traefik-compose.yml`.

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
| Redis TTL allowlist (state store only, no Go timers) | implemented |
| `403` for non-allowlisted clients | implemented |
| Non-GET requests handled like any other protected path (no path oracle) | implemented |
| `204` + `Cache-Control: no-store` on successful knock | implemented |
| Optional post-knock redirect (`redirectURL`, e.g. `/` for the homepage) | implemented |
| Client IP from `RemoteAddr` or a configured header | implemented |
| Static allowlist of IPs and CIDR ranges (always allowed) | implemented |
| IPv4 and IPv6, canonicalized (`2001:0DB8::1` == `2001:db8::1`) | implemented |
| Fail closed on Redis errors (`503`) | implemented |
| Bounded connection pool, timeouts, connection reuse | implemented |
| Constant-time secret path comparison | implemented |
| Client IP logging toggle (`logClientIP`, off by default) | implemented |
| HMAC token knock (`?token=timestamp.nonce.signature`) | **planned**, extension point in place |
| Knock rate limiting / brute-force protection | **planned** |

Version 1 deliberately implements only what is needed to be correct, stable,
secure and deployable.

## 2. How it works

1. Traefik routes the request to the middleware (`Middleware` CRD or labels).
2. If the request is **not** a `GET` whose `req.URL.Path` is (constant-time) equal
   to `knockPath`, the request is a **protected request**:
   * resolve the client IP,
   * client IP on the static allowlist → `next.ServeHTTP()` (no Redis call, so
     this keeps working during a Redis outage),
   * otherwise `EXISTS <keyPrefix><clientIP>` in Redis,
   * key present → `next.ServeHTTP()` (the backend is reached),
   * key absent → `403 Forbidden`,
   * Redis error → `503 Service Unavailable` (fail closed), or `next.ServeHTTP()`
     when the operator explicitly set `failClosed: false`.
3. If the request is a `GET` whose path matches, it is a **knock**:
   * resolve the client IP,
   * `SET <keyPrefix><clientIP> 1 EX <ttl>`,
   * success → `204 No Content`, `Cache-Control: no-store`, `X-Knock-TTL: 2h0m0s`,
     or `303 See Other` + `Location: <redirectURL>` when `redirectURL` is set,
   * Redis error → `503 Service Unavailable`, regardless of `failClosed`
     (a failed knock never redirects),
   * the request is always terminated here and never reaches the backend.

Only `GET` is a knock. Any other method (including `HEAD`) to the knock path is
handled exactly like a request to any other protected path and answers `403`
unless the client is already allowlisted, so it cannot be used to confirm a
guessed secret path.

The middleware never modifies the request (method, host, URL, authorization,
cookies, headers, body) nor the backend response. It only answers
allow / deny / knock.

## 3. Redis data model

| Key | Value | TTL |
| --- | --- | --- |
| `<keyPrefix><clientIP>` | `1` | configured `ttl` |

Examples:

```text
traefik:http-knock:192.168.1.10       -> 1  (EX 7200)
traefik:http-knock:2001:db8::1        -> 1  (EX 7200)
```

* The IP is normalized (`net.ParseIP(...).String()`) before the key is built, so
  different spellings of the same IPv6 address cannot create two entries.
* The IP is validated before use, so a client cannot inject arbitrary bytes or
  a `keyPrefix` break into the Redis key.
* The value is irrelevant: only `EXISTS` matters. TTL expiry is the only
  removal mechanism (there is no `DEL` in the request path).

Inspect state manually:

```bash
kubectl -n traefik-http-knock exec deploy/redis -- \
  redis-cli -a "$REDIS_PASSWORD" --scan --pattern 'traefik:http-knock:*'
kubectl -n traefik-http-knock exec deploy/redis -- \
  redis-cli -a "$REDIS_PASSWORD" TTL traefik:http-knock:203.0.113.5
```

## 4. Security model

The plugin is a **temporary IP allowlist**: whoever knows the knock path can
allowlist their own IP until the TTL expires.

| Risk | Mitigation |
| --- | --- |
| Guessable knock path | Use a 128-bit random secret (`openssl rand -hex 32`); length is enforced at config time (6–80 chars) |
| Timing side channel on the secret | Constant-time path comparison (length is not secret) |
| Status-code oracle on the secret path | Only `GET` is a knock; non-GET requests get the same `403` for the secret path and any other path, so no distinct status reveals a match |
| Response caching by browsers/proxies | `Cache-Control: no-store` and `Pragma: no-cache` on knock responses |
| Knock request reaching the backend | The middleware terminates the request itself and never calls `next` for a knock, including when `failClosed: false` |
| Open redirect via `redirectURL` | Only same-origin absolute paths (starting with a single `/`) and absolute `http`/`https` URLs are accepted; `//host`, other schemes, control characters and backslashes (`/\evil` normalises to `//evil`) are rejected at config load |
| Redis outage turning into an allow | Fail closed: `503`, never `next` for protected requests unless the operator explicitly sets `failClosed: false`. A knock is always terminated with `503` |
| Header spoofing (`X-Forwarded-For` etc.) | Off by default (`RemoteAddr` is used). `clientIPHeader` must only be set when a trusted proxy overwrites it |
| Static allowlist entries matching a spoofed client IP | Static entries match the resolved client IP, so they share the trust of `clientIPHeader`; keep it empty unless a trusted proxy overwrites it |
| Secret leaking into logs | Knock URLs, paths and Redis credentials are never logged. Use `logClientIP: true` only if you accept logging client IPs |
| Brute force on the knock path | Not covered by v1. Put the knock path behind a rate limit (`rateLimit` middleware) and/or a non-guessable secret, or wait for the HMAC token knock |
| Redis compromise/exposure | Run Redis in-cluster, require a password, restrict it with a `NetworkPolicy` (see `deploy/redis.yaml`) |

Residual risks you must accept or handle outside the plugin:

* Anyone who learns the secret URL can allowlist any IP they can make requests
  from. Treat the URL like a password; rotate it by changing `knockPath`.
* The allowlist is per client IP as seen by Traefik. Behind carrier-grade NAT /
  a corporate proxy, knocking allowlists other users sharing that IP.
* A stolen allowlist entry is valid for the whole TTL (default `2h`). Shorten
  `ttl` for sensitive services.

## 5. Configuration reference

```yaml
httpKnock:
  # Required. Exact path that triggers the knock. Must start with "/",
  # must not contain "?" or "#", 6 to 80 characters long.
  knockPath: "/__knock__/9c4e2e4e3b6d0c0f7b1a2c3d4e5f60718293a4b5c6d7e8f9"
  # Allowlist entry lifetime (Go duration). Redis expires the key.
  ttl: "2h"

  # Optional. Where a browser is sent after a successful knock. Set it to "/"
  # to land on the homepage (same origin), or to an absolute http(s) URL.
  # Only paths starting with "/" and absolute http(s) URLs are accepted;
  # "//host", other schemes and backslashes are rejected. Empty (default)
  # keeps the plain 204 response.
  redirectURL: ""

  # Required. "host:port" of Redis.
  redisAddr: "redis.traefik-http-knock.svc.cluster.local:6379"
  # Optional, Redis >= 6 ACL style. Prefer a Secret for the password.
  redisUsername: ""
  redisPassword: ""
  # Optional logical database (default 0).
  redisDB: 0

  # Prefix of the Redis key (default "traefik:http-knock:").
  keyPrefix: "traefik:http-knock:"

  # Optional. Only set when a trusted proxy always overwrites this header:
  # "X-Real-IP", "CF-Connecting-IP", "X-Forwarded-For", ...
  # Empty (default) means req.RemoteAddr (not spoofable).
  clientIPHeader: ""

  # Optional. IPs and CIDR ranges that are always allowed: no knock and no
  # Redis lookup. Entries are single IPs or CIDR ranges, IPv4 or IPv6. Empty
  # (default) means only knocks grant access. Validated at load time.
  staticAllowlist: []
  #  - "203.0.113.7"
  #  - "192.168.0.0/16"
  #  - "2001:db8::/32"

  # true (default): Redis errors return 503. false: Redis errors let the
  # request through (fail open). Never use false on a security boundary.
  failClosed: true

  # Timeouts and pool size.
  dialTimeout: "2s"
  readTimeout: "1s"
  writeTimeout: "1s"
  redisPoolSize: 16

  # Include client IPs in logs (default false).
  logClientIP: false
```

Notes:

* `failClosed` uses the same YAML name as the requested configuration but is a
  `*bool` in Go so that "unset" can be distinguished from an explicit `false`.
  Unset means `true`, which keeps the secure default. This is the only
  intentional deviation from the original field list.
* Invalid values make Traefik reject the middleware configuration at load time
  with a descriptive error (for example a malformed `ttl`); no request is
  served with a half-applied configuration.
* Redis is not contacted when the middleware is created, so a Redis outage
  cannot break Traefik's startup.

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
192.168.1.10     -> traefik:http-knock:192.168.1.10
[2001:db8::1]:443-> traefik:http-knock:2001:db8::1
2001:0DB8:0::1   -> traefik:http-knock:2001:db8::1
```

Zones (`fe80::1%eth0`) are stripped. IPv4-mapped IPv6 addresses (`::ffff:10.0.0.1`)
normalize to `10.0.0.1`, which is what Go's `net` package reports too, so a
client seen over IPv4 and IPv4-mapped IPv6 shares one allowlist entry.

### 6.4 Logging

Logged events (never the secret, never credentials):

```text
knock succeeded for client <redacted|IP>
knock rejected: method POST is not allowed
knock rejected: no usable client IP found in the request
request denied for client <redacted|IP>: no active knock
redis unavailable for client <redacted|IP>: <error>
```

`logClientIP: false` (default) replaces the IP with `redacted`.

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
├── ip.go                         # client IP extraction, normalization, keys
├── redis.go                      # minimal RESP client + bounded pool
├── knock_test.go                 # middleware behaviour tests
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
* `.github/workflows/ci.yml` — `fmt`, `vet`, `test`, `test -race` on every push.

## 8. Traefik v3 configuration

### 8.1 Plugin Catalog (published releases)

```yaml
experimental:
  plugins:
    httpKnock:
      moduleName: github.com/ttgml/traefik-http-knock
      version: v0.1.1
```

Requirements for a catalog release:

* repository path equals the module path in `go.mod`,
* `.traefik.yml` at the repository root with `import:` equal to that module
  path,
* a semver tag (`v0.1.0`) that Traefik can resolve through the Go module proxy,
* no `replace` directives and no dependencies outside the standard library
  (this plugin has none).

Then release:

```bash
make release PLUGIN_VERSION=v0.1.1   # runs the checks and creates an annotated tag
git push origin v0.1.1
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

Every request matching the router (including the knock URL on the same host)
passes through the middleware. The knock path must be reachable on the same
router, otherwise the knock never arrives.

## 9. k3s deployment

`deploy/` contains a complete example for a k3s cluster whose Traefik runs in
`kube-system` (the k3s default).

```bash
# 1. Namespace + Redis + demo app + Middleware + IngressRoute
kubectl apply -f deploy/namespace.yaml
kubectl apply -f deploy/redis.yaml
kubectl apply -f deploy/ingressroute.yaml

# 2. Set a real knock secret and the Redis password
SECRET=$(openssl rand -hex 32)
REDIS_PASSWORD=$(kubectl -n traefik-http-knock get secret redis-auth -o jsonpath='{.data.password}' | base64 -d)
sed -e "s|REPLACE_WITH_64_HEX_CHARS|${SECRET}|" \
    -e "s|REPLACE_WITH_REDIS_PASSWORD|${REDIS_PASSWORD}|" \
    deploy/middleware.yaml | kubectl apply -f -

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
docker build -t ghcr.io/<user>/traefik-http-knock:v0.1.1 .
docker push ghcr.io/<user>/traefik-http-knock:v0.1.1
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

## 10. Redis configuration

The deployment uses an ephemeral Redis: the allowlist is intentionally
expendable, and restarting Redis only means clients have to knock again.

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

* `noeviction` so that a full Redis never silently drops allowlist entries
  earlier than their TTL. Size `maxmemory` for peak knock load
  (`clients × ~80 bytes`).
* No persistence: allowlist data is not worth a volume.
* A password plus a `NetworkPolicy` (only Traefik's namespace may connect) is the
  minimum in-cluster hardening.
* For larger installations use a managed/external Redis (HA, auth, TLS) and
  point `redisAddr` at it. The plugin speaks plain RESP over TCP; if you need
  TLS to Redis, terminate it in a sidecar/socat proxy or open an issue — v1 has
  no TLS support.
* Keys are always written with an `EX` argument, so Redis expires them even if
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
5. If Cloudflare's proxy sends IPv6 when a client prefers IPv6, knock and access
   must both happen over the same family, otherwise the allowlist key differs.
   Fix by forcing IPv4 at the edge or by knocking and browsing over the same
   network.

## 12. Failure modes and troubleshooting

| Symptom | Likely cause | Action |
| --- | --- | --- |
| Every request `403` after a successful knock | Knock and access use different source IPs (proxy, NAT, IPv6/IPv4 mix) | Log the resolved IP (`logClientIP: true`) and check which header/hop is used; compare with `redis-cli --scan` |
| Every request `503` | Redis unreachable, wrong `redisAddr`, auth failure, or `SELECT` to a disabled DB | `kubectl -n traefik-http-knock logs deploy/redis`, check the Secret, test with `redis-cli -h ... -a ...` |
| `403` on the knock URL with a non-GET method | Only `GET` knocks; other methods are treated as protected requests | Use `curl -i` (a `GET`); `curl -I` sends `HEAD` and will not knock |
| Knock returns `204` but nothing is stored | Wrong Redis DB/prefix or you are looking at another Redis | Compare `keyPrefix` and `redisDB`, inspect with `redis-cli --scan --pattern '<prefix>*'` |
| Traefik logs `command not found` / plugin not loaded | `moduleName` does not match `go.mod`, or source is not in `/plugins-local/src/<moduleName>` | Check the mount path and the `additionalArguments` value (case-sensitive) |
| Plugin config rejected at startup | Invalid `knockPath`/`ttl`/timeouts | The error message names the field; see section 5 |
| Allowlist entry disappears too early | `ttl` too short, or Redis evicted the key | Check `TTL <key>`; use `noeviction` and enough `maxmemory` |
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
Docker is required. The Redis integration test is opt-in:

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

The compose secret is a development placeholder — never reuse it.

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
is treated as a protected request and answers the same `403` as any other path,
so it does not confirm the secret):

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

## 15. Production checklist

* [ ] `knockPath` uses `openssl rand -hex 32` and is stored as a secret, not in
      a public manifest.
* [ ] The knock URL is shared over a secure channel and rotated when leaked.
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
      down secret guessing.
* [ ] `redisPoolSize` and Redis `maxmemory` are sized for peak traffic.
* [ ] `go test -race ./...` is green in CI.
* [ ] Alerts exist for `503` responses (Redis outage = total outage when failing
      closed).
* [ ] The knock path is excluded from access logs if your log pipeline stores
      full URLs (otherwise the secret is written to logs).

## 16. License

MIT — see [LICENSE](LICENSE).
