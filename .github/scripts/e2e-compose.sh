#!/usr/bin/env bash
# End-to-end smoke test through the real plugin loader.
#
# This is the only check that exercises the plugin under Yaegi (the interpreter
# Traefik uses for local plugins) instead of the Go runtime. It builds the
# custom Traefik image, starts Redis + whoami + an SSE backend, and drives all
# three auth modes, streaming responses included.
#
#   make e2e
#   bash .github/scripts/e2e-compose.sh
#   E2E_SKIP_BUILD=1 bash .github/scripts/e2e-compose.sh  # reuse the e2e image
#   E2E_COMPOSE_OVERRIDE=override.yml bash .github/scripts/e2e-compose.sh
#     # extra compose file, for sandboxes that must reuse locally built images
set -euo pipefail

cd "$(dirname "$0")/../.."

COMPOSE=(docker compose -f .github/e2e/compose.yml)
if [ -n "${E2E_COMPOSE_OVERRIDE:-}" ]; then
	COMPOSE+=(-f "$E2E_COMPOSE_OVERRIDE")
fi

# Published ports live on the Docker host. A plain local run and a
# GitHub-hosted VM runner reach them on loopback. Inside a CI job container
# (Gitea act_runner, for example) loopback is the job container itself, so the
# published ports must be reached through the container's default gateway.
# GITHUB_ACTIONS alone is not a container signal: GitHub-hosted runners are VMs.
host_addr="127.0.0.1"
if [ -f /.dockerenv ] || [ -f /run/.containerenv ] || [ -n "${GITEA_ACTIONS:-}" ]; then
	gateway=""
	if command -v ip >/dev/null 2>&1; then
		gateway="$(ip route 2>/dev/null | awk '/^default/ {print $3; exit}')"
	fi
	if [ -z "$gateway" ] && [ -r /proc/net/route ]; then
		# /proc/net/route stores the gateway as little-endian hex bytes.
		hex="$(awk '$2 == "00000000" {print $3; exit}' /proc/net/route)"
		if [ -n "$hex" ]; then
			gateway="$(printf '%d.%d.%d.%d' "0x${hex:6:2}" "0x${hex:4:2}" "0x${hex:2:2}" "0x${hex:0:2}")"
		fi
	fi
	if [ -n "$gateway" ]; then
		host_addr="$gateway"
	fi
fi
echo "==> reaching published ports on $host_addr"

PATH_URL="http://$host_addr:8000"
PASSWORD_URL="http://$host_addr:8001"
BASIC_URL="http://$host_addr:8002"
KNOCK_SECRET="/__knock__/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

tmpdir="$(mktemp -d)"
jar="$tmpdir/cookies.txt"

cleanup() {
	rm -rf "$tmpdir"
	"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
}

dump_logs() {
	"${COMPOSE[@]}" logs --no-color --tail=200 >&2 || true
}

on_exit() {
	status=$?
	trap - EXIT
	if [ "$status" -ne 0 ]; then
		echo "e2e failed; recent compose logs:" >&2
		dump_logs
	fi
	cleanup
	exit "$status"
}
trap on_exit EXIT

wait_for_code() {
	local description="$1" expected="$2" url="$3"
	local code
	for _ in $(seq 1 60); do
		code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 2 "$url" 2>/dev/null || true)"
		if [ "$code" = "$expected" ]; then
			return 0
		fi
		sleep 1
	done
	echo "timed out waiting for $description ($url -> $expected, last code $code)" >&2
	return 1
}

assert_code() {
	local description="$1" expected="$2"
	shift 2
	local code
	code="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$@" 2>/dev/null || true)"
	if [ "$code" != "$expected" ]; then
		echo "FAIL: $description: got ${code:-<none>}, want $expected" >&2
		return 1
	fi
	echo "ok: $description ($code)"
}

echo "==> building and starting Traefik + Redis + whoami + SSE"
if [ "${E2E_SKIP_BUILD:-0}" = "1" ]; then
	# Useful when the image was built separately (and in sandboxes where the
	# Docker buildx cache directory is not writable).
	"${COMPOSE[@]}" up -d --no-build
else
	"${COMPOSE[@]}" up -d --build
fi

echo "==> path mode"
wait_for_code "path mode to become ready" 403 "$PATH_URL/"
assert_code "path: protected before knock" 403 "$PATH_URL/"
assert_code "path: POST to knock path is protected before a grant" 403 -X POST "$PATH_URL$KNOCK_SECRET"
assert_code "path: knocks" 204 "$PATH_URL$KNOCK_SECRET"
assert_code "path: protected after knock" 200 "$PATH_URL/"

echo "==> password mode"
wait_for_code "password mode to become ready" 200 "$PASSWORD_URL/__knock__"
assert_code "password: login page" 200 "$PASSWORD_URL/__knock__"
assert_code "password: login sets a session" 303 \
	-c "$jar" -b "$jar" -d "username=alice" -d "password=knock-demo" "$PASSWORD_URL/__knock__"
assert_code "password: session authorizes" 200 -b "$jar" "$PASSWORD_URL/"
assert_code "password: logout revokes the session" 303 \
	-b "$jar" -X POST -d "action=logout" "$PASSWORD_URL/__knock__"
assert_code "password: session is gone after logout" 403 -b "$jar" "$PASSWORD_URL/"

token="$(curl -sS --max-time 10 -H 'Accept: application/json' \
	-d "username=alice" -d "password=knock-demo" "$PASSWORD_URL/__knock__" \
	| sed -n 's/.*"token":"\([^"]*\)".*/\1/p')"
if [ -z "$token" ]; then
	echo "FAIL: JSON login did not return a token" >&2
	exit 1
fi
assert_code "password: Bearer token authorizes" 200 -H "Authorization: Bearer $token" "$PASSWORD_URL/"
assert_code "password: Bearer logout revokes the token" 303 \
	-H "Authorization: Bearer $token" -X POST -d "action=logout" "$PASSWORD_URL/__knock__"
assert_code "password: Bearer token is rejected after logout" 401 \
	-H "Authorization: Bearer $token" "$PASSWORD_URL/"

echo "==> basic mode"
assert_code "basic: challenge without credentials" 401 "$BASIC_URL/"
assert_code "basic: valid credentials authorize" 200 -u alice:knock-demo "$BASIC_URL/"

echo "==> SSE streaming (basic mode, privateResponses: true)"
assert_code "sse: challenge without credentials" 401 "$BASIC_URL/events"

# The backend sends four events two seconds apart and then closes the stream. A
# response buffered by the plugin delivers headers and body together only when
# the stream ends, so the first byte would arrive about six seconds in. A
# flushed stream delivers the first event immediately. Comparing the two
# timings keeps the check independent of how fast the runner is.
sse_headers="$tmpdir/sse-headers.txt"
sse_body="$tmpdir/sse-body.txt"
sse_code=""
for _ in $(seq 1 30); do
	sse_timing="$(curl -sS -N -u alice:knock-demo --max-time 20 \
		-D "$sse_headers" -o "$sse_body" \
		-w '%{http_code} %{time_starttransfer} %{time_total}' \
		"$BASIC_URL/events" 2>/dev/null || true)"
	read -r sse_code sse_start sse_end <<<"$sse_timing" || true
	[ "$sse_code" = "200" ] && break
	sleep 1
done
if [ "$sse_code" != "200" ]; then
	echo "FAIL: sse: got ${sse_code:-<none>}, want 200" >&2
	exit 1
fi
echo "ok: sse: stream authorized (200)"

if ! awk -v start="$sse_start" -v end="$sse_end" \
	'BEGIN { exit !(start + 0 > 0 && end - start > 2) }'; then
	echo "FAIL: sse: first byte at ${sse_start}s of a ${sse_end}s stream; the response was buffered" >&2
	exit 1
fi
echo "ok: sse: first byte at ${sse_start}s, stream ended at ${sse_end}s"

events="$(grep -c '^data: event-' "$sse_body" || true)"
if [ "$events" != "4" ]; then
	echo "FAIL: sse: body contained $events events, want 4" >&2
	exit 1
fi
echo "ok: sse: all four events arrived"

if ! grep -qi '^cache-control:.*private' "$sse_headers"; then
	echo "FAIL: sse: Cache-Control is not private" >&2
	exit 1
fi
if ! grep -qi '^vary:.*cookie' "$sse_headers"; then
	echo "FAIL: sse: Vary does not include Cookie" >&2
	exit 1
fi
echo "ok: sse: privateResponses headers applied to the stream"

echo "==> Redis outage"
"${COMPOSE[@]}" stop redis >/dev/null
assert_code "redis down: path protected fails closed" 503 "$PATH_URL/"
assert_code "redis down: password login fails closed" 503 \
	-d "username=alice" -d "password=knock-demo" "$PASSWORD_URL/__knock__"
assert_code "redis down: basic still works" 200 -u alice:knock-demo "$BASIC_URL/"

"${COMPOSE[@]}" start redis >/dev/null
wait_for_code "path mode to recover" 403 "$PATH_URL/"
assert_code "redis back: path knocks again" 204 "$PATH_URL$KNOCK_SECRET"
assert_code "redis back: path protected after new knock" 200 "$PATH_URL/"

echo "e2e passed: path, password, Basic, SSE streaming, logout and Redis outage"
