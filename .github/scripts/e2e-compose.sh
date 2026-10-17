#!/usr/bin/env bash
# End-to-end smoke test through the real plugin loader.
#
# This is the only check that exercises the plugin under Yaegi (the interpreter
# Traefik uses for local plugins) instead of the Go runtime. It builds the
# custom Traefik image, starts Redis + whoami, and drives all three auth modes.
#
#   make e2e
#   bash .github/scripts/e2e-compose.sh
#   E2E_SKIP_BUILD=1 bash .github/scripts/e2e-compose.sh  # reuse an existing image
set -euo pipefail

cd "$(dirname "$0")/../.."

COMPOSE=(docker compose -f docker-compose.yml -f .github/e2e/compose.yml)
PATH_URL="http://127.0.0.1:8000"
PASSWORD_URL="http://127.0.0.1:8001"
BASIC_URL="http://127.0.0.1:8002"
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

echo "==> building and starting Traefik + Redis + whoami"
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

echo "e2e passed: path, password, Basic, logout and Redis outage"
