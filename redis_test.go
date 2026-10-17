package traefik_http_knock

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func newTestRedisClient(t *testing.T, addr string, mutate ...func(*redisOptions)) *redisClient {
	t.Helper()
	opts := redisOptions{
		addr:         addr,
		dialTimeout:  2 * time.Second,
		readTimeout:  time.Second,
		writeTimeout: time.Second,
		maxConns:     4,
	}
	for _, m := range mutate {
		m(&opts)
	}
	client := newRedisClient(opts)
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func TestRedisTTLSeconds(t *testing.T) {
	tests := []struct {
		name string
		ttl  time.Duration
		want int64
	}{
		{name: "two hours", ttl: 2 * time.Hour, want: 7200},
		{name: "exact seconds", ttl: 90 * time.Second, want: 90},
		{name: "sub-second rounds up to one", ttl: 500 * time.Millisecond, want: 1},
		{name: "truncates partial seconds", ttl: 1500 * time.Millisecond, want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := redisTTLSeconds(tt.ttl); got != tt.want {
				t.Fatalf("redisTTLSeconds(%s) = %d, want %d", tt.ttl, got, tt.want)
			}
		})
	}
}

func TestRedisSetNXEx(t *testing.T) {
	srv := startFakeRedis(t)
	client := newTestRedisClient(t, srv.addr())

	key := loginFailureKey(DefaultKeyPrefix, "test", "203.0.113.9")
	created, err := client.setNXEx(key, "0", time.Minute)
	if err != nil {
		t.Fatalf("setNXEx first: %v", err)
	}
	if !created {
		t.Fatal("first SET NX EX must create the key")
	}

	created, err = client.setNXEx(key, "9", time.Minute)
	if err != nil {
		t.Fatalf("setNXEx second: %v", err)
	}
	if created {
		t.Fatal("SET NX EX must not overwrite an existing key")
	}
	value, ok, err := client.getValue(key)
	if err != nil || !ok || value != "0" {
		t.Fatalf("value after second setNXEx = %q, ok=%v, err=%v", value, ok, err)
	}

	// After the TTL the key can be created again.
	srv.expireAll()
	created, err = client.setNXEx(key, "0", time.Minute)
	if err != nil {
		t.Fatalf("setNXEx after expiry: %v", err)
	}
	if !created {
		t.Fatal("SET NX EX must create the key after expiry")
	}
}

func TestRedisSetExAndExists(t *testing.T) {
	srv := startFakeRedis(t)
	client := newTestRedisClient(t, srv.addr())

	key := ipGrantKey(DefaultKeyPrefix, "test", "192.168.1.10")

	allowed, err := client.exists(key)
	if err != nil {
		t.Fatalf("exists before set: %v", err)
	}
	if allowed {
		t.Fatal("key must not exist before the knock")
	}

	if err := client.setEx(key, "1", 2*time.Hour); err != nil {
		t.Fatalf("setEx: %v", err)
	}

	allowed, err = client.exists(key)
	if err != nil {
		t.Fatalf("exists after set: %v", err)
	}
	if !allowed {
		t.Fatal("key must exist after the knock")
	}

	want := "SET traefik:http-knock:test:ip:192.168.1.10 1 EX 7200"
	if got := srv.recordedCommands(); !contains(got, want) {
		t.Fatalf("expected command %q, got %v", want, got)
	}
}

func TestRedisKeyForIPv6IsUnambiguous(t *testing.T) {
	srv := startFakeRedis(t)
	client := newTestRedisClient(t, srv.addr())

	key := ipGrantKey(DefaultKeyPrefix, "test", "2001:db8::1")
	if err := client.setEx(key, "1", time.Minute); err != nil {
		t.Fatalf("setEx: %v", err)
	}

	want := "SET traefik:http-knock:test:ip:2001:db8::1 1 EX 60"
	if got := srv.recordedCommands(); !contains(got, want) {
		t.Fatalf("expected command %q, got %v", want, got)
	}
}

func TestRedisHandshakeAuthAndSelect(t *testing.T) {
	srv := startFakeRedis(t, fakeRedisOptions{
		password:  "s3cr3t",
		username:  "knock",
		requireDB: 3,
	})
	client := newTestRedisClient(t, srv.addr(), func(o *redisOptions) {
		o.password = "s3cr3t"
		o.username = "knock"
		o.db = 3
	})

	if err := client.ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}

	got := srv.recordedCommands()
	if !contains(got, "AUTH knock s3cr3t") {
		t.Fatalf("expected AUTH with username and password, got %v", got)
	}
	if !contains(got, "SELECT 3") {
		t.Fatalf("expected SELECT 3, got %v", got)
	}
}

func TestRedisHandshakeAuthPasswordOnly(t *testing.T) {
	srv := startFakeRedis(t, fakeRedisOptions{password: "hunter2"})
	client := newTestRedisClient(t, srv.addr(), func(o *redisOptions) { o.password = "hunter2" })

	if err := client.ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if got := srv.recordedCommands(); !contains(got, "AUTH hunter2") {
		t.Fatalf("expected AUTH with password only, got %v", got)
	}
}

func TestRedisAuthFailureIsReported(t *testing.T) {
	srv := startFakeRedis(t, fakeRedisOptions{password: "right", errOnAuth: true})
	client := newTestRedisClient(t, srv.addr(), func(o *redisOptions) { o.password = "wrong" })

	err := client.ping()
	if err == nil {
		t.Fatal("expected an authentication error")
	}
	if !strings.Contains(err.Error(), "AUTH") {
		t.Fatalf("error should mention AUTH, got %v", err)
	}
}

func TestRedisDialFailure(t *testing.T) {
	client := newTestRedisClient(t, closedAddr(t), func(o *redisOptions) {
		o.dialTimeout = 200 * time.Millisecond
	})

	if err := client.ping(); err == nil {
		t.Fatal("expected a dial error")
	}
}

func TestRedisServerErrorKeepsConnection(t *testing.T) {
	srv := startFakeRedis(t)
	client := newTestRedisClient(t, srv.addr(), func(o *redisOptions) { o.maxConns = 1 })

	srv.failNext(1)
	if _, err := client.exists("any"); err == nil {
		t.Fatal("expected the injected server error")
	}

	// The connection is still in sync, so the next command must succeed on the
	// same connection instead of dialing a new one.
	if err := client.ping(); err != nil {
		t.Fatalf("ping after server error: %v", err)
	}
	if got := srv.connectionCount(); got != 1 {
		t.Fatalf("expected the connection to be reused, %d connections open", got)
	}
	if peak := srv.peakConnections(); peak > 1 {
		t.Fatalf("expected a single connection, peaked at %d", peak)
	}
}

func TestRedisProtocolErrorDiscardsConnection(t *testing.T) {
	srv := startFakeRedis(t)
	client := newTestRedisClient(t, srv.addr())

	srv.setGarbage(true)
	if err := client.ping(); err == nil {
		t.Fatal("expected a protocol error")
	}

	srv.setGarbage(false)
	if err := client.ping(); err != nil {
		t.Fatalf("ping after protocol error: %v", err)
	}
	if got := srv.connectionCount(); got != 1 {
		t.Fatalf("expected exactly one live connection after recovery, got %d", got)
	}
}

func TestRedisConnectionsAreReused(t *testing.T) {
	srv := startFakeRedis(t)
	client := newTestRedisClient(t, srv.addr(), func(o *redisOptions) { o.maxConns = 8 })

	for i := 0; i < 20; i++ {
		if _, err := client.exists("key"); err != nil {
			t.Fatalf("exists: %v", err)
		}
	}
	if peak := srv.peakConnections(); peak != 1 {
		t.Fatalf("sequential commands must reuse one connection, peaked at %d", peak)
	}
}

func TestRedisPoolIsBoundedAndConcurrent(t *testing.T) {
	srv := startFakeRedis(t)
	const maxConns = 3
	client := newTestRedisClient(t, srv.addr(), func(o *redisOptions) {
		o.maxConns = maxConns
		o.readTimeout = 5 * time.Second
	})

	release := srv.blockCommands()

	const goroutines = 24
	var wg sync.WaitGroup
	errs := make(chan error, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := client.exists("key"); err != nil {
				errs <- err
			}
		}()
	}

	// Give the pool time to saturate before releasing the server.
	time.Sleep(100 * time.Millisecond)
	release()
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent exists: %v", err)
	}
	if peak := srv.peakConnections(); peak > maxConns {
		t.Fatalf("pool exceeded maxConns: peak %d > %d", peak, maxConns)
	}
}

func TestRedisPoolExhausted(t *testing.T) {
	srv := startFakeRedis(t)
	client := newTestRedisClient(t, srv.addr(), func(o *redisOptions) {
		o.maxConns = 1
		o.readTimeout = 10 * time.Millisecond
		o.writeTimeout = 10 * time.Millisecond
	})

	conn, err := client.get()
	if err != nil {
		t.Fatalf("first get: %v", err)
	}
	defer client.put(conn, nil)

	if _, err := client.get(); !errors.Is(err, errPoolExhausted) {
		t.Fatalf("expected errPoolExhausted, got %v", err)
	}
}

func TestRedisCloseReleasesConnections(t *testing.T) {
	srv := startFakeRedis(t)
	client := newTestRedisClient(t, srv.addr())

	if err := client.ping(); err != nil {
		t.Fatalf("ping: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second close must be a no-op, got %v", err)
	}
	if err := client.ping(); !errors.Is(err, errClientClosed) {
		t.Fatalf("expected errClientClosed, got %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for srv.connectionCount() != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := srv.connectionCount(); got != 0 {
		t.Fatalf("expected all connections to be closed, %d still open", got)
	}
}

// TestRedisIntegrationTTL exercises the real Redis implementation when
// REDIS_ADDR is provided, for example through docker compose or testcontainers:
//
//	REDIS_ADDR=127.0.0.1:6379 go test -run Integration -v ./...
func TestRedisIntegrationTTL(t *testing.T) {
	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		t.Skip("REDIS_ADDR is not set, skipping Redis integration test")
	}

	opts := redisOptions{
		addr:         addr,
		username:     os.Getenv("REDIS_USERNAME"),
		password:     os.Getenv("REDIS_PASSWORD"),
		dialTimeout:  2 * time.Second,
		readTimeout:  time.Second,
		writeTimeout: time.Second,
		maxConns:     4,
	}
	if db := os.Getenv("REDIS_DB"); db != "" {
		var err error
		opts.db, err = strconv.Atoi(db)
		if err != nil {
			t.Fatalf("invalid REDIS_DB: %v", err)
		}
	}

	client := newRedisClient(opts)
	defer func() { _ = client.Close() }()

	key := ipGrantKey("traefik:http-knock:itest:", "itest", "203.0.113.7")
	if _, err := client.do("DEL", key); err != nil {
		t.Fatalf("del before knock: %v", err)
	}

	allowed, err := client.exists(key)
	if err != nil {
		t.Fatalf("exists before knock: %v", err)
	}
	if allowed {
		t.Fatal("key must not exist before the knock")
	}

	if err := client.setEx(key, "1", 3*time.Second); err != nil {
		t.Fatalf("setEx: %v", err)
	}

	allowed, err = client.exists(key)
	if err != nil {
		t.Fatalf("exists after knock: %v", err)
	}
	if !allowed {
		t.Fatal("key must exist after the knock")
	}

	// SET NX EX is used by the login attempt limiter; exercise it against the
	// real server as well as the fake one.
	nxKey := loginFailureKey("traefik:http-knock:itest:", "itest", "203.0.113.8")
	created, err := client.setNXEx(nxKey, "0", time.Minute)
	if err != nil {
		t.Fatalf("setNXEx: %v", err)
	}
	if !created {
		t.Fatal("setNXEx must create a missing key")
	}
	created, err = client.setNXEx(nxKey, "9", time.Minute)
	if err != nil {
		t.Fatalf("setNXEx second: %v", err)
	}
	if created {
		t.Fatal("setNXEx must not overwrite an existing key")
	}
	if err := client.del(nxKey); err != nil {
		t.Fatalf("del nx key: %v", err)
	}

	reply, err := client.do("TTL", key)
	if err != nil {
		t.Fatalf("ttl: %v", err)
	}
	ttl, err := reply.integer()
	if err != nil {
		t.Fatalf("ttl reply: %v", err)
	}
	if ttl <= 0 || ttl > 3 {
		t.Fatalf("expected a TTL between 1 and 3 seconds, got %d", ttl)
	}

	// Redis must expire the key on its own.
	deadline := time.Now().Add(5 * time.Second)
	for {
		allowed, err = client.exists(key)
		if err != nil {
			t.Fatalf("exists after expiry: %v", err)
		}
		if !allowed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("key did not expire within the expected window")
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// TestRedisConcurrentStress makes the race detector look for data races in the
// pool while many goroutines hammer it.
func TestRedisRetriesOnceOnStaleConnection(t *testing.T) {
	srv := startFakeRedis(t)
	client := newTestRedisClient(t, srv.addr())

	// Warm up one pooled connection.
	if err := client.ping(); err != nil {
		t.Fatalf("warm-up ping: %v", err)
	}

	// The next command is swallowed by a socket that died mid-flight, as after
	// a Redis restart. The client must discard it and retry on a fresh one.
	srv.dropNextCommands(1)
	if err := client.ping(); err != nil {
		t.Fatalf("ping must recover from a stale connection, got %v", err)
	}

	if got := srv.connectionCount(); got != 1 {
		t.Fatalf("expected a single live connection after the retry, got %d", got)
	}
	if got := srv.totalConnections(); got != 2 {
		t.Fatalf("expected exactly one reconnect, %d connections were accepted", got)
	}
	// The command was attempted twice: once on the dead socket, once on the
	// fresh one.
	pings := 0
	for _, cmd := range srv.recordedCommands() {
		if cmd == "PING" {
			pings++
		}
	}
	if pings != 3 {
		t.Fatalf("expected 3 PING commands (warm-up, dropped, retry), got %d", pings)
	}
}

func TestRedisDoesNotRetryDialFailures(t *testing.T) {
	client := newTestRedisClient(t, closedAddr(t), func(o *redisOptions) {
		o.dialTimeout = 100 * time.Millisecond
	})

	start := time.Now()
	if err := client.ping(); err == nil {
		t.Fatal("expected a dial error")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("a dial failure must not be retried, took %s", elapsed)
	}
}

func TestRedisConcurrentStress(t *testing.T) {
	srv := startFakeRedis(t)
	client := newTestRedisClient(t, srv.addr(), func(o *redisOptions) { o.maxConns = 4 })

	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := ipGrantKey(DefaultKeyPrefix, "test", "10.0.0."+strconv.Itoa(i))
			for j := 0; j < 25; j++ {
				if err := client.setEx(key, "1", time.Minute); err != nil {
					t.Errorf("setEx: %v", err)
					return
				}
				if _, err := client.exists(key); err != nil {
					t.Errorf("exists: %v", err)
					return
				}
			}
		}(i)
	}
	wg.Wait()
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func decodeRESP(t *testing.T, raw string) (respValue, error) {
	t.Helper()
	return readRESP(bufio.NewReader(strings.NewReader(raw)), 0)
}

func TestRESPDecoding(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		check   func(*testing.T, respValue)
		wantErr string
	}{
		{
			name: "simple string",
			raw:  "+OK\r\n",
			check: func(t *testing.T, v respValue) {
				if v.kind != respSimpleString || v.str != "OK" || !v.ok() {
					t.Fatalf("unexpected value %+v", v)
				}
			},
		},
		{
			name: "error reply",
			raw:  "-ERR unknown command\r\n",
			check: func(t *testing.T, v respValue) {
				_ = v
				t.Fatal("a server error must not decode into a value")
			},
			wantErr: "ERR unknown command",
		},
		{
			name: "integer",
			raw:  ":42\r\n",
			check: func(t *testing.T, v respValue) {
				n, err := v.integer()
				if err != nil || n != 42 {
					t.Fatalf("integer() = %d, %v", n, err)
				}
			},
		},
		{
			name: "bulk string",
			raw:  "$5\r\nhello\r\n",
			check: func(t *testing.T, v respValue) {
				if v.kind != respBulkString || v.str != "hello" || v.isNil {
					t.Fatalf("unexpected value %+v", v)
				}
			},
		},
		{
			name: "empty bulk string",
			raw:  "$0\r\n\r\n",
			check: func(t *testing.T, v respValue) {
				if v.kind != respBulkString || v.str != "" || v.isNil {
					t.Fatalf("unexpected value %+v", v)
				}
			},
		},
		{
			name: "nil bulk string",
			raw:  "$-1\r\n",
			check: func(t *testing.T, v respValue) {
				if v.kind != respBulkString || !v.isNil {
					t.Fatalf("unexpected value %+v", v)
				}
			},
		},
		{
			name: "nil array",
			raw:  "*-1\r\n",
			check: func(t *testing.T, v respValue) {
				if v.kind != respArray || !v.isNil {
					t.Fatalf("unexpected value %+v", v)
				}
			},
		},
		{
			name: "empty array",
			raw:  "*0\r\n",
			check: func(t *testing.T, v respValue) {
				if v.kind != respArray || len(v.arr) != 0 {
					t.Fatalf("unexpected value %+v", v)
				}
			},
		},
		{
			name: "mixed array",
			raw:  "*3\r\n$3\r\nfoo\r\n:7\r\n+bar\r\n",
			check: func(t *testing.T, v respValue) {
				if v.kind != respArray || len(v.arr) != 3 {
					t.Fatalf("unexpected array %+v", v)
				}
				if v.arr[0].str != "foo" || v.arr[1].num != 7 || v.arr[2].str != "bar" {
					t.Fatalf("unexpected array contents %+v", v.arr)
				}
			},
		},
		{
			name: "nested array",
			raw:  "*1\r\n*1\r\n+OK\r\n",
			check: func(t *testing.T, v respValue) {
				if len(v.arr) != 1 || len(v.arr[0].arr) != 1 || v.arr[0].arr[0].str != "OK" {
					t.Fatalf("unexpected nesting %+v", v)
				}
			},
		},
		{
			name: "binary safe bulk string",
			raw:  "$4\r\na\r\nb\r\n",
			check: func(t *testing.T, v respValue) {
				if v.str != "a\r\nb" {
					t.Fatalf("bulk string = %q, want %q", v.str, "a\r\nb")
				}
			},
		},
		{name: "unknown type byte", raw: "!oops\r\n", wantErr: "unexpected reply byte"},
		{name: "truncated simple string", raw: "+OK", wantErr: "EOF"},
		{name: "bad integer", raw: ":abc\r\n", wantErr: "invalid integer reply"},
		{name: "bad bulk length", raw: "$abc\r\n", wantErr: "invalid bulk length"},
		{name: "huge bulk length", raw: "$999999999999\r\n", wantErr: "exceeds limit"},
		{name: "bulk length just above the limit", raw: "$" + strconv.Itoa(maxBulkLength+1) + "\r\n", wantErr: "exceeds limit"},
		{name: "bad array length", raw: "*abc\r\n", wantErr: "invalid array length"},
		{name: "bulk without CRLF terminator", raw: "$2\r\nfoo\r\n", wantErr: "not terminated by CRLF"},
		{name: "line without carriage return", raw: "+OK\n", wantErr: "not terminated by CRLF"},
		{name: "oversized reply line", raw: "+" + strings.Repeat("a", maxLineLength) + "\r\n", wantErr: "exceeds the maximum length"},
		{name: "reply nesting too deep", raw: strings.Repeat("*1\r\n", 12) + "+OK\r\n", wantErr: "nesting too deep"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, err := decodeRESP(t, tt.raw)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q, got value %+v", tt.wantErr, value)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			tt.check(t, value)
		})
	}
}

func TestRESPErrorTypes(t *testing.T) {
	_, err := decodeRESP(t, "-WRONGPASS bad password\r\n")
	if err == nil {
		t.Fatal("expected an error")
	}
	serverErr, ok := err.(redisError)
	if !ok {
		t.Fatalf("error is %T, want redisError so it can be classified without errors.As", err)
	}
	if serverErr.Error() != "redis: WRONGPASS bad password" {
		t.Fatalf("unexpected message %q", serverErr.Error())
	}
	if !isServerError(err) {
		t.Fatal("isServerError must recognize a Redis error reply")
	}
	if isServerError(io.EOF) {
		t.Fatal("isServerError must not treat transport errors as server errors")
	}
}

func TestRESPWriterEncoding(t *testing.T) {
	var buf bytes.Buffer
	conn := &redisConn{nc: nil, rw: bufio.NewReadWriter(bufio.NewReader(&buf), bufio.NewWriter(&buf))}

	if err := conn.writeCommand("SET", "key", "1", "EX", "7200"); err != nil {
		t.Fatalf("writeCommand: %v", err)
	}

	want := "*5\r\n$3\r\nSET\r\n$3\r\nkey\r\n$1\r\n1\r\n$2\r\nEX\r\n$4\r\n7200\r\n"
	if got := buf.String(); got != want {
		t.Fatalf("encoded command = %q, want %q", got, want)
	}
}

func TestRedisDescribeKind(t *testing.T) {
	tests := []struct {
		name string
		in   respValue
		want string
	}{
		{name: "simple string", in: respValue{kind: respSimpleString, str: "OK"}, want: "OK"},
		{name: "error", in: respValue{kind: respError, str: "boom"}, want: "error: boom"},
		{name: "integer", in: respValue{kind: respInteger, num: -2}, want: "-2"},
		{name: "bulk", in: respValue{kind: respBulkString, str: "x"}, want: "x"},
		{name: "nil bulk", in: respValue{kind: respBulkString, isNil: true}, want: "nil bulk string"},
		{name: "array", in: respValue{kind: respArray}, want: "array"},
		{name: "unknown", in: respValue{}, want: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := describeKind(tt.in); got != tt.want {
				t.Fatalf("describeKind() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRedisGetIncrExpireAndDel(t *testing.T) {
	srv := startFakeRedis(t)
	client := newTestRedisClient(t, srv.addr())

	key := "test:counter"
	if _, ok, err := client.getValue(key); err != nil || ok {
		t.Fatalf("getValue missing key = %v, %v; want false, nil", ok, err)
	}

	n, err := client.incr(key)
	if err != nil {
		t.Fatalf("incr: %v", err)
	}
	if n != 1 {
		t.Fatalf("first incr = %d, want 1", n)
	}
	n, err = client.incr(key)
	if err != nil {
		t.Fatalf("second incr: %v", err)
	}
	if n != 2 {
		t.Fatalf("second incr = %d, want 2", n)
	}
	if value, ok, err := client.getValue(key); err != nil || !ok || value != "2" {
		t.Fatalf("getValue = %q, %v, %v; want 2, true, nil", value, ok, err)
	}

	if err := client.expire(key, time.Minute); err != nil {
		t.Fatalf("expire: %v", err)
	}
	if err := client.del(key); err != nil {
		t.Fatalf("del: %v", err)
	}
	if _, ok, err := client.getValue(key); err != nil || ok {
		t.Fatalf("getValue after del = %v, %v; want false, nil", ok, err)
	}
}

func TestRedisSetExStoresArbitraryValue(t *testing.T) {
	srv := startFakeRedis(t)
	client := newTestRedisClient(t, srv.addr())

	key := ipGrantKey(DefaultKeyPrefix, "test", "10.0.0.1")
	if err := client.setEx(key, "alice|fingerprint", time.Hour); err != nil {
		t.Fatalf("setEx: %v", err)
	}
	value, ok, err := client.getValue(key)
	if err != nil || !ok {
		t.Fatalf("getValue = %v, %v; want true, nil", ok, err)
	}
	if value != "alice|fingerprint" {
		t.Fatalf("value = %q, want alice|fingerprint", value)
	}
}
