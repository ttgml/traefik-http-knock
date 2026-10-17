package traefik_http_knock

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"
)

// This file implements the small subset of Redis used by the plugin with the
// Go standard library only. Traefik's plugin loader (Yaegi for local plugins,
// vendoring rules for catalog plugins) makes every third-party dependency a
// liability. The plugin needs AUTH, SELECT, PING, EXISTS, GET, SET ... EX,
// INCR, EXPIRE and DEL.
//
// Supported replies: simple strings, errors, integers, bulk strings and arrays.
// Anything else is reported as a protocol error and the connection is dropped.

const (
	respSimpleString = '+'
	respError        = '-'
	respInteger      = ':'
	respBulkString   = '$'
	respArray        = '*'

	// respMaxDepth bounds recursive array parsing so that a hostile or broken
	// peer cannot exhaust the stack.
	respMaxDepth = 8
)

var (
	// errClientClosed is returned once the client has been closed.
	errClientClosed = errors.New("redis: client is closed")
	// errPoolExhausted is returned when no connection is available in time.
	errPoolExhausted = errors.New("redis: connection pool exhausted")
)

// redisError is a reply of type "-ERR ...". The connection stays usable, so it
// must not be treated as a connection failure.
type redisError string

func (e redisError) Error() string { return "redis: " + string(e) }

// respValue is a decoded RESP reply.
type respValue struct {
	kind  byte
	str   string
	num   int64
	arr   []respValue
	isNil bool
}

func (v respValue) ok() bool {
	return v.kind == respSimpleString || (v.kind == respBulkString && v.str == "OK")
}

func (v respValue) integer() (int64, error) {
	if v.kind != respInteger {
		return 0, fmt.Errorf("redis: expected integer reply, got %q", describeKind(v))
	}
	return v.num, nil
}

func describeKind(v respValue) string {
	switch v.kind {
	case respSimpleString:
		return v.str
	case respError:
		return "error: " + v.str
	case respInteger:
		return strconv.FormatInt(v.num, 10)
	case respBulkString:
		if v.isNil {
			return "nil bulk string"
		}
		return v.str
	case respArray:
		return "array"
	default:
		return "unknown"
	}
}

// redisConn is a single pooled connection. Connections are not safe for
// concurrent use; the pool hands each one to a single caller at a time.
type redisConn struct {
	nc net.Conn
	rw *bufio.ReadWriter
}

func (c *redisConn) close() {
	if c.nc != nil {
		_ = c.nc.Close()
	}
}

// writeCommand encodes a command as a RESP array of bulk strings.
func (c *redisConn) writeCommand(args ...string) error {
	w := c.rw.Writer
	if _, err := w.WriteString("*" + strconv.Itoa(len(args)) + "\r\n"); err != nil {
		return err
	}
	for _, arg := range args {
		if _, err := w.WriteString("$" + strconv.Itoa(len(arg)) + "\r\n"); err != nil {
			return err
		}
		if _, err := w.WriteString(arg); err != nil {
			return err
		}
		if _, err := w.WriteString("\r\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

// readReply decodes one RESP reply.
func (c *redisConn) readReply() (respValue, error) {
	return readRESP(c.rw.Reader, 0)
}

func readRESP(r *bufio.Reader, depth int) (respValue, error) {
	if depth > respMaxDepth {
		return respValue{}, errors.New("redis: reply nesting too deep")
	}

	prefix, err := r.ReadByte()
	if err != nil {
		return respValue{}, err
	}

	switch prefix {
	case respSimpleString:
		line, err := readLine(r)
		if err != nil {
			return respValue{}, err
		}
		return respValue{kind: respSimpleString, str: line}, nil

	case respError:
		line, err := readLine(r)
		if err != nil {
			return respValue{}, err
		}
		return respValue{}, redisError(line)

	case respInteger:
		line, err := readLine(r)
		if err != nil {
			return respValue{}, err
		}
		n, err := strconv.ParseInt(line, 10, 64)
		if err != nil {
			return respValue{}, fmt.Errorf("redis: invalid integer reply %q", line)
		}
		return respValue{kind: respInteger, num: n}, nil

	case respBulkString:
		line, err := readLine(r)
		if err != nil {
			return respValue{}, err
		}
		n, err := strconv.Atoi(line)
		if err != nil {
			return respValue{}, fmt.Errorf("redis: invalid bulk length %q", line)
		}
		if n < 0 {
			return respValue{kind: respBulkString, isNil: true}, nil
		}
		if n > maxBulkLength {
			return respValue{}, fmt.Errorf("redis: bulk length %d exceeds limit", n)
		}
		buf := make([]byte, n+2)
		if _, err := ioReadFull(r, buf); err != nil {
			return respValue{}, err
		}
		if buf[n] != '\r' || buf[n+1] != '\n' {
			return respValue{}, errors.New("redis: bulk string not terminated by CRLF")
		}
		return respValue{kind: respBulkString, str: string(buf[:n])}, nil

	case respArray:
		line, err := readLine(r)
		if err != nil {
			return respValue{}, err
		}
		n, err := strconv.Atoi(line)
		if err != nil {
			return respValue{}, fmt.Errorf("redis: invalid array length %q", line)
		}
		if n < 0 {
			return respValue{kind: respArray, isNil: true}, nil
		}
		if n > maxArrayLength {
			return respValue{}, fmt.Errorf("redis: array length %d exceeds limit", n)
		}
		arr := make([]respValue, 0, n)
		for i := 0; i < n; i++ {
			item, err := readRESP(r, depth+1)
			if err != nil {
				return respValue{}, err
			}
			arr = append(arr, item)
		}
		return respValue{kind: respArray, arr: arr}, nil

	default:
		return respValue{}, fmt.Errorf("redis: unexpected reply byte %q", prefix)
	}
}

// Bounds that keep a misbehaving peer from allocating arbitrary memory.
const (
	// maxBulkLength bounds a single bulk string. The commands this plugin uses
	// only return short strings (session values, counters, errors), so this is
	// far above any legitimate reply while stopping a hostile or broken peer
	// from making the plugin allocate hundreds of megabytes.
	maxBulkLength = 1 << 20
	// maxLineLength bounds a single reply header line (simple strings, errors,
	// integers and bulk/array lengths). Redis error messages are a few hundred
	// bytes at most, so this is generous.
	maxLineLength  = 64 * 1024
	maxArrayLength = 1 << 20
)

// readLine reads one CRLF-terminated RESP line. Its length is bounded so that a
// peer that never sends a newline cannot grow the read buffer without limit.
func readLine(r *bufio.Reader) (string, error) {
	var line []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(line)+len(chunk) > maxLineLength {
			return "", errors.New("redis: reply line exceeds the maximum length")
		}
		line = append(line, chunk...)

		if err == bufio.ErrBufferFull {
			// The line is longer than the reader's buffer; keep reading until
			// the newline or the bound above is reached.
			continue
		}
		if err != nil {
			return "", err
		}
		break
	}
	if len(line) < 2 || line[len(line)-2] != '\r' {
		return "", errors.New("redis: line not terminated by CRLF")
	}
	return string(line[:len(line)-2]), nil
}

// ioReadFull is a tiny wrapper so that the RESP reader stays easy to reason
// about (and easy to keep Yaegi-friendly).
func ioReadFull(r *bufio.Reader, buf []byte) (int, error) {
	return io.ReadFull(r, buf)
}

// redisOptions configures a redisClient.
type redisOptions struct {
	addr         string
	username     string
	password     string
	db           int
	dialTimeout  time.Duration
	readTimeout  time.Duration
	writeTimeout time.Duration
	maxConns     int
}

// redisClient is a small, bounded connection pool.
//
// A connection is created lazily up to maxConns. When the pool is full and no
// connection is idle, callers wait for one instead of stampeding Redis with
// new connections. Broken connections are closed and their slot released;
// healthy connections go back to the pool. There is no background goroutine
// and no reaper: idle connections are reclaimed by the server or reset by the
// Redis idle timeout configured in the deployment.
type redisClient struct {
	opts redisOptions

	mu     sync.Mutex
	total  int
	closed bool

	idle chan *redisConn
	done chan struct{}
}

func newRedisClient(opts redisOptions) *redisClient {
	if opts.maxConns < 1 {
		opts.maxConns = 1
	}
	return &redisClient{
		opts: opts,
		idle: make(chan *redisConn, opts.maxConns),
		done: make(chan struct{}),
	}
}

// exists implements EXISTS key. The second return value is the allowlist
// decision.
func (c *redisClient) exists(key string) (bool, error) {
	reply, err := c.doIdempotent("EXISTS", key)
	if err != nil {
		return false, err
	}
	n, err := reply.integer()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// setEx implements SET key value EX seconds, so Redis owns expiry.
func (c *redisClient) setEx(key, value string, ttl time.Duration) error {
	reply, err := c.doIdempotent("SET", key, value, "EX", strconv.FormatInt(redisTTLSeconds(ttl), 10))
	if err != nil {
		return err
	}
	if reply.kind == respSimpleString && reply.str == "OK" {
		return nil
	}
	return fmt.Errorf("redis: unexpected SET reply %q", describeKind(reply))
}

// setNXEx implements SET key value EX seconds NX. The boolean is false when the
// key already exists and nothing was written. SET NX is idempotent, so the
// first-attempt retry in doIdempotent is safe.
func (c *redisClient) setNXEx(key, value string, ttl time.Duration) (bool, error) {
	reply, err := c.doIdempotent("SET", key, value, "EX", strconv.FormatInt(redisTTLSeconds(ttl), 10), "NX")
	if err != nil {
		return false, err
	}
	if reply.kind == respBulkString && reply.isNil {
		return false, nil
	}
	if reply.kind == respSimpleString && reply.str == "OK" {
		return true, nil
	}
	return false, fmt.Errorf("redis: unexpected SET NX reply %q", describeKind(reply))
}

// getValue implements GET key. The boolean is false for a nil reply (key absent).
func (c *redisClient) getValue(key string) (string, bool, error) {
	reply, err := c.doIdempotent("GET", key)
	if err != nil {
		return "", false, err
	}
	if reply.kind == respBulkString && reply.isNil {
		return "", false, nil
	}
	if reply.kind == respBulkString || reply.kind == respSimpleString {
		return reply.str, true, nil
	}
	return "", false, fmt.Errorf("redis: unexpected GET reply %q", describeKind(reply))
}

// del implements DEL key. It is idempotent: deleting a missing key is not an
// error.
func (c *redisClient) del(key string) error {
	_, err := c.doIdempotent("DEL", key)
	return err
}

// incr implements INCR key. Unlike EXISTS/SET/PING it is not idempotent, so it
// must not be retried automatically: a lost reply would otherwise count the
// same login failure twice.
func (c *redisClient) incr(key string) (int64, error) {
	reply, err := c.do("INCR", key)
	if err != nil {
		return 0, err
	}
	return reply.integer()
}

// expire implements EXPIRE key seconds.
func (c *redisClient) expire(key string, ttl time.Duration) error {
	reply, err := c.doIdempotent("EXPIRE", key, strconv.FormatInt(redisTTLSeconds(ttl), 10))
	if err != nil {
		return err
	}
	if _, err := reply.integer(); err != nil {
		return err
	}
	return nil
}

// ping implements PING. It is used by tests and diagnostics, not by the
// request path.
func (c *redisClient) ping() error {
	reply, err := c.doIdempotent("PING")
	if err != nil {
		return err
	}
	if reply.kind == respSimpleString && reply.str == "PONG" {
		return nil
	}
	return fmt.Errorf("redis: unexpected PING reply %q", describeKind(reply))
}

// doIdempotent runs a command that is safe to repeat (EXISTS, SET, PING) and
// retries once on a transport failure.
//
// This hides the most common Redis outage mode: a pooled socket that a Redis
// restart, a load balancer or the Redis idle timeout silently invalidated. The
// first attempt discovers the dead socket, the retry uses a fresh connection.
//
// Failures that happened before a socket was obtained (dial failure, pool
// exhaustion, closed client) are not retried, so a genuinely unreachable Redis
// still fails after a single dial timeout.
//
// NOTE: the plugin deliberately avoids errors.Is/errors.As. Yaegi (the
// interpreter used for local plugins) panics on those stdlib helpers, so error
// classification uses plain type assertions on unwrapped errors instead.
func (c *redisClient) doIdempotent(args ...string) (respValue, error) {
	conn, err := c.get()
	if err != nil {
		return respValue{}, err
	}

	reply, err := c.execute(conn, args...)
	if err == nil {
		return reply, nil
	}
	if isServerError(err) {
		// Redis answered ("-ERR ..."): repeating the command is pointless and
		// the connection is still in sync.
		return respValue{}, err
	}
	return c.do(args...)
}

// isServerError reports whether err is an error reply from Redis. The error
// returned by the RESP reader is never wrapped, so a direct type assertion is
// correct here.
func isServerError(err error) bool {
	_, ok := err.(redisError)
	return ok
}

// do runs a command on a pooled connection exactly once.
func (c *redisClient) do(args ...string) (respValue, error) {
	conn, err := c.get()
	if err != nil {
		return respValue{}, err
	}
	return c.execute(conn, args...)
}

// execute writes one command on conn and reads its reply. Transport errors
// discard the connection; server errors and successful replies return it to the
// pool.
func (c *redisClient) execute(conn *redisConn, args ...string) (respValue, error) {
	if err := conn.nc.SetWriteDeadline(time.Now().Add(c.opts.writeTimeout)); err != nil {
		c.put(conn, err)
		return respValue{}, err
	}
	if err := conn.writeCommand(args...); err != nil {
		c.put(conn, err)
		return respValue{}, err
	}

	if err := conn.nc.SetReadDeadline(time.Now().Add(c.opts.readTimeout)); err != nil {
		c.put(conn, err)
		return respValue{}, err
	}
	reply, err := conn.readReply()
	if err != nil {
		if isServerError(err) {
			// The command failed but the connection is still in sync.
			c.put(conn, nil)
			return respValue{}, err
		}
		c.put(conn, err)
		return respValue{}, err
	}

	c.put(conn, nil)
	return reply, nil
}

// get returns an idle connection, dials one when the pool has room, or waits
// for one to be returned.
func (c *redisClient) get() (*redisConn, error) {
	select {
	case conn := <-c.idle:
		return conn, nil
	default:
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, errClientClosed
	}
	if c.total < c.opts.maxConns {
		c.total++
		c.mu.Unlock()
		conn, err := c.dial()
		if err != nil {
			c.releaseSlot()
			return nil, err
		}
		return conn, nil
	}
	c.mu.Unlock()

	// The pool is saturated. Wait for a connection to come back rather than
	// opening unbounded connections.
	wait := c.opts.readTimeout + c.opts.writeTimeout
	if wait <= 0 {
		wait = time.Second
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()

	select {
	case conn := <-c.idle:
		return conn, nil
	case <-c.done:
		return nil, errClientClosed
	case <-timer.C:
		return nil, errPoolExhausted
	}
}

// put returns a connection to the pool. A non-nil err means the connection must
// be discarded.
//
// The closed check and the channel send happen under the same mutex that Close
// holds while draining, so a connection can never be parked in the idle channel
// after Close returned.
func (c *redisClient) put(conn *redisConn, err error) {
	if conn == nil {
		return
	}
	if err != nil {
		conn.close()
		c.releaseSlot()
		return
	}

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		conn.close()
		c.releaseSlot()
		return
	}
	select {
	case c.idle <- conn:
		c.mu.Unlock()
	default:
		// Should not happen: at most maxConns connections exist and each of
		// them is either in use or in the channel.
		c.mu.Unlock()
		conn.close()
		c.releaseSlot()
	}
}

func (c *redisClient) releaseSlot() {
	c.mu.Lock()
	c.total--
	c.mu.Unlock()
}

// dial opens a new connection and performs the AUTH/SELECT handshake so that
// pooled connections are ready to use.
func (c *redisClient) dial() (*redisConn, error) {
	nc, err := net.DialTimeout("tcp", c.opts.addr, c.opts.dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("redis: dial %s: %w", c.opts.addr, err)
	}

	conn := &redisConn{
		nc: nc,
		rw: bufio.NewReadWriter(bufio.NewReaderSize(nc, 4096), bufio.NewWriterSize(nc, 4096)),
	}

	// The handshake gets a single, bounded deadline: a server that accepts the
	// connection but never answers must not pin the caller.
	deadline := time.Now().Add(c.opts.dialTimeout + c.opts.readTimeout + c.opts.writeTimeout)
	if err := nc.SetDeadline(deadline); err != nil {
		conn.close()
		return nil, err
	}
	if err := c.handshake(conn); err != nil {
		conn.close()
		return nil, err
	}
	if err := nc.SetDeadline(time.Time{}); err != nil {
		conn.close()
		return nil, err
	}
	return conn, nil
}

func (c *redisClient) handshake(conn *redisConn) error {
	if c.opts.password != "" || c.opts.username != "" {
		args := []string{"AUTH"}
		if c.opts.username != "" {
			// Redis >= 6 ACL form: AUTH <username> <password>.
			args = append(args, c.opts.username)
		}
		args = append(args, c.opts.password)

		reply, err := c.handshakeCommand(conn, args...)
		if err != nil {
			return fmt.Errorf("redis: AUTH failed: %w", err)
		}
		if !reply.ok() {
			return fmt.Errorf("redis: AUTH failed: unexpected reply %q", describeKind(reply))
		}
	}

	if c.opts.db != 0 {
		reply, err := c.handshakeCommand(conn, "SELECT", strconv.Itoa(c.opts.db))
		if err != nil {
			return fmt.Errorf("redis: SELECT %d failed: %w", c.opts.db, err)
		}
		if !reply.ok() {
			return fmt.Errorf("redis: SELECT %d failed: unexpected reply %q", c.opts.db, describeKind(reply))
		}
	}
	return nil
}

func (c *redisClient) handshakeCommand(conn *redisConn, args ...string) (respValue, error) {
	if err := conn.writeCommand(args...); err != nil {
		return respValue{}, err
	}
	return conn.readReply()
}

// Close closes the pool and every idle connection. In-flight callers see their
// connection closed by the server or by their own deadline; they must not
// return it to a closed pool, which put() handles.
func (c *redisClient) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	close(c.done)

	// Drain while holding the mutex: put() cannot park a connection once it
	// observes closed, because it takes the same mutex.
	for {
		select {
		case conn := <-c.idle:
			c.total--
			conn.close()
		default:
			c.mu.Unlock()
			return nil
		}
	}
}
