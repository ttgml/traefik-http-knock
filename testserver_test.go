package traefik_http_knock

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeRedisServer is an in-process RESP server used by the unit tests. It
// implements just enough of Redis (AUTH, SELECT, PING, EXISTS, SET, GET, DEL,
// TTL) to exercise the plugin without Docker.
//
// It also records every command it received so tests can assert on protocol
// details such as the exact SET ... EX arguments.
type fakeRedisServer struct {
	t  *testing.T
	ln net.Listener

	mu sync.Mutex

	values map[string]time.Time // key -> expiry (zero value means no expiry)

	password   string
	username   string
	requireDB  int
	errOnAuth  bool
	failNextNo int // number of upcoming commands answered with -ERR

	commands []string

	connCount  int
	totalConns int
	maxConns   int
	active     map[net.Conn]struct{}

	block     chan struct{} // when non-nil, commands wait for it to close
	dropAfter int           // close the connection after N commands (0 = never)
	dropNext  int           // close the connection before replying to the next N commands
	garbage   bool          // answer with an invalid RESP frame
	closed    bool
}

type fakeRedisOptions struct {
	password  string
	username  string
	requireDB int
	errOnAuth bool
}

func startFakeRedis(t *testing.T, opts ...fakeRedisOptions) *fakeRedisServer {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot start fake redis: %v", err)
	}

	srv := &fakeRedisServer{
		t:      t,
		ln:     ln,
		values: make(map[string]time.Time),
		active: make(map[net.Conn]struct{}),
	}
	if len(opts) > 0 {
		srv.password = opts[0].password
		srv.username = opts[0].username
		srv.requireDB = opts[0].requireDB
		srv.errOnAuth = opts[0].errOnAuth
	}

	go srv.serve()
	t.Cleanup(srv.Close)
	return srv
}

func (s *fakeRedisServer) addr() string { return s.ln.Addr().String() }

func (s *fakeRedisServer) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		s.connCount++
		s.totalConns++
		if s.connCount > s.maxConns {
			s.maxConns = s.connCount
		}
		s.active[conn] = struct{}{}
		s.mu.Unlock()

		go s.handle(conn)
	}
}

func (s *fakeRedisServer) handle(conn net.Conn) {
	defer func() {
		_ = conn.Close()
		s.mu.Lock()
		s.connCount--
		delete(s.active, conn)
		s.mu.Unlock()
	}()

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	authed := s.password == "" && s.username == ""
	selectedDB := 0
	handled := 0

	for {
		args, err := readCommand(r)
		if err != nil {
			return
		}
		if len(args) == 0 {
			continue
		}
		handled++

		s.mu.Lock()
		s.commands = append(s.commands, strings.Join(args, " "))
		block := s.block
		garbage := s.garbage
		dropAfter := s.dropAfter
		dropNext := s.dropNext
		if s.dropNext > 0 {
			s.dropNext--
		}
		failNext := s.failNextNo
		if failNext > 0 {
			s.failNextNo--
		}
		s.mu.Unlock()

		if dropAfter > 0 && handled > dropAfter {
			return
		}
		if dropNext > 0 {
			// Simulate a socket that Redis (or a proxy) invalidated: the
			// command is received but the connection dies before the reply.
			return
		}

		if block != nil {
			<-block
		}
		if garbage {
			_, _ = w.WriteString("!!! not resp\r\n")
			_ = w.Flush()
			return
		}

		name := strings.ToUpper(args[0])
		if failNext > 0 {
			_ = writeError(w, "ERR injected failure")
			continue
		}

		switch name {
		case "AUTH":
			if s.errOnAuth {
				_ = writeError(w, "WRONGPASS invalid username-password pair")
				continue
			}
			user, pass := "", ""
			switch len(args) {
			case 2:
				pass = args[1]
			case 3:
				user, pass = args[1], args[2]
			default:
				_ = writeError(w, "ERR wrong number of arguments for 'auth' command")
				continue
			}
			if s.password != "" && (pass != s.password || (s.username != "" && user != s.username)) {
				_ = writeError(w, "WRONGPASS invalid username-password pair")
				continue
			}
			authed = true
			_ = writeSimple(w, "OK")

		case "SELECT":
			if !authed {
				_ = writeError(w, "NOAUTH Authentication required.")
				continue
			}
			db, _ := strconv.Atoi(args[1])
			selectedDB = db
			_ = writeSimple(w, "OK")

		case "PING":
			_ = writeSimple(w, "PONG")

		case "EXISTS":
			if !authed {
				_ = writeError(w, "NOAUTH Authentication required.")
				continue
			}
			if selectedDB != s.requireDB {
				_ = writeError(w, "ERR wrong database selected")
				continue
			}
			n := 0
			for _, key := range args[1:] {
				if s.get(key) {
					n++
				}
			}
			_ = writeInteger(w, int64(n))

		case "SET":
			if !authed {
				_ = writeError(w, "NOAUTH Authentication required.")
				continue
			}
			if len(args) < 3 {
				_ = writeError(w, "ERR wrong number of arguments for 'set' command")
				continue
			}
			expiry := time.Time{}
			for i := 3; i < len(args); i++ {
				switch strings.ToUpper(args[i]) {
				case "EX":
					if i+1 >= len(args) {
						_ = writeError(w, "ERR syntax error")
						continue
					}
					seconds, _ := strconv.Atoi(args[i+1])
					expiry = time.Now().Add(time.Duration(seconds) * time.Second)
					i++
				case "PX":
					if i+1 >= len(args) {
						_ = writeError(w, "ERR syntax error")
						continue
					}
					ms, _ := strconv.Atoi(args[i+1])
					expiry = time.Now().Add(time.Duration(ms) * time.Millisecond)
					i++
				default:
					_ = writeError(w, "ERR syntax error")
					continue
				}
			}
			s.set(args[1], expiry)
			_ = writeSimple(w, "OK")

		case "GET":
			if s.get(args[1]) {
				_ = writeBulk(w, "1")
			} else {
				_ = writeNil(w)
			}

		case "DEL":
			n := 0
			for _, key := range args[1:] {
				if s.del(key) {
					n++
				}
			}
			_ = writeInteger(w, int64(n))

		case "TTL":
			s.mu.Lock()
			expiry, ok := s.values[args[1]]
			if ok && !expiry.IsZero() && time.Now().After(expiry) {
				delete(s.values, args[1])
				ok = false
			}
			s.mu.Unlock()
			switch {
			case !ok:
				_ = writeInteger(w, -2)
			case expiry.IsZero():
				_ = writeInteger(w, -1)
			default:
				_ = writeInteger(w, int64(time.Until(expiry).Seconds()))
			}

		default:
			_ = writeError(w, fmt.Sprintf("ERR unknown command '%s'", args[0]))
		}
	}
}

func (s *fakeRedisServer) get(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	expiry, ok := s.values[key]
	if !ok {
		return false
	}
	if !expiry.IsZero() && time.Now().After(expiry) {
		delete(s.values, key)
		return false
	}
	return true
}

func (s *fakeRedisServer) set(key string, expiry time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values[key] = expiry
}

func (s *fakeRedisServer) del(key string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.values[key]; !ok {
		return false
	}
	delete(s.values, key)
	return true
}

// expireAll simulates Redis TTL expiry without waiting for wall-clock time.
func (s *fakeRedisServer) expireAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.values = make(map[string]time.Time)
}

func (s *fakeRedisServer) recordedCommands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.commands))
	copy(out, s.commands)
	return out
}

func (s *fakeRedisServer) connectionCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connCount
}

// peakConnections reports the highest number of simultaneously open
// connections (used to check that the pool is bounded).
func (s *fakeRedisServer) peakConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.maxConns
}

// totalConnections reports how many connections were accepted since start-up
// (used to check reconnects).
func (s *fakeRedisServer) totalConnections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.totalConns
}

func (s *fakeRedisServer) failNext(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failNextNo = n
}

func (s *fakeRedisServer) setGarbage(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.garbage = v
}

// dropNextCommands makes the server close the connection (without replying)
// before handling the next n commands, which is how a stale pooled connection
// behaves after a Redis restart.
func (s *fakeRedisServer) dropNextCommands(n int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dropNext = n
}

func (s *fakeRedisServer) blockCommands() func() {
	ch := make(chan struct{})
	s.mu.Lock()
	s.block = ch
	s.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			s.block = nil
			s.mu.Unlock()
			close(ch)
		})
	}
}

func (s *fakeRedisServer) Close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	conns := make([]net.Conn, 0, len(s.active))
	for conn := range s.active {
		conns = append(conns, conn)
	}
	s.mu.Unlock()

	_ = s.ln.Close()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

// closedAddr returns an address that is guaranteed to refuse connections.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot allocate address: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// --- minimal RESP encoding helpers -------------------------------------------

func readCommand(r *bufio.Reader) ([]string, error) {
	prefix, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if prefix != '*' {
		return nil, fmt.Errorf("fake redis: expected array, got %q", prefix)
	}
	line, err := readLine(r)
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(line)
	if err != nil {
		return nil, fmt.Errorf("fake redis: bad array length %q", line)
	}
	args := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if prefix, err = r.ReadByte(); err != nil {
			return nil, err
		}
		if prefix != '$' {
			return nil, fmt.Errorf("fake redis: expected bulk string, got %q", prefix)
		}
		line, err = readLine(r)
		if err != nil {
			return nil, err
		}
		size, err := strconv.Atoi(line)
		if err != nil {
			return nil, fmt.Errorf("fake redis: bad bulk length %q", line)
		}
		buf := make([]byte, size+2)
		if _, err := io.ReadFull(r, buf); err != nil {
			return nil, err
		}
		args = append(args, string(buf[:size]))
	}
	return args, nil
}

// The helpers flush immediately: tests inject errors and then continue, and a
// buffered reply would only surface when the connection closes.

func writeSimple(w *bufio.Writer, s string) error {
	if _, err := w.WriteString("+" + s + "\r\n"); err != nil {
		return err
	}
	return w.Flush()
}

func writeError(w *bufio.Writer, s string) error {
	if _, err := w.WriteString("-" + s + "\r\n"); err != nil {
		return err
	}
	return w.Flush()
}

func writeInteger(w *bufio.Writer, n int64) error {
	if _, err := w.WriteString(":" + strconv.FormatInt(n, 10) + "\r\n"); err != nil {
		return err
	}
	return w.Flush()
}

func writeBulk(w *bufio.Writer, s string) error {
	if _, err := w.WriteString("$" + strconv.Itoa(len(s)) + "\r\n" + s + "\r\n"); err != nil {
		return err
	}
	return w.Flush()
}

func writeNil(w *bufio.Writer) error {
	if _, err := w.WriteString("$-1\r\n"); err != nil {
		return err
	}
	return w.Flush()
}
