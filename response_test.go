package traefik_http_knock

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// statusWriter records every WriteHeader call, including informational 1xx
// responses, so the wrapper can be tested without a real HTTP server.
type statusWriter struct {
	header   http.Header
	statuses []int
	body     bytes.Buffer
}

func newStatusWriter() *statusWriter {
	return &statusWriter{header: make(http.Header)}
}

func (w *statusWriter) Header() http.Header { return w.header }

func (w *statusWriter) WriteHeader(statusCode int) {
	w.statuses = append(w.statuses, statusCode)
}

func (w *statusWriter) Write(body []byte) (int, error) {
	if len(w.statuses) == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.body.Write(body)
}

func TestPrivateResponseWriterPreservesNoStore(t *testing.T) {
	rw := newStatusWriter()
	rw.Header().Set("Cache-Control", "no-store")
	w := newPrivateResponseWriter(rw)
	w.WriteHeader(http.StatusOK)

	if got := rw.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
	if got := rw.Header().Values("Vary"); len(got) != 2 {
		t.Fatalf("Vary = %v, want Cookie and Authorization", got)
	}
}

func TestPrivateResponseWriterPreservesStrongerDirectives(t *testing.T) {
	rw := newStatusWriter()
	rw.Header().Set("Cache-Control", "no-cache, s-maxage=60, max-age=30")
	w := newPrivateResponseWriter(rw)
	w.WriteHeader(http.StatusOK)

	got := rw.Header().Get("Cache-Control")
	if !strings.Contains(got, "no-cache") {
		t.Fatalf("Cache-Control = %q, want no-cache preserved", got)
	}
	if !strings.Contains(got, "max-age=30") {
		t.Fatalf("Cache-Control = %q, want max-age preserved", got)
	}
	if !strings.Contains(got, "private") {
		t.Fatalf("Cache-Control = %q, want private added", got)
	}
	if strings.Contains(got, "s-maxage") {
		t.Fatalf("Cache-Control = %q, want s-maxage removed", got)
	}
}

func TestPrivateResponseWriterForwardsInformationalStatus(t *testing.T) {
	rw := newStatusWriter()
	w := newPrivateResponseWriter(rw)
	w.WriteHeader(http.StatusEarlyHints)
	w.WriteHeader(http.StatusNotFound)

	if len(rw.statuses) != 2 || rw.statuses[0] != http.StatusEarlyHints || rw.statuses[1] != http.StatusNotFound {
		t.Fatalf("statuses = %v, want [103 404]", rw.statuses)
	}
}

func TestPrivateResponseWriterAddsHeadersWhenBackendWritesNothing(t *testing.T) {
	rw := newStatusWriter()
	w := newPrivateResponseWriter(rw)
	w.finish()

	if got := rw.Header().Get("Cache-Control"); got != "private" {
		t.Fatalf("Cache-Control = %q, want private", got)
	}
	if len(rw.statuses) != 0 {
		t.Fatalf("finish must not write a status, got %v", rw.statuses)
	}
}

func TestPrivateResponseWriterSetsHeadersOnWrite(t *testing.T) {
	rw := newStatusWriter()
	w := newPrivateResponseWriter(rw)
	if _, err := w.Write([]byte("ok")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := rw.Header().Get("Cache-Control"); got != "private" {
		t.Fatalf("Cache-Control = %q, want private", got)
	}
	if len(rw.statuses) != 1 || rw.statuses[0] != http.StatusOK {
		t.Fatalf("statuses = %v, want [200]", rw.statuses)
	}
}

// readFromWriter records calls to ReadFrom so the wrapper can prove that it
// keeps net/http's sendfile fast path reachable.
type readFromWriter struct {
	statusWriter
	readFromCalls int
}

func (w *readFromWriter) ReadFrom(src io.Reader) (int64, error) {
	w.readFromCalls++
	if len(w.statuses) == 0 {
		w.WriteHeader(http.StatusOK)
	}
	// writerOnly hides this type's ReadFrom method from io.Copy, otherwise the
	// copy would recurse back into ReadFrom.
	return io.Copy(writerOnly{w}, src)
}

type writerOnly struct{ io.Writer }

func TestPrivateResponseWriterForwardsReadFrom(t *testing.T) {
	rw := &readFromWriter{statusWriter: *newStatusWriter()}
	w := newPrivateResponseWriter(rw)

	n, err := w.ReadFrom(strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != int64(len("hello")) {
		t.Fatalf("ReadFrom copied %d bytes, want %d", n, len("hello"))
	}
	if rw.readFromCalls != 1 {
		t.Fatalf("underlying ReadFrom calls = %d, want 1", rw.readFromCalls)
	}
	if got := rw.body.String(); got != "hello" {
		t.Fatalf("body = %q, want hello", got)
	}
	if got := rw.Header().Get("Cache-Control"); got != "private" {
		t.Fatalf("Cache-Control = %q, want private", got)
	}
	if len(rw.statuses) != 1 || rw.statuses[0] != http.StatusOK {
		t.Fatalf("statuses = %v, want [200]", rw.statuses)
	}
}

func TestPrivateResponseWriterReadFromFallback(t *testing.T) {
	rw := newStatusWriter()
	w := newPrivateResponseWriter(rw)

	n, err := w.ReadFrom(strings.NewReader("fallback"))
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != int64(len("fallback")) {
		t.Fatalf("ReadFrom copied %d bytes, want %d", n, len("fallback"))
	}
	if got := rw.body.String(); got != "fallback" {
		t.Fatalf("body = %q, want fallback", got)
	}
	if got := rw.Header().Get("Cache-Control"); got != "private" {
		t.Fatalf("Cache-Control = %q, want private", got)
	}
	if len(rw.statuses) != 1 || rw.statuses[0] != http.StatusOK {
		t.Fatalf("statuses = %v, want [200]", rw.statuses)
	}
}

// optionalWriter implements the optional interfaces that streaming, WebSocket
// and HTTP/2 push backends type-assert on a ResponseWriter.
type optionalWriter struct {
	statusWriter
	flushed  bool
	hijacked bool
	pushed   string
}

func (w *optionalWriter) Flush() { w.flushed = true }

func (w *optionalWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	w.hijacked = true
	return nil, nil, nil
}

func (w *optionalWriter) Push(target string, _ *http.PushOptions) error {
	w.pushed = target
	return nil
}

func TestPrivateResponseWriterForwardsOptionalInterfaces(t *testing.T) {
	rw := &optionalWriter{statusWriter: *newStatusWriter()}
	w := newPrivateResponseWriter(rw)

	if got := w.Unwrap(); got != rw {
		t.Fatalf("Unwrap() = %T, want the original writer", got)
	}

	w.Flush()
	if !rw.flushed {
		t.Fatal("Flush was not forwarded to the backend writer")
	}
	if len(rw.statuses) != 1 || rw.statuses[0] != http.StatusOK {
		t.Fatalf("statuses after Flush = %v, want [200]", rw.statuses)
	}

	if _, _, err := w.Hijack(); err != nil {
		t.Fatalf("Hijack: %v", err)
	}
	if !rw.hijacked {
		t.Fatal("Hijack was not forwarded to the backend writer")
	}

	if err := w.Push("/style.css", nil); err != nil {
		t.Fatalf("Push: %v", err)
	}
	if rw.pushed != "/style.css" {
		t.Fatalf("pushed target = %q, want /style.css", rw.pushed)
	}
}

func TestPrivateResponseWriterOptionalInterfacesUnsupported(t *testing.T) {
	rw := newStatusWriter()
	w := newPrivateResponseWriter(rw)

	if _, _, err := w.Hijack(); err == nil {
		t.Fatal("Hijack must fail when the backend writer does not support it")
	}
	if err := w.Push("/style.css", nil); err != http.ErrNotSupported {
		t.Fatalf("Push error = %v, want http.ErrNotSupported", err)
	}
}

// flusherWriter records Flush calls so the wrapper can prove that it flushes
// the responses the reverse proxy cannot reach a flusher for.
type flusherWriter struct {
	statusWriter
	flushes int
}

func (w *flusherWriter) Flush() { w.flushes++ }

func TestPrivateResponseWriterFlushesUnframedWrites(t *testing.T) {
	rw := &flusherWriter{statusWriter: *newStatusWriter()}
	rw.Header().Set("Content-Type", "text/event-stream")
	w := newPrivateResponseWriter(rw)

	for i := 0; i < 3; i++ {
		if _, err := w.Write([]byte("data: tick\n\n")); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	if rw.flushes != 3 {
		t.Fatalf("flushes = %d, want one per write (3)", rw.flushes)
	}
	if got, want := rw.body.String(), strings.Repeat("data: tick\n\n", 3); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
	if got := rw.Header().Get("Cache-Control"); got != "private" {
		t.Fatalf("Cache-Control = %q, want private", got)
	}
}

func TestPrivateResponseWriterKeepsFramedResponsesBuffered(t *testing.T) {
	rw := &flusherWriter{statusWriter: *newStatusWriter()}
	rw.Header().Set("Content-Length", "5")
	w := newPrivateResponseWriter(rw)

	if _, err := w.Write([]byte("hello")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if rw.flushes != 0 {
		t.Fatalf("flushes = %d, want 0 for a response with Content-Length", rw.flushes)
	}
}

// TestPrivateResponseWriterStreamsToClient holds the backend open after the
// first event. A client must receive that event before the handler returns,
// which only happens when the wrapper flushes a response without a
// Content-Length. The backend deliberately never calls Flush: Traefik's reverse
// proxy is the caller that would normally do it, and under Yaegi it cannot reach
// the wrapper's Flush method.
func TestPrivateResponseWriterStreamsToClient(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		w := newPrivateResponseWriter(rw)
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		<-release
		io.WriteString(w, "data: second\n\n")
	}))
	defer srv.Close()
	defer close(release)

	// The timeout bounds the failure mode this test guards against: a buffered
	// response also holds back the response headers, so the request itself
	// blocks until the backend finishes.
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	first := make([]byte, len("data: first\n\n"))
	read := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(resp.Body, first)
		read <- err
	}()

	select {
	case err := <-read:
		if err != nil {
			t.Fatalf("reading the first event: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first event was buffered until the handler returned")
	}
}
