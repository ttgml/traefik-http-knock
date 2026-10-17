package traefik_http_knock

import (
	"bufio"
	"bytes"
	"net"
	"net/http"
	"strings"
	"testing"
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
