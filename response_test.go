package traefik_http_knock

import (
	"bytes"
	"net/http"
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
