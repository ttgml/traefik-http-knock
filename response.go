package traefik_http_knock

import (
	"bufio"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
)

// privateResponseWriter enforces cache isolation on protected responses.
//
// A shared cache (CDN, reverse proxy) must never store a response that was
// authorized by a cookie or Authorization header. Backends sometimes set
// "Cache-Control: public" themselves, so setting the header before calling the
// backend is not enough: this wrapper applies the final value at WriteHeader
// time.
//
// Yaegi, the interpreter Traefik uses for local plugins, bridges an interpreted
// http.ResponseWriter with stdlib._netHTTPResponseWriterHijacker: Header, Write,
// WriteHeader and Hijack are forwarded, nothing else. http.Flusher and Unwrap
// are absent, so the reverse proxy's flushes never reach the wrapped writer and
// a streaming response stays buffered until the backend closes it. Write flushes
// unframed responses itself; see flushWrites. WebSocket upgrades are unaffected,
// because the bridge does forward Hijack.
type privateResponseWriter struct {
	http.ResponseWriter
	wroteHeader bool
	// flushWrites is set when the backend did not declare a Content-Length.
	// Such a response is chunked or delimited by EOF, which is how streaming
	// responses (SSE, NDJSON, token streams) are produced.
	flushWrites bool
}

func newPrivateResponseWriter(rw http.ResponseWriter) *privateResponseWriter {
	return &privateResponseWriter{ResponseWriter: rw}
}

func (w *privateResponseWriter) applyPrivateHeaders() {
	applyPrivateHeaders(w.ResponseWriter.Header())
}

// applyPrivateHeaders marks a response as non-shared-cacheable. It preserves an
// explicit "no-store" from the backend: private is weaker than no-store, and
// overwriting it would make a sensitive response browser-cacheable. Other
// stronger directives such as no-cache or must-revalidate are kept so adding
// private does not let a browser serve a stale authenticated response without
// revalidation. Shared-cache-only directives (public, s-maxage) are dropped.
func applyPrivateHeaders(header http.Header) {
	if !hasNoStore(header) {
		if len(header.Values("Cache-Control")) == 0 {
			// Most backends do not set Cache-Control; avoid allocating a
			// directive slice and joining it just to produce "private".
			header.Set("Cache-Control", "private")
		} else {
			header.Set("Cache-Control", privateCacheControl(header.Values("Cache-Control")))
		}
	}
	addVary(header, "Cookie")
	addVary(header, "Authorization")
}

// privateCacheControl returns the existing directives with private added and
// shared-cache directives removed. It keeps max-age, no-cache, must-revalidate
// and similar directives so the wrapper does not weaken the backend's policy.
func privateCacheControl(values []string) string {
	directives := make([]string, 0, 4)
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			lower := strings.ToLower(part)
			switch lower {
			case "private":
				continue
			case "public":
				continue
			}
			if strings.HasPrefix(lower, "s-maxage=") {
				continue
			}
			directives = append(directives, part)
		}
	}
	directives = append(directives, "private")
	return strings.Join(directives, ", ")
}

func hasNoStore(header http.Header) bool {
	for _, value := range header.Values("Cache-Control") {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), "no-store") {
				return true
			}
		}
	}
	return false
}

func (w *privateResponseWriter) WriteHeader(statusCode int) {
	// 1xx responses other than 101 are informational and do not commit the
	// response. Passing them through without setting wroteHeader keeps the
	// wrapper from dropping the backend's final status.
	if statusCode >= 100 && statusCode < 200 && statusCode != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(statusCode)
		return
	}
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.applyPrivateHeaders()
	w.flushWrites = !hasContentLength(w.ResponseWriter.Header())
	w.ResponseWriter.WriteHeader(statusCode)
}

// finish applies the private headers when the backend returned without writing
// anything. The server still sends an implicit 200 using these headers.
func (w *privateResponseWriter) finish() {
	if !w.wroteHeader {
		w.applyPrivateHeaders()
	}
}

func (w *privateResponseWriter) Write(body []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	n, err := w.ResponseWriter.Write(body)
	// Traefik's reverse proxy cannot flush through this wrapper under Yaegi
	// (see the type comment), so an unframed response must be flushed here or
	// the client sees nothing until the backend closes the stream. Framed
	// responses keep net/http's normal buffering.
	if w.flushWrites {
		flushWriter(w.ResponseWriter)
	}
	return n, err
}

// flushWriter forwards a flush when the wrapped writer supports it.
func flushWriter(rw http.ResponseWriter) {
	if flusher, ok := rw.(http.Flusher); ok {
		flusher.Flush()
	}
}

// hasContentLength reports whether the backend declared a body length.
func hasContentLength(header http.Header) bool {
	for _, value := range header.Values("Content-Length") {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return false
}

// ReadFrom forwards to the underlying writer's ReadFrom when it implements
// io.ReaderFrom. net/http's response does, and uses it for the sendfile
// fast path on large bodies. Without this method io.Copy sees only the wrapper,
// falls back to a generic buffer copy, and sends every chunk through Write
// (which is interpreted when the plugin runs under Yaegi).
func (w *privateResponseWriter) ReadFrom(src io.Reader) (int64, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(w.ResponseWriter, src)
}

func (w *privateResponseWriter) Flush() {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	flushWriter(w.ResponseWriter)
}

func (w *privateResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("http-knock: underlying ResponseWriter does not support hijacking")
	}
	return hijacker.Hijack()
}

func (w *privateResponseWriter) Push(target string, opts *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, opts)
}

// Unwrap lets http.ResponseController reach the original writer.
func (w *privateResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// addVary adds a field to the Vary header unless it is already present. It
// keeps existing values from the backend intact.
func addVary(header http.Header, field string) {
	for _, value := range header.Values("Vary") {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), field) {
				return
			}
		}
	}
	header.Add("Vary", field)
}

// setNoStore marks responses generated by the middleware as uncacheable.
func setNoStore(header http.Header) {
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
}
