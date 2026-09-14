package traefik_http_knock

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
)

// errNoClientIP is returned when no usable client IP can be determined. The
// middleware denies the request in that case instead of guessing.
var errNoClientIP = errors.New("no usable client IP found in the request")

// clientIPFromRequest resolves the client IP for a request.
//
// When header is empty the TCP peer address from req.RemoteAddr is used, which
// cannot be spoofed by the client. When header is set (for example
// "X-Real-IP" or "CF-Connecting-IP") that header wins, but only if it contains
// a syntactically valid IP; otherwise the trusted peer address is used as a
// fallback so that a missing header cannot lock everybody out.
//
// SECURITY: a configured header is only trustworthy when a reverse proxy in
// front of Traefik always overwrites it. See the README.
func clientIPFromRequest(req *http.Request, header string) (string, error) {
	if req == nil {
		return "", errNoClientIP
	}

	if header != "" {
		if raw := req.Header.Get(header); raw != "" {
			candidate := raw
			if strings.EqualFold(header, "X-Forwarded-For") {
				candidate = firstForwardedFor(raw)
			}
			if ip, err := normalizeIP(candidate); err == nil {
				return ip, nil
			}
		}
	}

	return remoteIP(req.RemoteAddr)
}

// remoteIP extracts and normalizes the IP from a "host:port" peer address. It
// also accepts a bare IP (used by some proxies and by tests) and strips an
// IPv6 zone such as "fe80::1%eth0".
func remoteIP(remoteAddr string) (string, error) {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return "", errNoClientIP
	}

	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	} else if strings.HasPrefix(remoteAddr, "[") && strings.HasSuffix(remoteAddr, "]") {
		// "[2001:db8::1]" without port.
		host = strings.TrimSuffix(strings.TrimPrefix(remoteAddr, "["), "]")
	}

	return normalizeIP(host)
}

// normalizeIP validates raw and returns its canonical textual form. Using the
// canonical form means a single client always maps to a single Redis key, so
// "2001:0DB8:0:0::1" and "2001:db8::1" cannot create two different entries.
func normalizeIP(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errNoClientIP
	}

	// Drop an IPv6 zone identifier ("fe80::1%eth0") before parsing.
	if i := strings.IndexByte(raw, '%'); i >= 0 {
		raw = raw[:i]
	}

	// Strip a port when the value is unambiguously "host:port": either an
	// IPv4 address or a bracketed IPv6 literal. A bare IPv6 address contains
	// several colons and is left untouched.
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	} else if strings.HasPrefix(raw, "[") && strings.HasSuffix(raw, "]") {
		// "[2001:db8::1]" without a port.
		raw = raw[1 : len(raw)-1]
	}

	ip := net.ParseIP(raw)
	if ip == nil {
		return "", fmt.Errorf("%w: %q is not a valid IP address", errNoClientIP, raw)
	}
	return ip.String(), nil
}

// firstForwardedFor returns the left-most entry of an X-Forwarded-For value,
// which is the original client. Trailing proxies are ignored.
func firstForwardedFor(value string) string {
	if i := strings.IndexByte(value, ','); i >= 0 {
		value = value[:i]
	}
	return strings.TrimSpace(value)
}

// validHeaderName reports whether name is a valid HTTP header field name
// (RFC 7230 token). A misspelled header would otherwise silently fall back to
// the peer address, which is safe but surprising for the operator.
func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)):
		default:
			return false
		}
	}
	return true
}
