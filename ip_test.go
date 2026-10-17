package traefik_http_knock

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "ipv4", input: "192.168.1.10", want: "192.168.1.10"},
		{name: "ipv4 with port", input: "192.168.1.10:4567", want: "192.168.1.10"},
		{name: "ipv4 with spaces", input: "  10.0.0.1  ", want: "10.0.0.1"},
		{name: "ipv6", input: "2001:db8::1", want: "2001:db8::1"},
		{name: "ipv6 compressed", input: "2001:0DB8:0:0:0:0:0:1", want: "2001:db8::1"},
		{name: "ipv6 loopback", input: "::1", want: "::1"},
		{name: "ipv6 with brackets", input: "[2001:db8::1]", want: "2001:db8::1"},
		{name: "ipv6 with brackets and port", input: "[2001:db8::1]:443", want: "2001:db8::1"},
		{name: "ipv6 with zone", input: "fe80::1%eth0", want: "fe80::1"},
		{name: "ipv4 mapped ipv6 matches plain ipv4", input: "::ffff:10.0.0.1", want: "10.0.0.1"},
		{name: "ipv4 mapped ipv6 uppercase", input: "::FFFF:192.168.1.10", want: "192.168.1.10"},
		{name: "empty", input: "", wantErr: true},
		{name: "garbage", input: "not-an-ip", wantErr: true},
		{name: "hostname", input: "example.com", wantErr: true},
		{name: "injection attempt", input: "1.2.3.4:6379:9", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeIP(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("normalizeIP(%q) = %q, want error", tt.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeIP(%q): %v", tt.input, err)
			}
			if got != tt.want {
				t.Fatalf("normalizeIP(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRemoteIP(t *testing.T) {
	tests := []struct {
		name    string
		remote  string
		want    string
		wantErr bool
	}{
		{name: "ipv4 with port", remote: "10.0.0.1:5000", want: "10.0.0.1"},
		{name: "ipv6 with port", remote: "[2001:db8::1]:5000", want: "2001:db8::1"},
		{name: "bare ipv4", remote: "10.0.0.1", want: "10.0.0.1"},
		{name: "bare ipv6", remote: "2001:db8::1", want: "2001:db8::1"},
		{name: "empty", remote: "", wantErr: true},
		{name: "garbage", remote: "nope", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := remoteIP(tt.remote)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("remoteIP(%q) = %q, want error", tt.remote, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("remoteIP(%q): %v", tt.remote, err)
			}
			if got != tt.want {
				t.Fatalf("remoteIP(%q) = %q, want %q", tt.remote, got, tt.want)
			}
		})
	}
}

func TestClientIPFromRequest(t *testing.T) {
	tests := []struct {
		name    string
		header  string
		values  map[string]string
		remote  string
		want    string
		wantErr bool
	}{
		{
			name:   "remote address by default",
			remote: "192.0.2.10:5000",
			want:   "192.0.2.10",
		},
		{
			name:   "ipv6 remote address",
			remote: "[2001:db8::5]:5000",
			want:   "2001:db8::5",
		},
		{
			name:   "x-real-ip wins",
			header: "X-Real-IP",
			values: map[string]string{"X-Real-IP": "203.0.113.5"},
			remote: "192.0.2.10:5000",
			want:   "203.0.113.5",
		},
		{
			name:   "cloudflare header",
			header: "CF-Connecting-IP",
			values: map[string]string{"CF-Connecting-IP": "2001:DB8::9"},
			remote: "192.0.2.10:5000",
			want:   "2001:db8::9",
		},
		{
			name:   "x-forwarded-for takes the first entry",
			header: "X-Forwarded-For",
			values: map[string]string{"X-Forwarded-For": "203.0.113.5, 70.41.3.18, 150.172.238.178"},
			remote: "192.0.2.10:5000",
			want:   "203.0.113.5",
		},
		{
			name:   "x-forwarded-for tolerates whitespace",
			header: "X-Forwarded-For",
			values: map[string]string{"X-Forwarded-For": "  203.0.113.5 ,10.0.0.1"},
			remote: "192.0.2.10:5000",
			want:   "203.0.113.5",
		},
		{
			name:   "missing header falls back to the peer",
			header: "X-Real-IP",
			remote: "192.0.2.10:5000",
			want:   "192.0.2.10",
		},
		{
			name:   "invalid header falls back to the peer",
			header: "X-Real-IP",
			values: map[string]string{"X-Real-IP": "definitely-not-an-ip"},
			remote: "192.0.2.10:5000",
			want:   "192.0.2.10",
		},
		{
			name:   "unknown header falls back to the peer",
			header: "X-Custom-Client-IP",
			values: map[string]string{"X-Custom-Client-IP": "203.0.113.5"},
			remote: "192.0.2.10:5000",
			want:   "203.0.113.5",
		},
		{
			name:    "no remote address and no header",
			remote:  "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
			req.RemoteAddr = tt.remote
			for k, v := range tt.values {
				req.Header.Set(k, v)
			}

			got, err := clientIPFromRequest(req, tt.header)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("clientIPFromRequest() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("clientIPFromRequest(): %v", err)
			}
			if got != tt.want {
				t.Fatalf("clientIPFromRequest() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClientIPFromRequestNilRequest(t *testing.T) {
	if _, err := clientIPFromRequest(nil, ""); err == nil {
		t.Fatal("expected an error for a nil request")
	}
}

func TestFirstForwardedFor(t *testing.T) {
	tests := []struct{ in, want string }{
		{"203.0.113.5", "203.0.113.5"},
		{"203.0.113.5,70.41.3.18", "203.0.113.5"},
		{" 203.0.113.5 , 70.41.3.18 ", "203.0.113.5"},
		{"2001:db8::1, 10.0.0.1", "2001:db8::1"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := firstForwardedFor(tt.in); got != tt.want {
			t.Fatalf("firstForwardedFor(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIPGrantKey(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		realm  string
		ip     string
		want   string
	}{
		{name: "ipv4", prefix: "traefik:http-knock:", realm: "app", ip: "192.168.1.10", want: "traefik:http-knock:app:ip:192.168.1.10"},
		{name: "ipv6", prefix: "traefik:http-knock:", realm: "app", ip: "2001:db8::1", want: "traefik:http-knock:app:ip:2001:db8::1"},
		{name: "custom prefix", prefix: "knock:", realm: "app", ip: "10.0.0.1", want: "knock:app:ip:10.0.0.1"},
		{name: "v4 and v6 never collide", prefix: "k:", realm: "app", ip: "::1", want: "k:app:ip:::1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipGrantKey(tt.prefix, tt.realm, tt.ip); got != tt.want {
				t.Fatalf("ipGrantKey(%q, %q, %q) = %q, want %q", tt.prefix, tt.realm, tt.ip, got, tt.want)
			}
		})
	}
}

func TestConstantTimeEqualString(t *testing.T) {
	if !constantTimeEqualString("secret", "secret") {
		t.Fatal("identical strings must be equal")
	}
	if constantTimeEqualString("secret", "secrez") {
		t.Fatal("different strings must not be equal")
	}
	if constantTimeEqualString("secret", "secret-longer") {
		t.Fatal("different lengths must not be equal")
	}
	if !constantTimeEqualString("", "") {
		t.Fatal("empty strings must be equal")
	}
}

func TestParseStaticAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		ip      string
		want    bool
	}{
		{name: "exact ipv4", entries: []string{"203.0.113.7"}, ip: "203.0.113.7", want: true},
		{name: "exact ipv4 mismatch", entries: []string{"203.0.113.7"}, ip: "203.0.113.8", want: false},
		{name: "exact ipv6", entries: []string{"2001:db8::1"}, ip: "2001:db8::1", want: true},
		{name: "ipv4 mapped matches plain ipv4", entries: []string{"10.0.0.1"}, ip: "10.0.0.1", want: true},
		{name: "ipv4 cidr inside", entries: []string{"10.0.0.0/24"}, ip: "10.0.0.99", want: true},
		{name: "ipv4 cidr outside", entries: []string{"10.0.0.0/24"}, ip: "10.0.1.1", want: false},
		{name: "ipv6 cidr inside", entries: []string{"2001:db8::/32"}, ip: "2001:db8:1::5", want: true},
		{name: "ipv6 cidr outside", entries: []string{"2001:db8::/32"}, ip: "2001:db9::1", want: false},
		{name: "host bits are masked", entries: []string{"10.0.0.5/24"}, ip: "10.0.0.200", want: true},
		{name: "mixed entries", entries: []string{"10.0.0.0/8", "2001:db8::1", "192.168.0.0/16"}, ip: "192.168.5.5", want: true},
		{name: "surrounding whitespace", entries: []string{"  10.0.0.1  "}, ip: "10.0.0.1", want: true},
		{name: "empty allowlist", entries: nil, ip: "10.0.0.1", want: false},
		{name: "empty ip", entries: []string{"10.0.0.1"}, ip: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allow, err := parseStaticAllowlist(tt.entries)
			if err != nil {
				t.Fatalf("parseStaticAllowlist(%v): %v", tt.entries, err)
			}
			if got := allow.contains(tt.ip); got != tt.want {
				t.Fatalf("contains(%q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestParseStaticAllowlistRejectsBadEntries(t *testing.T) {
	for _, entry := range []string{
		"",
		"   ",
		"not-an-ip",
		"999.1.1.1",
		"example.com",
		"10.0.0.0/33",
		"10.0.0.1/abc",
		"2001:db8::/129",
	} {
		if _, err := parseStaticAllowlist([]string{entry}); err == nil {
			t.Fatalf("parseStaticAllowlist(%q) must fail", entry)
		}
	}
}

func TestStaticAllowlistNilContainsNothing(t *testing.T) {
	var allow *staticAllowlist
	if allow.contains("10.0.0.1") {
		t.Fatal("a nil allowlist must match nothing")
	}
}

// TestValidHeaderName covers the names operators actually configure. The
// regression this guards against is interpreter-specific (see
// validHeaderName): real Go accepted them, Yaegi did not, so the cases with
// uppercase letters or digits are the ones that matter.
func TestValidHeaderName(t *testing.T) {
	tests := []struct {
		name  string
		head  string
		valid bool
	}{
		{name: "empty", head: "", valid: false},
		{name: "cloudflare", head: "CF-Connecting-IP", valid: true},
		{name: "canonicalised cloudflare", head: http.CanonicalHeaderKey("CF-Connecting-IP"), valid: true},
		{name: "lowercase", head: "x-real-ip", valid: true},
		{name: "x-forwarded-for", head: "X-Forwarded-For", valid: true},
		{name: "letters only", head: "XRealIP", valid: true},
		{name: "digits only", head: "1234", valid: true},
		{name: "digits inside", head: "X-Real-IP-2", valid: true},
		{name: "token specials", head: "_-.~^|`!#$%&'*+", valid: true},
		{name: "space", head: "X Real IP", valid: false},
		{name: "tab", head: "X-Real-IP\t", valid: false},
		{name: "colon", head: "X-Real-IP:", valid: false},
		{name: "newline", head: "X-Real-IP\n", valid: false},
		{name: "non-ascii", head: "X-Réal", valid: false},
		{name: "underscore-prefixed", head: "_realip", valid: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validHeaderName(tt.head); got != tt.valid {
				t.Errorf("validHeaderName(%q) = %v, want %v", tt.head, got, tt.valid)
			}
		})
	}
}
