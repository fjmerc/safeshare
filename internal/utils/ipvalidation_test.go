package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestIsTrustedProxyIP(t *testing.T) {
	tests := []struct {
		name           string
		ipStr          string
		trustedProxies string
		want           bool
	}{
		{
			name:           "exact match single IP",
			ipStr:          "192.168.1.1",
			trustedProxies: "192.168.1.1",
			want:           true,
		},
		{
			name:           "no match single IP",
			ipStr:          "192.168.1.2",
			trustedProxies: "192.168.1.1",
			want:           false,
		},
		{
			name:           "CIDR match",
			ipStr:          "192.168.1.50",
			trustedProxies: "192.168.1.0/24",
			want:           true,
		},
		{
			name:           "CIDR no match",
			ipStr:          "192.168.2.50",
			trustedProxies: "192.168.1.0/24",
			want:           false,
		},
		{
			name:           "multiple proxies - match first",
			ipStr:          "10.0.0.1",
			trustedProxies: "10.0.0.1,192.168.1.0/24",
			want:           true,
		},
		{
			name:           "multiple proxies - match second CIDR",
			ipStr:          "192.168.1.100",
			trustedProxies: "10.0.0.1,192.168.1.0/24",
			want:           true,
		},
		{
			name:           "localhost IPv4",
			ipStr:          "127.0.0.1",
			trustedProxies: "127.0.0.1",
			want:           true,
		},
		{
			name:           "empty trusted proxies",
			ipStr:          "192.168.1.1",
			trustedProxies: "",
			want:           false,
		},
		{
			name:           "invalid IP",
			ipStr:          "not-an-ip",
			trustedProxies: "192.168.1.0/24",
			want:           false,
		},
		{
			name:           "whitespace in trusted proxies",
			ipStr:          "192.168.1.1",
			trustedProxies: " 192.168.1.1 , 10.0.0.1 ",
			want:           true,
		},
		{
			name:           "invalid CIDR",
			ipStr:          "192.168.1.1",
			trustedProxies: "192.168.1.0/invalid",
			want:           false,
		},
		{
			name:           "IPv6 address",
			ipStr:          "::1",
			trustedProxies: "::1",
			want:           true,
		},
		{
			name:           "IPv6 CIDR",
			ipStr:          "2001:db8::1",
			trustedProxies: "2001:db8::/32",
			want:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsTrustedProxyIP(tt.ipStr, tt.trustedProxies)
			if got != tt.want {
				t.Errorf("IsTrustedProxyIP(%q, %q) = %v, want %v", tt.ipStr, tt.trustedProxies, got, tt.want)
			}
		})
	}
}

func TestExtractIP(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{
			name: "IPv4 with port",
			addr: "192.168.1.1:8080",
			want: "192.168.1.1",
		},
		{
			name: "IPv4 without port",
			addr: "192.168.1.1",
			want: "192.168.1.1",
		},
		{
			name: "IPv6 with brackets and port",
			addr: "[::1]:8080",
			want: "::1",
		},
		{
			name: "IPv6 with brackets no port",
			addr: "[::1]",
			want: "::1",
		},
		{
			name: "IPv6 without brackets",
			addr: "::1",
			want: "::1",
		},
		{
			name: "full IPv6 without port",
			addr: "2001:db8::1",
			want: "2001:db8::1",
		},
		{
			name: "full IPv6 with brackets and port",
			addr: "[2001:db8::1]:443",
			want: "2001:db8::1",
		},
		{
			name: "localhost with port",
			addr: "127.0.0.1:3000",
			want: "127.0.0.1",
		},
		{
			name: "empty string",
			addr: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractIP(tt.addr)
			if got != tt.want {
				t.Errorf("ExtractIP(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}

func TestGetClientIPWithTrust(t *testing.T) {
	tests := []struct {
		name              string
		remoteAddr        string
		xForwardedFor     string
		xRealIP           string
		trustProxyHeaders string
		trustedProxyIPs   string
		want              string
	}{
		{
			name:              "trust=false returns RemoteAddr",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     "10.0.0.1",
			trustProxyHeaders: "false",
			trustedProxyIPs:   "",
			want:              "192.168.1.1",
		},
		{
			name:              "trust=true uses X-Forwarded-For",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     "10.0.0.1",
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "10.0.0.1",
		},
		{
			name:              "trust=true with chain uses first IP",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     "10.0.0.1, 172.16.0.1, 192.168.1.1",
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "10.0.0.1",
		},
		{
			name:              "trust=true prefers X-Forwarded-For over X-Real-IP",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     "10.0.0.1",
			xRealIP:           "172.16.0.1",
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "10.0.0.1",
		},
		{
			name:              "trust=true uses X-Real-IP when X-Forwarded-For empty",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     "",
			xRealIP:           "172.16.0.1",
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "172.16.0.1",
		},
		{
			name:              "trust=auto with trusted proxy uses X-Forwarded-For",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     "10.0.0.1",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   "192.168.1.1",
			want:              "10.0.0.1",
		},
		{
			name:              "trust=auto with untrusted proxy returns RemoteAddr",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     "10.0.0.1",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   "10.0.0.0/8",
			want:              "192.168.1.1",
		},
		{
			name:              "trust=true falls back to RemoteAddr when no headers",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     "",
			xRealIP:           "",
			trustProxyHeaders: "true",
			trustedProxyIPs:   "",
			want:              "192.168.1.1",
		},
		{
			name:              "unknown trust mode defaults to auto behavior",
			remoteAddr:        "192.168.1.1:8080",
			xForwardedFor:     "10.0.0.1",
			trustProxyHeaders: "unknown",
			trustedProxyIPs:   "192.168.1.1",
			want:              "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			got := GetClientIPWithTrust(req, tt.trustProxyHeaders, tt.trustedProxyIPs)
			if got != tt.want {
				t.Errorf("GetClientIPWithTrust() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIpInCIDR(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		cidr string
		want bool
	}{
		{
			name: "IP in CIDR",
			ip:   "192.168.1.100",
			cidr: "192.168.1.0/24",
			want: true,
		},
		{
			name: "IP not in CIDR",
			ip:   "192.168.2.1",
			cidr: "192.168.1.0/24",
			want: false,
		},
		{
			name: "invalid CIDR",
			ip:   "192.168.1.1",
			cidr: "invalid",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use IsTrustedProxyIP to test CIDR matching indirectly
			got := IsTrustedProxyIP(tt.ip, tt.cidr)
			if got != tt.want {
				t.Errorf("IsTrustedProxyIP(%q, %q) = %v, want %v", tt.ip, tt.cidr, got, tt.want)
			}
		})
	}
}
