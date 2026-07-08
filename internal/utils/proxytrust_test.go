package utils

import (
	"net/http/httptest"
	"testing"
)

const defaultTrustedProxies = "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

func restoreDefaultTrust(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		ConfigureClientIPTrust("auto", defaultTrustedProxies)
	})
}

func TestTrustsProxyHeaders(t *testing.T) {
	restoreDefaultTrust(t)

	tests := []struct {
		name              string
		trustProxyHeaders string
		trustedProxyIPs   string
		remoteAddr        string
		want              bool
	}{
		{
			name:              "auto trusts RFC1918 source",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   defaultTrustedProxies,
			remoteAddr:        "10.1.2.3:41000",
			want:              true,
		},
		{
			name:              "auto trusts loopback source",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   defaultTrustedProxies,
			remoteAddr:        "127.0.0.1:41000",
			want:              true,
		},
		{
			name:              "auto rejects public source",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   defaultTrustedProxies,
			remoteAddr:        "203.0.113.5:41000",
			want:              false,
		},
		{
			name:              "true trusts everything",
			trustProxyHeaders: "true",
			trustedProxyIPs:   defaultTrustedProxies,
			remoteAddr:        "203.0.113.5:41000",
			want:              true,
		},
		{
			name:              "false trusts nothing",
			trustProxyHeaders: "false",
			trustedProxyIPs:   defaultTrustedProxies,
			remoteAddr:        "10.1.2.3:41000",
			want:              false,
		},
		{
			name:              "auto with narrowed proxy list rejects other private ranges",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   "192.168.1.10",
			remoteAddr:        "10.1.2.3:41000",
			want:              false,
		},
		{
			name:              "auto with narrowed proxy list trusts listed proxy",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   "192.168.1.10",
			remoteAddr:        "192.168.1.10:41000",
			want:              true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreDefaultTrust(t)
			ConfigureClientIPTrust(tt.trustProxyHeaders, tt.trustedProxyIPs)
			req := httptest.NewRequest("GET", "http://localhost:8080/", nil)
			req.RemoteAddr = tt.remoteAddr

			if got := TrustsProxyHeaders(req); got != tt.want {
				t.Errorf("TrustsProxyHeaders() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetClientIP_ConfiguredTrust(t *testing.T) {
	restoreDefaultTrust(t)

	tests := []struct {
		name              string
		trustProxyHeaders string
		trustedProxyIPs   string
		remoteAddr        string
		xForwardedFor     string
		xRealIP           string
		want              string
	}{
		{
			name:              "honors XFF from trusted proxy",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   defaultTrustedProxies,
			remoteAddr:        "10.1.2.3:41000",
			xForwardedFor:     "203.0.113.9",
			want:              "203.0.113.9",
		},
		{
			name:              "ignores XFF from untrusted source",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   defaultTrustedProxies,
			remoteAddr:        "198.51.100.7:41000",
			xForwardedFor:     "203.0.113.9",
			want:              "198.51.100.7",
		},
		{
			name:              "false mode ignores XFF even from private source",
			trustProxyHeaders: "false",
			trustedProxyIPs:   defaultTrustedProxies,
			remoteAddr:        "10.1.2.3:41000",
			xForwardedFor:     "203.0.113.9",
			want:              "10.1.2.3",
		},
		{
			name:              "narrowed proxy list blocks spoofing from other containers",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   "192.168.1.10",
			remoteAddr:        "172.17.0.5:41000",
			xForwardedFor:     "1.2.3.4",
			want:              "172.17.0.5",
		},
		{
			name:              "honors X-Real-IP from trusted proxy when no XFF",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   defaultTrustedProxies,
			remoteAddr:        "10.1.2.3:41000",
			xRealIP:           "203.0.113.9",
			want:              "203.0.113.9",
		},
		{
			name:              "ignores X-Real-IP from untrusted source",
			trustProxyHeaders: "auto",
			trustedProxyIPs:   defaultTrustedProxies,
			remoteAddr:        "198.51.100.7:41000",
			xRealIP:           "203.0.113.9",
			want:              "198.51.100.7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			restoreDefaultTrust(t)
			ConfigureClientIPTrust(tt.trustProxyHeaders, tt.trustedProxyIPs)
			req := httptest.NewRequest("GET", "http://localhost:8080/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			if got := GetClientIP(req); got != tt.want {
				t.Errorf("GetClientIP() = %q, want %q", got, tt.want)
			}
		})
	}
}
