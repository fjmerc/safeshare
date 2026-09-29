package utils

import (
	"net/http/httptest"
	"testing"
)

const defaultTrustedProxies = "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

func restoreDefaultTrust(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		ConfigureClientIPTrust("auto", defaultTrustedProxies, false)
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
			ConfigureClientIPTrust(tt.trustProxyHeaders, tt.trustedProxyIPs, false)
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
			ConfigureClientIPTrust(tt.trustProxyHeaders, tt.trustedProxyIPs, false)
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

func restoreDefaultRateLimitIPv6Prefix(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		ConfigureRateLimitIPv6Prefix(64)
	})
}

func TestRateLimitKey_DefaultPrefix(t *testing.T) {
	restoreDefaultRateLimitIPv6Prefix(t)
	ConfigureRateLimitIPv6Prefix(64)

	a := RateLimitKey("2001:db8:1234:5678::1")
	b := RateLimitKey("2001:db8:1234:5678:aaaa:bbbb:cccc:dddd")
	if a != b {
		t.Errorf("RateLimitKey() for two addresses in the same /64 = %q, %q, want equal", a, b)
	}

	c := RateLimitKey("2001:db8:1234:9999::1")
	if a == c {
		t.Errorf("RateLimitKey() for addresses in different /64s both = %q, want different", a)
	}
}

func TestRateLimitKey_ConfiguredPrefix(t *testing.T) {
	restoreDefaultRateLimitIPv6Prefix(t)
	ConfigureRateLimitIPv6Prefix(48)

	a := RateLimitKey("2001:db8:1234::1")
	b := RateLimitKey("2001:db8:1234:ffff::1")
	if a != b {
		t.Errorf("RateLimitKey() with /48 configured for two addresses in the same /48 = %q, %q, want equal", a, b)
	}

	c := RateLimitKey("2001:db8:5678::1")
	if a == c {
		t.Errorf("RateLimitKey() with /48 configured for addresses in different /48s both = %q, want different", a)
	}
}

func TestRateLimitKey_128IsPerAddress(t *testing.T) {
	restoreDefaultRateLimitIPv6Prefix(t)
	ConfigureRateLimitIPv6Prefix(128)

	a := RateLimitKey("2001:db8::1")
	b := RateLimitKey("2001:db8::2")
	if a == b {
		t.Error("RateLimitKey() with prefix=128 grouped two distinct addresses together, want per-address")
	}

	same := RateLimitKey("2001:db8::1")
	if a != same {
		t.Error("RateLimitKey() with prefix=128 not stable for the same address")
	}
}

func TestRateLimitKey_IPv4AlwaysPerAddress(t *testing.T) {
	restoreDefaultRateLimitIPv6Prefix(t)
	ConfigureRateLimitIPv6Prefix(48) // IPv4 must be unaffected by the IPv6 prefix setting

	a := RateLimitKey("203.0.113.5")
	b := RateLimitKey("203.0.113.6")
	if a == b {
		t.Error("RateLimitKey() grouped two distinct IPv4 addresses together, want per-address")
	}
	if a != "203.0.113.5" {
		t.Errorf("RateLimitKey(%q) = %q, want unchanged", "203.0.113.5", a)
	}
}

func TestRateLimitKey_UnparsableFallsBackToInput(t *testing.T) {
	restoreDefaultRateLimitIPv6Prefix(t)
	got := RateLimitKey("not-an-ip")
	if got != "not-an-ip" {
		t.Errorf("RateLimitKey(%q) = %q, want unchanged input", "not-an-ip", got)
	}
}
