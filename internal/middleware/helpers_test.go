package middleware

import (
	"net/http/httptest"
	"testing"
)

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name           string
		remoteAddr     string
		xForwardedFor  string
		xRealIP        string
		expectedIP     string
	}{
		{
			name:       "direct connection from localhost",
			remoteAddr: "127.0.0.1:8080",
			expectedIP: "127.0.0.1",
		},
		{
			name:          "behind proxy from localhost with X-Forwarded-For",
			remoteAddr:    "127.0.0.1:8080",
			xForwardedFor: "203.0.113.50",
			expectedIP:    "203.0.113.50",
		},
		{
			name:       "behind proxy from RFC1918 with X-Forwarded-For",
			remoteAddr:    "10.0.0.1:8080",
			xForwardedFor: "203.0.113.100",
			expectedIP:    "203.0.113.100",
		},
		{
			name:          "behind proxy from 172.16.x.x with X-Forwarded-For",
			remoteAddr:    "172.16.0.1:8080",
			xForwardedFor: "198.51.100.50",
			expectedIP:    "198.51.100.50",
		},
		{
			name:          "behind proxy from 192.168.x.x with X-Forwarded-For",
			remoteAddr:    "192.168.1.1:8080",
			xForwardedFor: "192.0.2.100",
			expectedIP:    "192.0.2.100",
		},
		{
			name:        "behind proxy with X-Real-IP",
			remoteAddr:  "192.168.1.1:8080",
			xRealIP:     "203.0.113.200",
			expectedIP:  "203.0.113.200",
		},
		{
			name:          "X-Forwarded-For takes precedence over X-Real-IP",
			remoteAddr:    "127.0.0.1:8080",
			xForwardedFor: "203.0.113.1",
			xRealIP:       "203.0.113.2",
			expectedIP:    "203.0.113.1",
		},
		{
			name:          "X-Forwarded-For chain - uses first IP",
			remoteAddr:    "192.168.1.1:8080",
			xForwardedFor: "203.0.113.1, 10.0.0.1, 192.168.1.1",
			expectedIP:    "203.0.113.1",
		},
		{
			name:       "untrusted proxy - returns remote addr",
			remoteAddr: "203.0.113.50:8080",
			xForwardedFor: "10.0.0.1",
			expectedIP: "203.0.113.50",
		},
		{
			name:       "no headers - returns remote addr",
			remoteAddr: "192.168.1.100:8080",
			expectedIP: "192.168.1.100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardedFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardedFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			got := getClientIP(req)
			if got != tt.expectedIP {
				t.Errorf("getClientIP() = %q, want %q", got, tt.expectedIP)
			}
		})
	}
}

func TestGetClientIP_IPv6(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		expectedIP string
	}{
		{
			name:       "IPv6 localhost",
			remoteAddr: "[::1]:8080",
			expectedIP: "::1",
		},
		{
			name:       "IPv6 address",
			remoteAddr: "[2001:db8::1]:8080",
			expectedIP: "2001:db8::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = tt.remoteAddr

			got := getClientIP(req)
			if got != tt.expectedIP {
				t.Errorf("getClientIP() = %q, want %q", got, tt.expectedIP)
			}
		})
	}
}
