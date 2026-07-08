package utils

import (
	"net/http"
	"sync/atomic"
)

// proxyTrustConfig holds the process-wide proxy trust settings, configured
// once at startup from the loaded config. Helpers that have no access to
// *config.Config (middleware, handler shortcuts) read from here instead of
// hardcoding trust values.
type proxyTrustConfig struct {
	trustProxyHeaders string
	trustedProxyIPs   string
}

// Defaults match config defaults: "auto" mode with loopback + RFC1918 proxies.
var currentProxyTrust atomic.Pointer[proxyTrustConfig]

func init() {
	currentProxyTrust.Store(&proxyTrustConfig{
		trustProxyHeaders: "auto",
		trustedProxyIPs:   "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
	})
}

// ConfigureClientIPTrust sets the process-wide proxy trust settings.
// Call once at startup after loading config, before serving requests.
func ConfigureClientIPTrust(trustProxyHeaders, trustedProxyIPs string) {
	currentProxyTrust.Store(&proxyTrustConfig{
		trustProxyHeaders: trustProxyHeaders,
		trustedProxyIPs:   trustedProxyIPs,
	})
}

// GetClientIP extracts the client IP using the configured proxy trust settings.
func GetClientIP(r *http.Request) string {
	cfg := currentProxyTrust.Load()
	return GetClientIPWithTrust(r, cfg.trustProxyHeaders, cfg.trustedProxyIPs)
}

// TrustsProxyHeaders reports whether proxy-supplied headers (X-Forwarded-For,
// X-Forwarded-Host, X-Forwarded-Proto, X-Real-IP) should be honored for this
// request under the configured trust settings.
func TrustsProxyHeaders(r *http.Request) bool {
	cfg := currentProxyTrust.Load()
	switch cfg.trustProxyHeaders {
	case "true":
		return true
	case "false":
		return false
	default: // "auto"
		remoteIP := ExtractIP(r.RemoteAddr)
		return IsTrustedProxyIP(remoteIP, cfg.trustedProxyIPs)
	}
}
