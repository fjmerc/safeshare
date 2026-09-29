package utils

import (
	"net/http"
	"net/netip"
	"sync/atomic"

	"github.com/fjmerc/safeshare/internal/proxytrust"
)

// proxyTrustConfig holds the process-wide proxy trust settings, configured
// once at startup from the loaded config. Helpers that have no access to
// *config.Config (middleware, handler shortcuts) read from here instead of
// hardcoding trust values.
type proxyTrustConfig struct {
	trustProxyHeaders string
	trustedProxyIPs   string
	anonymousMode     bool
}

// Defaults match config defaults: "auto" mode with loopback + RFC1918 proxies.
var currentProxyTrust atomic.Pointer[proxyTrustConfig]

func init() {
	currentProxyTrust.Store(&proxyTrustConfig{
		trustProxyHeaders: "auto",
		trustedProxyIPs:   "127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
		anonymousMode:     false,
	})
}

// ConfigureClientIPTrust sets the process-wide proxy trust settings.
// Call once at startup after loading config, before serving requests.
func ConfigureClientIPTrust(trustProxyHeaders, trustedProxyIPs string, anonymousMode bool) {
	currentProxyTrust.Store(&proxyTrustConfig{
		trustProxyHeaders: trustProxyHeaders,
		trustedProxyIPs:   trustedProxyIPs,
		anonymousMode:     anonymousMode,
	})
}

// GetClientIP extracts the client IP using the configured proxy trust settings.
func GetClientIP(r *http.Request) string {
	cfg := currentProxyTrust.Load()
	return GetClientIPWithTrust(r, cfg.trustProxyHeaders, cfg.trustedProxyIPs, cfg.anonymousMode)
}

// currentRateLimitIPv6Prefix holds the process-wide IPv6 rate-limit grouping
// width (RATE_LIMIT_IPV6_PREFIX), configured once at startup via
// ConfigureRateLimitIPv6Prefix. Defaults to /64 so tests and any caller that
// never installs one still get sane grouping instead of ungrouped
// per-address IPv6 buckets (T43).
var currentRateLimitIPv6Prefix atomic.Int64

func init() {
	currentRateLimitIPv6Prefix.Store(proxytrust.DefaultRateLimitIPv6PrefixBits)
}

// ConfigureRateLimitIPv6Prefix sets the process-wide IPv6 rate-limit
// grouping width used by RateLimitKey. Call once at startup after loading
// config, before serving requests. bits should already be validated to
// [MinRateLimitIPv6PrefixBits, MaxRateLimitIPv6PrefixBits] by
// internal/config; an out-of-range value here is simply clamped by
// proxytrust.RateLimitGroupKey's own bounds handling rather than panicking.
func ConfigureRateLimitIPv6Prefix(bits int) {
	currentRateLimitIPv6Prefix.Store(int64(bits))
}

// RateLimitKey returns the per-client grouping key used for rate limiting
// and concurrency caps (upload/download rate limits, login attempt limits,
// in-flight download/decrypt caps): ipStr unchanged for IPv4 (or an
// unparsable value), and its configured-width IPv6 prefix
// (RATE_LIMIT_IPV6_PREFIX, default /64) for IPv6 -- see
// proxytrust.RateLimitGroupKey. This is the single shared implementation
// every per-IP limiter in the codebase uses (T43); callers that also need
// to log or store the full client IP (audit logs, uploader_ip, etc.) must
// keep using the un-grouped value returned by GetClientIPWithTrust/
// GetClientIP for that -- RateLimitKey is only for limiter bucket keys.
func RateLimitKey(ipStr string) string {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return ipStr
	}
	bits := int(currentRateLimitIPv6Prefix.Load())
	return proxytrust.RateLimitGroupKey(proxytrust.NormalizeAddr(addr), bits)
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
