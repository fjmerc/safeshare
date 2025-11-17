package utils

import (
	"net"
	"net/http"
	"strings"
)

// IsTrustedProxyIP checks if the given IP address is in the trusted proxy list.
// trustedProxies is a comma-separated string of IPs and CIDR ranges.
// Examples: "127.0.0.1,192.168.1.0/24" or "10.0.0.0/8"
func IsTrustedProxyIP(ipStr string, trustedProxies string) bool {
	// Parse the IP address
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	// Split the trusted proxies list
	proxies := strings.Split(trustedProxies, ",")
	for _, proxy := range proxies {
		proxy = strings.TrimSpace(proxy)
		if proxy == "" {
			continue
		}

		// Check if it's a CIDR range
		if strings.Contains(proxy, "/") {
			if ipInCIDR(ip, proxy) {
				return true
			}
		} else {
			// It's a single IP
			proxyIP := net.ParseIP(proxy)
			if proxyIP != nil && ip.Equal(proxyIP) {
				return true
			}
		}
	}

	return false
}

// ipInCIDR checks if an IP is within a CIDR range
func ipInCIDR(ip net.IP, cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(ip)
}

// ExtractIP extracts the IP address from a "host:port" string.
// If no port is present, returns the input as-is.
// Returns empty string if input is invalid.
func ExtractIP(addr string) string {
	// Handle IPv6 addresses with port: [::1]:8080
	if strings.HasPrefix(addr, "[") {
		if idx := strings.LastIndex(addr, "]:"); idx != -1 {
			return addr[1:idx]
		}
		// Just [::1] without port
		return strings.Trim(addr, "[]")
	}

	// Handle IPv4 addresses with port: 1.2.3.4:8080
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		// Check if this is an IPv6 address without brackets
		if strings.Count(addr, ":") > 1 {
			// Multiple colons = IPv6 without port
			return addr
		}
		// Single colon = IPv4:port
		return addr[:idx]
	}

	// No port, return as-is
	return addr
}

// GetClientIPWithTrust extracts the client IP from the request with trusted proxy validation.
// trustProxyHeaders: "auto", "true", "false" - controls whether to trust proxy headers
// trustedProxyIPs: comma-separated list of trusted proxy IPs/CIDR ranges
func GetClientIPWithTrust(r *http.Request, trustProxyHeaders string, trustedProxyIPs string) string {
	// Extract IP from RemoteAddr (the immediate connection source)
	remoteIP := ExtractIP(r.RemoteAddr)

	// Determine if we should trust proxy headers
	shouldTrust := false

	switch trustProxyHeaders {
	case "true":
		// Always trust proxy headers
		shouldTrust = true
	case "false":
		// Never trust proxy headers
		shouldTrust = false
	case "auto":
		// Trust only if request comes from a trusted proxy IP
		shouldTrust = IsTrustedProxyIP(remoteIP, trustedProxyIPs)
	default:
		// Default to auto mode for safety
		shouldTrust = IsTrustedProxyIP(remoteIP, trustedProxyIPs)
	}

	// If we shouldn't trust proxy headers, return RemoteAddr directly
	if !shouldTrust {
		return remoteIP
	}

	// Trust proxy headers - check X-Forwarded-For first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain (the original client)
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return remoteIP
}
