package webhooks

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// allowPrivateNetworks gates whether webhook deliveries may target private,
// loopback, link-local, or other internal IP ranges. Disabled by default to
// prevent SSRF (cloud-metadata reads, internal admin endpoint hits, LAN
// scanning). The value is set at startup from cfg.AllowPrivateWebhookTargets
// (env WEBHOOK_ALLOW_PRIVATE_TARGETS) — see SetAllowPrivateNetworks. The
// atomic avoids a mutex in the hot dial path.
var allowPrivateNetworks atomic.Bool

// SetAllowPrivateNetworks toggles the private-IP guard. Called once from
// main during startup with cfg.AllowPrivateWebhookTargets. Tests use it to
// flip behaviour inside individual cases. Returns the prior value so callers
// can restore via defer.
func SetAllowPrivateNetworks(allow bool) bool {
	return allowPrivateNetworks.Swap(allow)
}

// ErrBlockedTarget is returned when a webhook URL or dial target resolves to a
// disallowed IP or hostname.
var ErrBlockedTarget = errors.New("webhook target resolves to a blocked address (private, loopback, link-local, or metadata IP)")

// CGNAT range per RFC 6598. Not covered by net.IP.IsPrivate (stdlib).
var cgnatNet = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// IPv6 NAT64 well-known prefix per RFC 6052.
var nat64Net = &net.IPNet{IP: net.ParseIP("64:ff9b::"), Mask: net.CIDRMask(96, 128)}

// Hostname suffixes that resolve to internal infrastructure on common
// deployments. Match is case-insensitive on a trailing label boundary.
var blockedHostSuffixes = []string{
	".localhost",
	".local",
	".internal",
	".intranet",
	".lan",
	".home",
	".corp",
	".home.arpa",
}

// blockedHostExact is matched exactly (post-lowercase).
var blockedHostExact = []string{
	"localhost",
	"localhost.",
	"ip6-localhost",
	"ip6-loopback",
}

// IsBlockedIP reports whether the given IP belongs to a range we refuse to
// reach from server-side webhook delivery. Covers RFC 1918, loopback, link-
// local, multicast, broadcast, unspecified, CGNAT, NAT64, and the IPv6 ULA
// prefix. Cloud instance-metadata IPs (169.254.169.254, fd00:ec2::254) fall
// out of the link-local check naturally.
func IsBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	// Normalize IPv4-mapped IPv6 (::ffff:a.b.c.d) so RFC-1918 checks fire on the
	// embedded v4 address, not the v6 wrapper.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsPrivate() {
		return true
	}
	// 255.255.255.255 (and 0.0.0.0 — already caught by IsUnspecified)
	if ip.Equal(net.IPv4bcast) {
		return true
	}
	if cgnatNet.Contains(ip) {
		return true
	}
	if nat64Net.Contains(ip) {
		return true
	}
	return false
}

// isBlockedHostname returns true if the hostname (sans port) is a localhost-
// alias or carries a suffix used by common internal name spaces.
func isBlockedHostname(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return true
	}
	for _, exact := range blockedHostExact {
		if host == strings.TrimSuffix(exact, ".") {
			return true
		}
	}
	for _, suffix := range blockedHostSuffixes {
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}
	return false
}

// ValidateWebhookURL parses rawURL and verifies the scheme is http/https, a
// host is present, the hostname is not a localhost alias, and (when the host
// is an IP literal or resolves) no resolved IP is blocked.
//
// Should be called from admin webhook create/update handlers. Defense-in-depth
// against config-time misuse; the safe dialer applies the same check at
// connect time to defeat DNS rebinding.
func ValidateWebhookURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return errors.New("only http and https schemes are allowed")
	}
	host := parsed.Hostname()
	if host == "" {
		return errors.New("URL must include a hostname")
	}
	// Reject any IPv6 zone-ID form (fe80::1%eth0). Go's url.Hostname returns
	// the zone-suffixed string and net.ParseIP rejects it, which would
	// otherwise route us into the DNS branch and rely on resolver behaviour
	// to reject the target. No legitimate webhook destination needs a zone
	// ID, so refuse outright.
	if strings.ContainsAny(host, "%") {
		return ErrBlockedTarget
	}
	if allowPrivateNetworks.Load() {
		return nil
	}
	if isBlockedHostname(host) {
		return ErrBlockedTarget
	}
	// IP-literal hostnames: check directly without DNS.
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return ErrBlockedTarget
		}
		return nil
	}
	// Hostname: resolve and reject if any A/AAAA record is blocked. Use a short
	// timeout so a slow DNS doesn't hang the admin request.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return fmt.Errorf("hostname lookup failed: %w", err)
	}
	for _, a := range addrs {
		if IsBlockedIP(a.IP) {
			return ErrBlockedTarget
		}
	}
	return nil
}

// safeDialContext is the DialContext for the webhook http.Transport. It
// resolves the target, rejects blocked IPs, and then dials the chosen IP
// directly — pinning the resolved address so a TTL-1 DNS-rebinding response
// cannot redirect us between this check and the connect syscall.
func safeDialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid dial address %q: %w", address, err)
	}
	// Refuse IPv6 zone-ID literals at the dial step too — symmetric with
	// ValidateWebhookURL. See comment there.
	if strings.ContainsAny(host, "%") {
		return nil, ErrBlockedTarget
	}
	if !allowPrivateNetworks.Load() && isBlockedHostname(host) {
		return nil, ErrBlockedTarget
	}

	var ips []net.IP
	if ip := net.ParseIP(host); ip != nil {
		ips = []net.IP{ip}
	} else {
		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("dial lookup failed: %w", err)
		}
		ips = make([]net.IP, 0, len(addrs))
		for _, a := range addrs {
			ips = append(ips, a.IP)
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no addresses resolved for %q", host)
	}

	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	allowPrivate := allowPrivateNetworks.Load()
	var lastErr error
	for _, ip := range ips {
		if !allowPrivate && IsBlockedIP(ip) {
			lastErr = ErrBlockedTarget
			continue
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = ErrBlockedTarget
	}
	return nil, lastErr
}

// safeCheckRedirect applies the same target validation on every redirect hop,
// preventing an attacker-controlled target from 302'ing us to an internal
// address.
func safeCheckRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return errors.New("too many webhook redirects")
	}
	if err := ValidateWebhookURL(req.URL.String()); err != nil {
		return fmt.Errorf("redirect to blocked target: %w", err)
	}
	return nil
}

// Sensitive-data patterns to redact from webhook response bodies before
// storage. Webhook targets may return their auth headers in echoes, error
// payloads, or upstream API responses; we don't want to mirror credentials
// into the SafeShare admin UI's delivery history.
var (
	bearerPattern  = regexp.MustCompile(`(?i)(bearer\s+)[A-Za-z0-9._\-]+`)
	apiKeyPattern  = regexp.MustCompile(`(?i)("?(?:api[_-]?key|access[_-]?token|secret[_-]?(?:access[_-]?)?key|password|x-[a-z-]*-(?:token|key))"?\s*[:=]\s*"?)[^"\s,}]+`)
	awsAKIDPattern = regexp.MustCompile(`(?i)(AKIA|ASIA)[0-9A-Z]{16}`)
	jwtPattern     = regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}`)
)

// redactSensitiveResponseBody scrubs common credential patterns from the body
// before it is persisted to the webhook_deliveries table.
func redactSensitiveResponseBody(body string) string {
	body = bearerPattern.ReplaceAllString(body, "${1}[REDACTED]")
	body = apiKeyPattern.ReplaceAllString(body, "${1}[REDACTED]")
	body = awsAKIDPattern.ReplaceAllString(body, "[REDACTED-AWS-KEY]")
	body = jwtPattern.ReplaceAllString(body, "[REDACTED-JWT]")
	return body
}
