// Package proxytrust parses and represents the TRUSTED_PROXY_IPS
// configuration value: a comma-separated list of bare IPs, CIDR ranges, and
// the "cloudflare" keyword.
//
// It intentionally has no dependency on any other SafeShare internal
// package. internal/config (which validates TRUSTED_PROXY_IPS at startup)
// and internal/utils (which enforces it at request time) both need this
// logic, but internal/config indirectly imports internal/utils elsewhere
// (config -> backup -> utils), so internal/utils itself cannot be imported
// from internal/config without an import cycle. This leaf package is the
// shared dependency both sides can use instead (T41).
package proxytrust

import (
	"fmt"
	"net/netip"
	"strings"
)

// CloudflareKeyword is the TRUSTED_PROXY_IPS list entry that expands to
// Cloudflare's published edge IP ranges. It is never included in a default
// trust list: Cloudflare Workers (and other Cloudflare products) can
// originate requests from the same ranges as the edge network, so trusting
// them must be an explicit, informed operator choice (see
// docs/REVERSE_PROXY.md).
const CloudflareKeyword = "cloudflare"

// CloudflareIPv4Ranges and CloudflareIPv6Ranges are Cloudflare's published
// edge IP ranges, hardcoded from https://www.cloudflare.com/ips-v4 and
// https://www.cloudflare.com/ips-v6 as verified 2026-09-29. Cloudflare
// updates this list infrequently, but operators relying on the "cloudflare"
// keyword in TRUSTED_PROXY_IPS should periodically diff it against the live
// list and update this file if it changes.
var CloudflareIPv4Ranges = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

var CloudflareIPv6Ranges = []string{
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

// NormalizeAddr unmaps IPv4-mapped IPv6 addresses (::ffff:a.b.c.d ->
// a.b.c.d) and drops any zone identifier, so the same client always
// normalizes to the same address regardless of how it was represented on
// the wire. Callers (rate limiting, IP blocking) use the result as a map
// key, so it must be stable.
func NormalizeAddr(addr netip.Addr) netip.Addr {
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	return addr
}

// NormalizePrefix unmaps an IPv4-mapped IPv6 prefix (e.g. "::ffff:10.0.0.0/104")
// down to its equivalent plain-IPv4 prefix ("10.0.0.0/8"), adjusting the
// prefix length to account for the 96 fixed bits of the "::ffff:" preamble.
// A mapped prefix shorter than /96 doesn't correspond to any coherent IPv4
// range (part of the fixed "::ffff:" preamble itself would be variable), so
// that's rejected as a configuration error rather than silently producing a
// prefix that matches nothing (bug-hunter finding, T41 follow-up).
//
// Exported (T43) so internal/ipcanon can apply the same CIDR normalization
// to IP-blocklist entries that ParseListSplit applies to TRUSTED_PROXY_IPS
// entries, instead of duplicating this logic.
func NormalizePrefix(p netip.Prefix) (netip.Prefix, error) {
	addr := p.Addr()
	bits := p.Bits()
	if addr.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, fmt.Errorf("IPv4-mapped IPv6 prefix %s has fewer than 96 significant bits, which does not correspond to a valid IPv4 range", p)
		}
		addr = addr.Unmap()
		bits -= 96
	}
	if addr.Zone() != "" {
		addr = addr.WithZone("")
	}
	return netip.PrefixFrom(addr, bits), nil
}

// ParseListSplit parses a comma-separated TRUSTED_PROXY_IPS value into two
// separate prefix lists: local (operator-listed bare IPs and CIDRs) and
// cloudflare (populated only when the "cloudflare" keyword is present, with
// Cloudflare's published edge ranges). Keeping the two sets separate lets
// callers apply different trust rules to each -- in particular, at most one
// hop of an X-Forwarded-For chain may ever be attributed to Cloudflare,
// while an operator's own local proxy chain may skip any number of hops
// (see internal/utils.GetClientIPWithTrust and docs/REVERSE_PROXY.md).
//
// Each entry is either:
//   - a bare IP address (widened to a host prefix: /32 for IPv4, /128 for IPv6)
//   - a CIDR range (e.g. "10.0.0.0/8")
//   - the literal keyword "cloudflare" (case-insensitive)
//
// Empty entries (from stray commas/whitespace) are skipped. Any other entry
// that fails to parse as an IP or CIDR is a configuration error.
func ParseListSplit(trustedProxyIPs string) (local, cloudflare []netip.Prefix, err error) {
	for _, raw := range strings.Split(trustedProxyIPs, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}

		if strings.EqualFold(entry, CloudflareKeyword) {
			for _, cidr := range CloudflareIPv4Ranges {
				cloudflare = append(cloudflare, netip.MustParsePrefix(cidr))
			}
			for _, cidr := range CloudflareIPv6Ranges {
				cloudflare = append(cloudflare, netip.MustParsePrefix(cidr))
			}
			continue
		}

		if strings.Contains(entry, "/") {
			p, perr := netip.ParsePrefix(entry)
			if perr != nil {
				return nil, nil, fmt.Errorf("invalid CIDR %q: %w", entry, perr)
			}
			np, nerr := NormalizePrefix(p)
			if nerr != nil {
				return nil, nil, fmt.Errorf("invalid CIDR %q: %w", entry, nerr)
			}
			local = append(local, np)
			continue
		}

		addr, aerr := netip.ParseAddr(entry)
		if aerr != nil {
			return nil, nil, fmt.Errorf("invalid IP %q: %w", entry, aerr)
		}
		addr = NormalizeAddr(addr)
		local = append(local, netip.PrefixFrom(addr, addr.BitLen()))
	}
	return local, cloudflare, nil
}

// ParseList parses trustedProxyIPs the same way as ParseListSplit, but
// returns a single combined list. Prefer ParseListSplit for anything that
// needs to distinguish an operator's own trusted infrastructure from
// Cloudflare's edge network; this combined form is for callers that only
// need a yes/no "is this IP trusted at all" answer (e.g. IsTrustedProxyIP).
func ParseList(trustedProxyIPs string) ([]netip.Prefix, error) {
	local, cloudflare, err := ParseListSplit(trustedProxyIPs)
	if err != nil {
		return nil, err
	}
	return append(local, cloudflare...), nil
}

// Trusted reports whether addr (already normalized via NormalizeAddr) falls
// within any of the given prefixes.
func Trusted(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// PrefixContains reports whether a fully contains b -- i.e. every address in
// b is also in a, including the case a == b. Two CIDR prefixes never
// partially overlap (that's a property of the address space being a binary
// trie): if they overlap at all, one is always a full subset of the other,
// so combined with a simple Overlaps() check, this is enough to tell "a is
// the broader/equal one" apart from "b is the broader one" (T43 code-review
// follow-up: used by the admin IP-blocklist's self-lockout check to
// distinguish blocking a trusted range/host outright from merely blocking
// an address that happens to sit inside a broader trusted range).
//
// a and b should both already be masked (e.g. via Prefix.Masked(), which
// every caller in this codebase already applies before storing or comparing
// a prefix). Prefixes of different address families never contain each
// other.
func PrefixContains(a, b netip.Prefix) bool {
	if a.Addr().Is4() != b.Addr().Is4() {
		return false
	}
	return a.Bits() <= b.Bits() && a.Contains(b.Addr())
}

// DefaultRateLimitIPv6PrefixBits is the width of the IPv6 prefix
// RateLimitGroupKey groups clients by when no operator-configured value is
// available (RATE_LIMIT_IPV6_PREFIX default; T43).
const DefaultRateLimitIPv6PrefixBits = 64

// MinRateLimitIPv6PrefixBits and MaxRateLimitIPv6PrefixBits bound the valid
// range for RATE_LIMIT_IPV6_PREFIX. The lower bound (48) keeps a single
// configured value from grouping an implausibly large swath of distinct
// customers/allocations (a /48 is already a full standard end-site
// allocation) into one rate-limit bucket; 128 (the upper bound) means
// per-address, i.e. the same behavior as pre-T43 IPv6 handling.
const (
	MinRateLimitIPv6PrefixBits = 48
	MaxRateLimitIPv6PrefixBits = 128
)

// RateLimitGroupKey returns the key used to group a client address for
// per-client rate limiting and concurrency caps (login attempt limits,
// upload/download rate limits, in-flight download/decrypt caps): the full
// address for IPv4, and addr's leading ipv6PrefixBits-bit prefix for IPv6 --
// so a client that legitimately rotates addresses within one allocation
// (routine for many residential/mobile IPv6 networks) is grouped as the one
// client it actually is, instead of getting a fresh limiter bucket per
// address (T43). ipv6PrefixBits == 128 (or any value >= 128) disables
// grouping and returns the full address, matching plain per-address IPv4
// behavior.
//
// addr should already be normalized via NormalizeAddr. An invalid
// (zero-value) addr returns its own (empty) String().
func RateLimitGroupKey(addr netip.Addr, ipv6PrefixBits int) string {
	if !addr.IsValid() || addr.Is4() || ipv6PrefixBits >= MaxRateLimitIPv6PrefixBits {
		return addr.String()
	}
	if ipv6PrefixBits < 0 {
		ipv6PrefixBits = DefaultRateLimitIPv6PrefixBits
	}
	prefix, err := addr.Prefix(ipv6PrefixBits)
	if err != nil {
		return addr.String()
	}
	return prefix.Addr().String()
}
