package utils

import (
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/fjmerc/safeshare/internal/privacy"
	"github.com/fjmerc/safeshare/internal/proxytrust"
)

// ParseTrustedProxyList parses a comma-separated TRUSTED_PROXY_IPS value.
// See internal/proxytrust.ParseList for the accepted syntax (bare IPs,
// CIDRs, and the "cloudflare" keyword). Re-exported here so config
// validation and request-time trust checks share one parser without
// internal/config having to import internal/utils, which would create an
// import cycle (internal/utils -> internal/backup -> internal/config).
func ParseTrustedProxyList(trustedProxyIPs string) ([]netip.Prefix, error) {
	return proxytrust.ParseList(trustedProxyIPs)
}

// trustedProxySet is the parsed, cacheable form of a TRUSTED_PROXY_IPS
// value: the operator's own local/regional trust list, and (only when the
// "cloudflare" keyword is present) Cloudflare's published edge ranges, kept
// separate. See GetClientIPWithTrust for why the split matters.
type trustedProxySet struct {
	local      []netip.Prefix
	cloudflare []netip.Prefix
}

func (s trustedProxySet) combined() []netip.Prefix {
	if len(s.cloudflare) == 0 {
		return s.local
	}
	all := make([]netip.Prefix, 0, len(s.local)+len(s.cloudflare))
	all = append(all, s.local...)
	all = append(all, s.cloudflare...)
	return all
}

// trustedProxyCache memoizes the parsed prefix sets for each distinct
// TRUSTED_PROXY_IPS string value, so the CIDR/IP list is parsed once rather
// than on every request. TRUSTED_PROXY_IPS is operator-configured at startup
// and not user input, so the small, effectively-bounded set of distinct
// values seen in a process lifetime makes this cache safe to grow
// unbounded for the life of the process.
var trustedProxyCache sync.Map // string -> trustedProxySet

// cachedTrustedProxySet returns the parsed local/cloudflare prefix sets for
// trustedProxyIPs, parsing and caching them on first use. A value that fails
// to parse (should already have been rejected by config validation at
// startup) degrades to an empty trust list rather than panicking or
// trusting everything.
func cachedTrustedProxySet(trustedProxyIPs string) trustedProxySet {
	if v, ok := trustedProxyCache.Load(trustedProxyIPs); ok {
		return v.(trustedProxySet)
	}
	local, cloudflare, err := proxytrust.ParseListSplit(trustedProxyIPs)
	if err != nil {
		slog.Warn("invalid TRUSTED_PROXY_IPS ignored at runtime; trusting no proxies",
			"error", err,
		)
		local, cloudflare = nil, nil
	}
	set := trustedProxySet{local: local, cloudflare: cloudflare}
	actual, _ := trustedProxyCache.LoadOrStore(trustedProxyIPs, set)
	return actual.(trustedProxySet)
}

// cachedTrustedProxyPrefixes returns the combined (local + cloudflare)
// parsed prefixes for trustedProxyIPs. Used by callers that only need a
// yes/no "is this IP trusted at all" answer.
func cachedTrustedProxyPrefixes(trustedProxyIPs string) []netip.Prefix {
	return cachedTrustedProxySet(trustedProxyIPs).combined()
}

// IsTrustedProxyIP checks if the given IP address is in the trusted proxy
// list. trustedProxies is a comma-separated string of IPs, CIDR ranges, and
// optionally the "cloudflare" keyword (see ParseTrustedProxyList).
func IsTrustedProxyIP(ipStr string, trustedProxies string) bool {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	return proxytrust.Trusted(proxytrust.NormalizeAddr(addr), cachedTrustedProxyPrefixes(trustedProxies))
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

// parseForwardedEntry parses a single X-Forwarded-For hop. It accepts a bare
// IPv4/IPv6 address, "v4:port", or "[v6]:port" (some proxies append a port;
// the standard header does not carry one, but we normalize it away when
// present rather than treating it as garbage). Anything else -- empty,
// "unknown", or text that isn't a valid IP once a legitimate port/bracket
// wrapper is stripped -- is reported as invalid so the walk can stop safely.
func parseForwardedEntry(raw string) (netip.Addr, bool) {
	entry := strings.TrimSpace(raw)
	if entry == "" || strings.EqualFold(entry, "unknown") {
		return netip.Addr{}, false
	}
	host := ExtractIP(entry)
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return proxytrust.NormalizeAddr(addr), true
}

// ffCursor walks X-Forwarded-For hops from right (closest to us) to left
// (most client-ward) directly over the raw header line(s), without ever
// materializing a slice of every hop. A single very long header (an
// attacker can send megabytes of comma-separated garbage) would otherwise
// cost an allocation proportional to the hop count on every request; this
// cursor does zero-copy string slicing and O(1) extra allocation regardless
// of input size (bug-hunter finding, T41 follow-up).
//
// RFC 7230 treats repeated header fields with the same name as equivalent
// to one field with their values joined by commas, in the order the fields
// appear -- so a proxy chain that emits two separate "X-Forwarded-For:"
// lines is handled the same as one line with both chains comma-joined: the
// cursor exhausts lines[last] before moving on to lines[last-1], etc.
type ffCursor struct {
	lines []string
	li    int // index of the line currently being scanned; -1 once exhausted
	end   int // exclusive end offset within lines[li] still unscanned
}

func newFFCursor(lines []string) ffCursor {
	if len(lines) == 0 {
		return ffCursor{li: -1}
	}
	return ffCursor{lines: lines, li: len(lines) - 1, end: len(lines[len(lines)-1])}
}

// next returns the next hop (raw, untrimmed) walking right to left, or
// ok=false once every line is exhausted. It never copies the underlying
// header bytes -- each returned string is a slice into the original header
// value -- and each byte of the input is examined by at most one
// strings.LastIndexByte scan across the whole walk, so total work is O(n)
// in the combined header length regardless of hop count or distribution.
func (c *ffCursor) next() (string, bool) {
	for c.li >= 0 {
		line := c.lines[c.li]
		if c.end == 0 {
			// Nothing left on this line (it started with a comma, e.g.
			// ",1.2.3.4", or was empty). Move to the previous line.
			c.li--
			if c.li >= 0 {
				c.end = len(c.lines[c.li])
			}
			continue
		}
		segment := line[:c.end]
		idx := strings.LastIndexByte(segment, ',')
		if idx == -1 {
			// First (leftmost) hop on this line.
			hop := segment
			c.li--
			if c.li >= 0 {
				c.end = len(c.lines[c.li])
			}
			return hop, true
		}
		hop := segment[idx+1:]
		c.end = idx
		return hop, true
	}
	return "", false
}

// maxForwardedForHops bounds how many X-Forwarded-For hops a single request
// walk will consider. A real reverse-proxy chain is a handful of hops at
// most; anything beyond this is never legitimate and is treated the same as
// a malformed entry (see walkForwardedFor) rather than being walked in
// full -- this bounds per-request work against a maliciously long header
// regardless of its size (bug-hunter finding, T41 follow-up).
const maxForwardedForHops = 32

// walkForwardedFor implements the rightmost-untrusted-hop algorithm over
// cur: the entries closest to us (rightmost) were appended by proxies we
// trust, so we skip them and return the first entry, walking right to left,
// that is NOT itself a trusted proxy. That is the closest thing to the real
// client this hop of the chain can vouch for.
//
// local and cloudflare are kept as separate trust sets, and treated
// asymmetrically:
//
//   - local (operator-listed) entries may be skipped without limit, since
//     the operator vouches for every hop in their own infrastructure.
//   - AT MOST ONE cloudflare-range entry may ever be skipped as a hop
//     (tracked by cfBudget, which the caller sets to 0 if RemoteAddr itself
//     was already a Cloudflare address -- see GetClientIPWithTrust). This
//     matters because Cloudflare Workers (and other Cloudflare products)
//     can themselves originate requests from inside Cloudflare's published
//     ranges: if we kept skipping every consecutive Cloudflare-looking
//     entry the way we skip local ones, a Worker could inject an
//     attacker-chosen leftmost entry, have Cloudflare append the Worker's
//     own (also Cloudflare-range) egress IP, and have both entries skipped
//     as "trusted proxy hops" -- reopening exactly the spoof T41 fixed.
//   - Once the single Cloudflare hop has been consumed, the walk stops
//     trusting anything further: the very next entry is returned as the
//     client unconditionally, even if it also happens to fall in a
//     Cloudflare or local trusted range. Cloudflare's edge only ever
//     vouches for the one peer it saw; anything beyond that boundary is
//     data Cloudflare relayed, not infrastructure we control. In practice
//     this means a Cloudflare Worker's request is attributed to the
//     Worker's own egress IP -- indistinguishable from a single client, so
//     multiple Workers behind the same egress share a fail-closed rate
//     limit/IP-block bucket rather than any one of them being able to pick
//     an arbitrary identity.
//
// ok is false when no usable IP could be determined at all -- either the
// rightmost entry itself is malformed, the chain exceeds
// maxForwardedForHops, or the list is empty. When a malformed entry (or the
// hop cap) is hit after one or more trusted hops were already walked, the
// safe choice is to return the last (i.e. outermost / closest to us)
// trusted hop rather than guessing at what lies beyond it -- that exposes a
// known proxy IP instead of an attacker-controlled value.
//
// cfConsumed reports whether a Cloudflare-range entry was ever skipped as a
// hop during this walk, and cfHop is that entry's address (the zero
// netip.Addr if cfConsumed is false). The caller uses this to decide
// whether the result needs to pass the CF-Connecting-IP veto, and what to
// fall back to if it doesn't (see GetClientIPWithTrust /
// applyCFConnectingIPVeto).
func walkForwardedFor(cur ffCursor, local, cloudflare []netip.Prefix, cfBudget int) (result string, ok bool, cfHop netip.Addr, cfConsumed bool) {
	var lastTrusted netip.Addr
	haveLastTrusted := false
	hops := 0

	for {
		raw, more := cur.next()
		if !more {
			break
		}
		hops++
		if hops > maxForwardedForHops {
			if haveLastTrusted {
				return lastTrusted.String(), true, cfHop, cfConsumed
			}
			return "", false, netip.Addr{}, false
		}

		addr, valid := parseForwardedEntry(raw)
		if !valid {
			if haveLastTrusted {
				return lastTrusted.String(), true, cfHop, cfConsumed
			}
			return "", false, netip.Addr{}, false
		}

		if cfConsumed {
			// The Cloudflare trust boundary was already crossed: this entry
			// is the client, full stop, regardless of what range it's in.
			return addr.String(), true, cfHop, cfConsumed
		}

		if proxytrust.Trusted(addr, local) {
			lastTrusted = addr
			haveLastTrusted = true
			continue
		}

		if cfBudget > 0 && proxytrust.Trusted(addr, cloudflare) {
			cfBudget--
			cfConsumed = true
			cfHop = addr
			lastTrusted = addr
			haveLastTrusted = true
			continue
		}

		// First entry walking from the right that isn't skippable: this is
		// the client IP the chain's outermost trusted hop vouches for.
		return addr.String(), true, cfHop, cfConsumed
	}

	// Walked off the left end without finding an unskippable entry: every
	// hop in the chain was itself trusted (and, if a Cloudflare hop was
	// involved, it was the very last entry with nothing further left).
	// lastTrusted holds the leftmost entry (the last one processed), which
	// is the best available answer -- see GetClientIPWithTrust's doc
	// comment for why this is safe.
	if haveLastTrusted {
		return lastTrusted.String(), true, cfHop, cfConsumed
	}
	return "", false, netip.Addr{}, false
}

// GetClientIPWithTrust extracts the client IP from the request with trusted
// proxy validation.
//
// trustProxyHeaders: "auto" (trust only when RemoteAddr matches
// trustedProxyIPs), "true" (always trust headers, regardless of RemoteAddr),
// or "false" (never trust headers). Any other value is treated as "auto".
//
// trustedProxyIPs: comma-separated list of trusted proxy IPs/CIDR ranges,
// optionally including the "cloudflare" keyword (see ParseTrustedProxyList).
//
// When headers are trusted, the client IP is determined by walking
// X-Forwarded-For from the right and skipping entries that are themselves
// trusted proxies (see walkForwardedFor) -- never by taking the leftmost,
// client-controlled entry. X-Real-IP is consulted only when X-Forwarded-For
// is entirely absent. The returned string is normalized (IPv4-mapped IPv6
// unmapped, zone dropped) so it is stable for use as a map/rate-limit key.
//
// Cloudflare hop budget: if the "cloudflare" keyword is configured, at most
// one hop in the walk may be attributed to Cloudflare's edge network (see
// walkForwardedFor). If RemoteAddr itself already falls in a Cloudflare
// range -- i.e. SafeShare sits directly behind Cloudflare with no local
// reverse proxy in between -- that budget is considered already spent by
// the direct connection, so no further entry in X-Forwarded-For can be
// skipped as "the Cloudflare hop" either.
//
// CF-Connecting-IP veto: the hop budget alone doesn't close every topology.
// With Cloudflare Tunnel, the entry SafeShare's own reverse proxy appends
// represents the tunnel daemon's own local address (not a published
// Cloudflare range), so the walk can still land on an attacker-forged entry
// past a Worker's own Cloudflare-range egress hop. And when a Worker
// connects to the origin directly -- bypassing Cloudflare's actual
// edge/proxy layer -- RemoteAddr itself is a Cloudflare-range address with
// no local reverse proxy in front at all, including when the only signal is
// X-Real-IP. So whenever the result depends on trusting Cloudflare (a
// Cloudflare hop was consumed in the walk, or RemoteAddr's own hop budget
// was pre-spent), the candidate is only accepted if it matches the
// CF-Connecting-IP header Cloudflare's real edge/proxy layer sets -- see
// applyCFConnectingIPVeto for the exact rule and its residual limits.
//
// When every trust-list entry is local (no Cloudflare hop was ever
// consumed) and the entire chain turns out to be trusted, the leftmost
// entry is returned, matching long-standing behavior for a fully-internal
// request chain (e.g. an internal health checker routed through several of
// the operator's own load balancers). This is intentionally NOT changed by
// the Cloudflare fix: reaching this branch already requires RemoteAddr (the
// literal TCP peer, unspoofable) to itself be inside the operator's chosen
// TRUSTED_PROXY_IPS, and every hop in between to also match that
// operator-chosen list -- the residual risk here is entirely a function of
// how broad the operator made TRUSTED_PROXY_IPS, not of this algorithm
// (operators should keep it as narrow as their actual proxy topology
// requires; see docs/REVERSE_PROXY.md).
//
// anonymousMode controls whether the IP is redacted in the debug log emitted
// when a trusted peer sends no usable forwarded header, or when the
// CF-Connecting-IP veto fires.
func GetClientIPWithTrust(r *http.Request, trustProxyHeaders string, trustedProxyIPs string, anonymousMode bool) string {
	remoteIP := ExtractIP(r.RemoteAddr)
	remoteNorm := normalizeIPString(remoteIP)
	set := cachedTrustedProxySet(trustedProxyIPs)

	var shouldTrust bool
	switch trustProxyHeaders {
	case "true":
		// Always trust proxy headers -- but still via the rightmost-untrusted
		// walk below, never the leftmost (client-controlled) entry.
		shouldTrust = true
	case "false":
		shouldTrust = false
	default: // "auto" and any unrecognized value default to auto for safety
		remoteAddr := parseAddrOrZero(remoteIP)
		shouldTrust = proxytrust.Trusted(remoteAddr, set.local) || proxytrust.Trusted(remoteAddr, set.cloudflare)
	}

	if !shouldTrust {
		return remoteNorm
	}

	// dependsOnCF and cfHopFallback track whether the eventual candidate
	// relies on trusting Cloudflare, and what to fall back to if the
	// CF-Connecting-IP veto rejects it (see applyCFConnectingIPVeto).
	dependsOnCF := false
	cfHopFallback := ""

	cfBudget := 1
	if len(set.cloudflare) > 0 && proxytrust.Trusted(parseAddrOrZero(remoteIP), set.cloudflare) {
		// SafeShare sits directly behind Cloudflare (no local reverse proxy
		// between them): the direct connection itself is the one Cloudflare
		// hop, so no X-Forwarded-For entry can additionally be skipped as
		// Cloudflare's, and anything derived from headers below depends on
		// that direct Cloudflare connection.
		cfBudget = 0
		dependsOnCF = true
		cfHopFallback = remoteNorm
	}

	values := r.Header.Values("X-Forwarded-For")
	if len(values) > 0 {
		ip, ok, cfHop, cfConsumed := walkForwardedFor(newFFCursor(values), set.local, set.cloudflare, cfBudget)
		if ok {
			if cfConsumed {
				dependsOnCF = true
				cfHopFallback = cfHop.String()
			}
			return applyCFConnectingIPVeto(r, ip, dependsOnCF, cfHopFallback, anonymousMode)
		}
		// X-Forwarded-For was present but unusable (malformed rightmost hop
		// with no trusted hop walked, or the chain exceeded
		// maxForwardedForHops). Do NOT fall back to X-Real-IP here -- that
		// fallback is reserved for when X-Forwarded-For is absent. cfConsumed
		// is always false when ok is false (a Cloudflare hop always sets
		// haveLastTrusted, which is required for ok=true), so no veto is
		// needed: remoteNorm already equals cfHopFallback whenever
		// dependsOnCF is true here.
		logNoUsableForwardedHeader(remoteNorm, anonymousMode)
		return remoteNorm
	}

	// X-Forwarded-For absent: X-Real-IP is the fallback, but only when it is
	// itself a valid IP. dependsOnCF here can only come from RemoteAddr's
	// budget being pre-spent (no walk ran), so the veto still applies.
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if addr, err := netip.ParseAddr(xri); err == nil {
			candidate := proxytrust.NormalizeAddr(addr).String()
			return applyCFConnectingIPVeto(r, candidate, dependsOnCF, cfHopFallback, anonymousMode)
		}
	}

	logNoUsableForwardedHeader(remoteNorm, anonymousMode)
	return remoteNorm
}

// cfConnectingIPHeader is set only by Cloudflare's own edge/proxy layer --
// never by SafeShare's own reverse proxy -- and is used by
// applyCFConnectingIPVeto.
const cfConnectingIPHeader = "CF-Connecting-IP"

// cfConnectingIPMissingOnce makes the first "header missing" veto log at Warn:
// if Cloudflare is configured to strip visitor-IP headers (e.g. the "Remove
// visitor IP headers" managed transform), every visitor silently collapses
// onto the Cloudflare hop's address, which the operator needs to notice.
var cfConnectingIPMissingOnce sync.Once

// applyCFConnectingIPVeto enforces that a candidate client IP which depends
// on trusting Cloudflare is only accepted if it matches the normalized
// CF-Connecting-IP header. On a mismatch, a missing header, or a
// malformed header, the veto fails closed onto cfHopFallback: the
// Cloudflare hop that was consumed while walking X-Forwarded-For, or
// RemoteAddr itself if the one-hop budget was pre-spent by a direct
// connection. When dependsOnCF is false the candidate is returned
// unchanged -- the header is consulted only when Cloudflare trust actually
// produced the candidate, and even then it is only ever a veto: it is never
// itself the returned value.
//
// Pseudo-IPv4: both of Cloudflare's modes keep CF-Connecting-IP and the
// edge-appended X-Forwarded-For entry in agreement ("Add header" leaves both
// as the real address, "Overwrite" rewrites both to the pseudo IPv4), so a
// direct CF-Connecting-IP match covers them. Cf-Pseudo-IPv4 is deliberately
// ignored: legitimate traffic never needs it, and a Worker whose spoofed
// entry got past the walk can set it to match that entry.
//
// Residual gap (see docs/REVERSE_PROXY.md): a Worker that bypasses
// Cloudflare's proxy entirely and connects to the origin directly is, at
// that point, just an ordinary HTTP client -- it can forge CF-Connecting-IP
// itself, same as any other header. This veto cannot
// distinguish that from a header genuinely set by Cloudflare's edge; fully
// closing that gap requires the origin/reverse-proxy to accept only
// connections that actually came through Cloudflare's proxy (Authenticated
// Origin Pulls, or Cloudflare Tunnel exclusively).
func applyCFConnectingIPVeto(r *http.Request, candidate string, dependsOnCF bool, cfHopFallback string, anonymousMode bool) string {
	if !dependsOnCF {
		return candidate
	}

	raw := strings.TrimSpace(r.Header.Get(cfConnectingIPHeader))
	if raw == "" {
		cfConnectingIPMissingOnce.Do(func() {
			slog.Warn("CF-Connecting-IP header missing on a request that relied on Cloudflare trust; "+
				"attributing it to the Cloudflare hop instead. If this keeps happening, check that Cloudflare "+
				"is not configured to remove visitor IP headers (logged once)",
				"fallback_ip", privacy.RedactIP(cfHopFallback, anonymousMode))
		})
		logCFConnectingIPVeto(candidate, cfHopFallback, "missing", anonymousMode)
		return cfHopFallback
	}
	cfAddr, err := netip.ParseAddr(raw)
	if err != nil {
		logCFConnectingIPVeto(candidate, cfHopFallback, "malformed", anonymousMode)
		return cfHopFallback
	}
	if candidate == proxytrust.NormalizeAddr(cfAddr).String() {
		return candidate
	}

	logCFConnectingIPVeto(candidate, cfHopFallback, "mismatch", anonymousMode)
	return cfHopFallback
}

func logCFConnectingIPVeto(candidate, fallback, reason string, anonymousMode bool) {
	slog.Debug("CF-Connecting-IP veto rejected candidate; falling back to the Cloudflare hop",
		"reason", reason,
		"candidate_ip", privacy.RedactIP(candidate, anonymousMode),
		"fallback_ip", privacy.RedactIP(fallback, anonymousMode),
	)
}

func logNoUsableForwardedHeader(remoteNorm string, anonymousMode bool) {
	slog.Debug("trusted peer sent no usable forwarded header; using RemoteAddr",
		"remote_ip", privacy.RedactIP(remoteNorm, anonymousMode),
	)
}

// normalizeIPString normalizes an IP address string for stable use as a
// map/rate-limit key. If the input cannot be parsed as an IP (should not
// happen for a real RemoteAddr), it is returned unchanged.
func normalizeIPString(ipStr string) string {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return ipStr
	}
	return proxytrust.NormalizeAddr(addr).String()
}

// parseAddrOrZero parses ipStr as an address for trust-list checks,
// returning the zero netip.Addr (which cannot match any prefix) if it fails
// to parse, so an unparsable RemoteAddr simply never matches any trusted
// prefix rather than being treated as trusted.
func parseAddrOrZero(ipStr string) netip.Addr {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}
	}
	return proxytrust.NormalizeAddr(addr)
}
