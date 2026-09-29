// Package ipcanon canonicalizes IP addresses and CIDR ranges for the
// admin IP-blocklist feature (T43 audit finding).
//
// Before T43, GetClientIPWithTrust already returned a canonical client IP
// (IPv4-mapped unmapped, zone dropped, lowercase, compressed) for every
// request, but blocked-IP matching still compared that canonical value
// against whatever string an admin originally typed into the block form —
// so "2001:DB8::1", "2001:0db8::1", and "::ffff:1.2.3.4" were all accepted
// by BlockIP but never matched by IsIPBlocked. This package gives every
// admin-repository implementation (sqlite, postgres) and the legacy
// internal/database helpers one shared, tested canonicalization used
// consistently on write (BlockIP/UnblockIP) and read (IsIPBlocked).
//
// It builds on proxytrust.NormalizeAddr/NormalizePrefix — the same
// normalization already applied to TRUSTED_PROXY_IPS entries and to every
// request's client IP — so a canonical blocklist entry always compares
// equal to the canonical client IP for the same logical address, however
// either was originally written.
package ipcanon

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/fjmerc/safeshare/internal/proxytrust"
)

// ErrPrefixTooBroad wraps the error CanonicalizePrefix returns when a CIDR
// is broader than MinPrefixBitsV4/MinPrefixBitsV6, so callers can tell that
// specific case apart from "doesn't parse at all" with errors.Is -- e.g. both
// NormalizeBlockedIPs (to warn specifically about a legacy row that predates
// these bounds) and each repository's loadCIDRPrefixes (to deliberately NOT
// enforce such a row as CIDR containment -- see its doc comment) check for
// this. A row like this can no longer be edited through the normal
// canonical path either, but stays removable -- see UnblockIP's fallback.
var ErrPrefixTooBroad = errors.New("CIDR prefix is broader than the allowed minimum")

// MinPrefixBitsV4 and MinPrefixBitsV6 are the narrowest (i.e. fewest
// significant bits / broadest address range) CIDR prefix lengths
// CanonicalizePrefix accepts for a blocklist entry. Anything broader --
// including the fully-unspecified 0.0.0.0/0 and ::/0 -- is rejected: a
// prefix that wide could plausibly block the operator's own access (and,
// for a public deployment, essentially the entire internet) by a single
// admin typo. These match the thresholds internal/config already warns on
// for an overly-broad TRUSTED_PROXY_IPS entry, but here they're a hard
// error rather than a warning, since blocking (not merely trusting) that
// much address space is a much more actively harmful mistake.
const (
	MinPrefixBitsV4 = 8
	MinPrefixBitsV6 = 32
)

// Canonicalize parses a bare IP address and returns its canonical string
// form: IPv4-mapped IPv6 unmapped, zone dropped, lowercase, compressed --
// the same normalization GetClientIPWithTrust applies to every request's
// client IP.
func Canonicalize(raw string) (string, error) {
	entry := strings.TrimSpace(raw)
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return "", fmt.Errorf("invalid IP address %q: %w", raw, err)
	}
	return proxytrust.NormalizeAddr(addr).String(), nil
}

// CanonicalizePrefix parses a CIDR range, canonicalizes it (unmapping an
// IPv4-mapped IPv6 prefix down to its plain-IPv4 equivalent, masking off any
// host bits below the prefix length), and rejects it if it's broader than
// MinPrefixBitsV4/MinPrefixBitsV6.
func CanonicalizePrefix(raw string) (netip.Prefix, error) {
	entry := strings.TrimSpace(raw)
	p, err := netip.ParsePrefix(entry)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", raw, err)
	}
	p, err = proxytrust.NormalizePrefix(p)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid CIDR %q: %w", raw, err)
	}
	p = p.Masked()

	addr := p.Addr()
	switch {
	case addr.Is4() && p.Bits() < MinPrefixBitsV4:
		return netip.Prefix{}, fmt.Errorf(
			"CIDR %q is broader than /%d, which is too broad to block (risk of self-lockout): %w", raw, MinPrefixBitsV4, ErrPrefixTooBroad)
	case addr.Is6() && p.Bits() < MinPrefixBitsV6:
		return netip.Prefix{}, fmt.Errorf(
			"CIDR %q is broader than /%d, which is too broad to block (risk of self-lockout): %w", raw, MinPrefixBitsV6, ErrPrefixTooBroad)
	}
	return p, nil
}

// CanonicalizeEntry parses a blocklist entry an admin typed -- either a bare
// IP address or a CIDR range (distinguished by the presence of "/") -- and
// returns its canonical stored form. isPrefix reports which case applied.
func CanonicalizeEntry(raw string) (value string, isPrefix bool, err error) {
	entry := strings.TrimSpace(raw)
	if entry == "" {
		return "", false, fmt.Errorf("IP address cannot be empty")
	}
	if strings.Contains(entry, "/") {
		p, perr := CanonicalizePrefix(entry)
		if perr != nil {
			return "", false, perr
		}
		return p.String(), true, nil
	}
	addr, aerr := Canonicalize(entry)
	if aerr != nil {
		return "", false, aerr
	}
	return addr, false, nil
}
