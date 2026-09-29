package handlers

import (
	"log/slog"
	"sync"

	"github.com/fjmerc/safeshare/internal/utils"
)

// decryptAdmission is the process-wide decrypt-memory admission budget used
// by serveFileWithRangeSupport for every encrypted (SFSE or legacy) claim
// download — see utils.DecryptAdmission and ADR-017 (T34). A nil value (the
// zero value of this var, until SetDecryptAdmission installs one) is a
// valid "unlimited" budget, so tests and any other caller that never
// installs one still work.
var decryptAdmission *utils.DecryptAdmission

// SetDecryptAdmission installs the process-wide decrypt-memory admission
// budget, typically sized from DOWNLOAD_DECRYPT_MEMORY_BUDGET at startup.
// Pass nil to disable the cap.
func SetDecryptAdmission(d *utils.DecryptAdmission) {
	decryptAdmission = d
	if d != nil {
		slog.Info("decrypt admission budget installed", "capacity_bytes", d.Capacity())
	}
}

// defaultEncryptedDownloadsPerIP is encryptedRangeIPTracker's cap before
// SetEncryptedRangeIPTracker installs an operator-configured one (from
// MAX_ENCRYPTED_DOWNLOADS_PER_IP) at startup — so tests and any other
// caller that never calls the setter still get a sane, bounded default
// instead of an unbounded (nil) tracker.
const defaultEncryptedDownloadsPerIP = 8

// encryptedRangeIPTrackerKey is the sentinel "file ID" passed to
// encryptedRangeIPTracker so its (fileID, ip) keying acts as a plain
// per-IP-only counter. Real file IDs are always >= 1 (SQLite/Postgres
// autoincrement primary keys), so 0 can never collide with one.
const encryptedRangeIPTrackerKey int64 = 0

// encryptedRangeIPTracker bounds concurrent encrypted-content claim
// downloads (SFSE or legacy) a single client IP may have in flight at once,
// across every file — not just one (that's inFlightTracker's job, scoped
// per-file under ADR-014). ADR-017 rule 3/6: an attacker confined to a
// single claim code (e.g. by a max_downloads cap, or simply not knowing any
// other codes) could otherwise still flood many cheap tiny-Range requests,
// each of which costs a full chunk decrypt server-side, and inFlightTracker
// alone wouldn't bound that because it's keyed per file. This bounds it
// per-IP instead, independent of which file(s) are targeted.
//
// Keyed by decryptShareIPKey (full address for IPv4, /64 prefix for
// IPv6 — see its doc), the same key used for the per-IP decrypt-memory
// share below, so a client rotating addresses within its own IPv6 /64
// (routine for many residential/mobile allocations) is tracked as one
// client for both limits, not given a fresh budget per address.
//
// Configurable via MAX_ENCRYPTED_DOWNLOADS_PER_IP (security-audit
// finding: Tor/Ghost-mode and untrusted-proxy deployments can have every
// client share one apparent IP, where a fixed cap of 8 would throttle
// legitimate concurrent traffic — see docs/TOR_DEPLOYMENT.md). 0 disables
// the cap (NewInFlightTracker already returns nil for a non-positive
// value, which is nil-receiver-safe throughout).
var encryptedRangeIPTracker = NewInFlightTracker(defaultEncryptedDownloadsPerIP)

// SetEncryptedRangeIPTracker installs the process-wide per-IP concurrency
// tracker for encrypted claim downloads, typically sized from
// MAX_ENCRYPTED_DOWNLOADS_PER_IP at startup. Pass nil to disable the cap.
func SetEncryptedRangeIPTracker(t *InFlightTracker) {
	encryptedRangeIPTracker = t
}

// decryptShareIPKey returns the key used to group a client for both
// encryptedRangeIPTracker and decryptShare (the per-IP decrypt-memory
// budget share below): the full address for IPv4, or the configured-width
// IPv6 prefix (RATE_LIMIT_IPV6_PREFIX, default /64) for IPv6 —
// security-audit finding: keying on the full IPv6 address would let a
// client that legitimately rotates addresses within its own allocation
// (routine for many residential/mobile IPv6 networks) trivially bypass both
// limits by requesting a fresh address per download; grouping by prefix
// treats that as the one client it actually is.
//
// T43: delegates to utils.RateLimitKey, the single shared implementation
// every per-IP limiter in the codebase uses, instead of duplicating the
// same full-address-for-v4/prefix-for-v6 logic with its own hardcoded /64.
func decryptShareIPKey(ip string) string {
	return utils.RateLimitKey(ip)
}

// decryptIPShare bounds how many bytes of the global decrypt-memory budget
// (decryptAdmission) a single client (keyed via decryptShareIPKey) may hold
// concurrently, capped at decryptAdmission.Capacity()/4 — security-audit
// finding: the global FIFO admission queue (utils.DecryptAdmission) is
// fair in arrival order, but nothing stopped one client from opening
// several concurrent encrypted downloads and claiming a disproportionate
// (even total) share of the budget, starving every other client despite
// that fairness.
//
// A lone request (nothing else currently held by that key) is always
// admitted regardless of its own weight — the cap bounds concurrent
// multi-request abuse from one client, not the size of any single
// legitimate request, which is already bounded elsewhere (a chunk's size
// for SFSE, LEGACY_DECRYPT_MAX_BYTES for legacy). Rejecting a lone
// big-but-legal request here would be a functional regression, not a
// security fix: LEGACY_DECRYPT_MAX_BYTES (128MB default) is deliberately
// allowed to exceed a quarter of DOWNLOAD_DECRYPT_MEMORY_BUDGET (256MB
// default, so a quarter is 64MB) precisely so a single at-the-cap legacy
// download isn't rejected outright by this share (see ADR-017).
type decryptShareTracker struct {
	mu   sync.Mutex
	used map[string]int64
}

var decryptShare = &decryptShareTracker{used: make(map[string]int64)}

// tryReserve reserves weight bytes against ipKey's share of capShare. See
// the type doc for the "a lone request is always admitted" rule. A
// non-positive capShare (e.g. an unconfigured/unlimited decryptAdmission,
// whose Capacity() is 0, or MAX_ENCRYPTED_DOWNLOADS_PER_IP=0 — see
// perIPShareCap) disables per-IP share enforcement entirely rather than
// rejecting every second-or-later concurrent request from any IP outright —
// the global budget (if any) still applies regardless.
//
// Returns two independent booleans (security-audit finding, round 4):
// admitted reports whether the caller may proceed at all (always true when
// capShare<=0); reserved reports whether an entry was actually recorded in
// t.used for this call. They differ specifically in the capShare<=0 case:
// admitted is true but reserved is false, since nothing was recorded. The
// caller must gate its eventual release() call on reserved, not admitted —
// calling release() for a reservation that was never actually recorded
// would decrement whatever value happens to be at t.used[ipKey], which
// could belong to a different, still-active reservation for the same key
// made while capShare was positive (e.g. across a runtime config change, or
// simply while share enforcement and disabled-share requests for the same
// IP interleave).
func (t *decryptShareTracker) tryReserve(ipKey string, weight, capShare int64) (admitted, reserved bool) {
	if capShare <= 0 {
		return true, false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	current := t.used[ipKey]
	if current > 0 && current+weight > capShare {
		return false, false
	}
	t.used[ipKey] = current + weight
	return true, true
}

// release returns weight bytes reserved by a matching tryReserve call.
func (t *decryptShareTracker) release(ipKey string, weight int64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.used[ipKey] - weight
	if v <= 0 {
		delete(t.used, ipKey)
		return
	}
	t.used[ipKey] = v
}
