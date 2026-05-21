package handlers

import (
	"log/slog"
	"sync"
)

// InFlightTracker bounds the number of concurrent download reservations a
// single client IP can hold against a single file. Defence-in-depth against
// a Slowloris-style attack where one IP opens many slow reads against a
// `max_downloads=N` file to hold all its slots until the reservation reaper
// TTL elapses (default 30 min) — bug-hunter SH-2.3 M3.
//
// The global rate-limit middleware caps total requests per IP per hour
// (default 50). That alone bounds attack throughput, but doesn't bound
// *concurrency*: an attacker can burst N concurrent slow requests within
// the rate budget and tie up all N reservation slots simultaneously. The
// in-flight tracker layers on top of the rate limiter to cap concurrency
// per (file, IP) pair.
//
// State is in-memory and per-process. SafeShare's single-instance
// deployment model makes this acceptable; a future multi-instance
// deployment would need to plumb the cap through the DB (reservation row
// with `client_ip` column).
type InFlightTracker struct {
	mu       sync.Mutex
	counts   map[int64]map[string]int // fileID → ip → count
	maxPerIP int
}

// NewInFlightTracker constructs a tracker capping concurrent reservations
// per IP per file at `maxPerIP`. A non-positive value disables the cap and
// returns nil — callers should treat nil as "no cap" via the tracker's
// methods (which are nil-receiver-safe).
func NewInFlightTracker(maxPerIP int) *InFlightTracker {
	if maxPerIP <= 0 {
		return nil
	}
	return &InFlightTracker{
		counts:   make(map[int64]map[string]int),
		maxPerIP: maxPerIP,
	}
}

// TryAcquire attempts to record a new in-flight reservation for (fileID,
// ip). Returns true if accepted (the caller must call Release exactly once
// on the same key), false if the per-IP cap is already saturated. A nil
// receiver always accepts (cap disabled).
func (t *InFlightTracker) TryAcquire(fileID int64, ip string) bool {
	if t == nil {
		return true
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	perIP := t.counts[fileID]
	if perIP == nil {
		perIP = make(map[string]int)
		t.counts[fileID] = perIP
	}
	if perIP[ip] >= t.maxPerIP {
		return false
	}
	perIP[ip]++
	return true
}

// Release decrements the in-flight count for (fileID, ip) and tidies empty
// maps. Safe to call on a nil receiver and idempotent against
// double-release (clamps at zero).
func (t *InFlightTracker) Release(fileID int64, ip string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	perIP := t.counts[fileID]
	if perIP == nil {
		return
	}
	if perIP[ip] > 0 {
		perIP[ip]--
	}
	if perIP[ip] == 0 {
		delete(perIP, ip)
	}
	if len(perIP) == 0 {
		delete(t.counts, fileID)
	}
}

// MaxPerIP returns the configured cap. 0 if the tracker is disabled (nil).
func (t *InFlightTracker) MaxPerIP() int {
	if t == nil {
		return 0
	}
	return t.maxPerIP
}

// inFlightTracker holds the package-level tracker used by ClaimHandler. nil
// means the cap is disabled (no MAX_INFLIGHT_PER_IP_PER_FILE configured, or
// set to 0).
var inFlightTracker *InFlightTracker

// SetInFlightTracker installs the tracker used by ClaimHandler. Pass nil
// to disable the cap (the handler will still rate-limit via the global
// middleware). Mirrors SetStorageBackend's lifecycle: called once during
// startup, before requests are served.
func SetInFlightTracker(t *InFlightTracker) {
	inFlightTracker = t
	if t != nil {
		slog.Info("in-flight reservation tracker installed",
			"max_per_ip_per_file", t.MaxPerIP(),
		)
	}
}

// GetInFlightTracker returns the installed tracker (nil if disabled).
// Exposed for tests that need to introspect or override.
func GetInFlightTracker() *InFlightTracker {
	return inFlightTracker
}
