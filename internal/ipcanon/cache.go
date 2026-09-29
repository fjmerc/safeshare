package ipcanon

import (
	"context"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// PrefixCache caches a repository's blocked-CIDR rows as parsed
// netip.Prefix values, so IsIPBlocked's containment check doesn't
// re-query (or re-parse) the CIDR rows of the blocklist on every request.
//
// Design (T43): the exact-match half of a block check is a single indexed
// "WHERE ip_address = ?" lookup and stays that way -- this cache only
// covers the CIDR rows, which can't be indexed for containment in either
// SQLite or PostgreSQL without a specialized extension. The blocklist is
// operator-maintained and expected to stay small (tens to low hundreds of
// entries), so holding every CIDR prefix in memory and doing a linear
// Contains scan is cheap; there's no need for an interval tree here.
//
// Scaling limit (code-review follow-up): the query each repository's
// loadCIDRPrefixes runs to populate this cache is a plain
// "WHERE ip_address LIKE '%/%'" -- a leading wildcard, so it can't use the
// existing ip_address index and always does a full table scan of
// blocked_ips. That's fine at the size this feature is designed for (an
// admin-maintained blocklist, not a bulk threat-intel feed), but it means
// the reload cost -- and therefore the cost of every cache miss/TTL
// expiry/BlockIP/UnblockIP -- grows linearly with the *total* row count
// (exact-match rows included), not just the CIDR row count. A deployment
// that grows the blocklist into the tens of thousands of rows should
// consider a dedicated indexed column (e.g. a boolean "is_cidr") instead of
// the LIKE scan.
//
// Two invalidation strategies, chosen per backend by the ttl passed to New:
//
//   - SQLite is single-process, so a ttl of 0 means "never expire on its
//     own" -- the repository calls Invalidate() itself after every
//     BlockIP/UnblockIP that touches a CIDR row, and that alone is
//     sufficient: nothing else can be writing to the table concurrently
//     from a different process.
//
//   - PostgreSQL may be fronted by multiple instances, each with its own
//     in-memory cache; one instance's Invalidate() call doesn't reach the
//     others'. A short ttl (a few seconds) bounds how stale another
//     instance's view of a newly-blocked/unblocked CIDR range can be,
//     trading a small window of staleness for not having to add a pub/sub
//     or polling layer just for this. Exact-match blocks -- the common
//     case -- are unaffected: those always hit the indexed query fresh, on
//     every instance, on every request.
type PrefixCache struct {
	ttl time.Duration

	mu sync.RWMutex
	// prefixes and haveData together hold the last successfully loaded
	// value, kept around across an Invalidate()/TTL expiry specifically so
	// a subsequent failed reload has something to fall back to (see Get's
	// stale-while-error handling below) -- haveData, not prefixes == nil,
	// is the source of truth for "do we have a value at all," since an
	// empty blocklist is a legitimate loaded value (prefixes == nil).
	prefixes []netip.Prefix
	haveData bool
	// loadedAt and invalidated together determine freshness: loadedAt is
	// when prefixes was last successfully populated, and invalidated is
	// set by Invalidate() and cleared by the next successful load. Kept
	// separate from haveData so a stale (expired/invalidated) cache can
	// still report it has a fallback value to serve on a failed reload.
	loadedAt    time.Time
	invalidated bool
}

// NewPrefixCache creates a cache that reloads via the loader passed to Get
// whenever it has never been loaded, has been Invalidate()d, or (if ttl > 0)
// its last load is older than ttl. ttl <= 0 disables time-based expiry
// entirely -- the cache is only ever refreshed by an explicit Invalidate().
func NewPrefixCache(ttl time.Duration) *PrefixCache {
	return &PrefixCache{ttl: ttl}
}

// Invalidate marks the cache stale, forcing the next Get to reload.
func (c *PrefixCache) Invalidate() {
	c.mu.Lock()
	c.invalidated = true
	c.mu.Unlock()
}

// Get returns the cached prefixes, reloading via load if the cache is stale.
// Concurrent callers during a reload each still call load independently
// (rather than sharing one in-flight load) -- reloads are already rare
// (only after a write, or a TTL tick) and cheap (a small table scan), so the
// extra complexity of a singleflight-style dedup isn't worth it here.
//
// Stale-while-error (code-review follow-up): if a reload attempt fails and
// a previous successful load exists, Get logs the error and returns that
// last-known-good list instead of propagating the error -- a transient
// blip (a DB reconnect, a momentary timeout) then degrades to serving
// slightly stale blocklist data rather than making IsIPBlocked fail (and,
// depending on the caller, fail open) for every request until the next
// successful reload. The cache itself stays marked stale, so the very next
// Get call tries to reload again rather than latching onto the stale data
// for a full TTL. An error is only ever returned when there has never been
// a successful load to fall back to.
func (c *PrefixCache) Get(ctx context.Context, load func(context.Context) ([]netip.Prefix, error)) ([]netip.Prefix, error) {
	c.mu.RLock()
	if c.fresh() {
		p := c.prefixes
		c.mu.RUnlock()
		return p, nil
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	// Re-check after acquiring the write lock: another goroutine may have
	// already reloaded while we were waiting for it.
	if c.fresh() {
		return c.prefixes, nil
	}
	prefixes, err := load(ctx)
	if err != nil {
		if c.haveData {
			slog.Warn("failed to reload blocked CIDR ranges; serving the last successful load instead",
				"error", err, "last_loaded_at", c.loadedAt)
			return c.prefixes, nil
		}
		return nil, err
	}
	c.prefixes = prefixes
	c.loadedAt = time.Now()
	c.haveData = true
	c.invalidated = false
	return c.prefixes, nil
}

// fresh reports whether the cache can be served without reloading. Callers
// must hold at least a read lock.
func (c *PrefixCache) fresh() bool {
	if !c.haveData || c.invalidated {
		return false
	}
	if c.ttl <= 0 {
		return true
	}
	return time.Since(c.loadedAt) < c.ttl
}
