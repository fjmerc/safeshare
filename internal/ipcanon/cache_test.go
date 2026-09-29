package ipcanon

import (
	"context"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("ParsePrefix(%q): %v", s, err)
	}
	return p
}

func TestPrefixCache_LoadsOnceUntilInvalidated(t *testing.T) {
	c := NewPrefixCache(0)
	var loads int32

	load := func(ctx context.Context) ([]netip.Prefix, error) {
		atomic.AddInt32(&loads, 1)
		return []netip.Prefix{mustPrefix(t, "10.0.0.0/8")}, nil
	}

	for i := 0; i < 5; i++ {
		prefixes, err := c.Get(context.Background(), load)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if len(prefixes) != 1 {
			t.Fatalf("Get() returned %d prefixes, want 1", len(prefixes))
		}
	}
	if got := atomic.LoadInt32(&loads); got != 1 {
		t.Errorf("load called %d times, want 1 (cache should serve from memory)", got)
	}

	c.Invalidate()
	if _, err := c.Get(context.Background(), load); err != nil {
		t.Fatalf("Get after Invalidate: %v", err)
	}
	if got := atomic.LoadInt32(&loads); got != 2 {
		t.Errorf("load called %d times after Invalidate, want 2", got)
	}
}

func TestPrefixCache_TTLExpiry(t *testing.T) {
	c := NewPrefixCache(10 * time.Millisecond)
	var loads int32
	load := func(ctx context.Context) ([]netip.Prefix, error) {
		atomic.AddInt32(&loads, 1)
		return []netip.Prefix{mustPrefix(t, "192.168.0.0/16")}, nil
	}

	if _, err := c.Get(context.Background(), load); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if _, err := c.Get(context.Background(), load); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got := atomic.LoadInt32(&loads); got != 1 {
		t.Errorf("load called %d times before TTL expiry, want 1", got)
	}

	time.Sleep(20 * time.Millisecond)

	if _, err := c.Get(context.Background(), load); err != nil {
		t.Fatalf("Get after TTL expiry: %v", err)
	}
	if got := atomic.LoadInt32(&loads); got != 2 {
		t.Errorf("load called %d times after TTL expiry, want 2", got)
	}
}

func TestPrefixCache_LoadErrorNotCached(t *testing.T) {
	c := NewPrefixCache(0)
	wantErr := context.DeadlineExceeded
	failing := func(ctx context.Context) ([]netip.Prefix, error) {
		return nil, wantErr
	}

	if _, err := c.Get(context.Background(), failing); err != wantErr {
		t.Fatalf("Get() error = %v, want %v", err, wantErr)
	}

	// A failed load must not be cached as "loaded" -- the next call should
	// try again (and this time succeed), not keep returning the stale error
	// state or empty data forever.
	ok := func(ctx context.Context) ([]netip.Prefix, error) {
		return []netip.Prefix{mustPrefix(t, "203.0.113.0/24")}, nil
	}
	prefixes, err := c.Get(context.Background(), ok)
	if err != nil {
		t.Fatalf("Get after failed load: %v", err)
	}
	if len(prefixes) != 1 {
		t.Fatalf("Get() returned %d prefixes, want 1", len(prefixes))
	}
}

// TestPrefixCache_StaleWhileError is a code-review follow-up test: once a
// load has succeeded at least once, a later failed reload (triggered by
// Invalidate) must serve the last-known-good list rather than propagating
// the error.
func TestPrefixCache_StaleWhileError(t *testing.T) {
	c := NewPrefixCache(0)
	good := []netip.Prefix{mustPrefix(t, "10.0.0.0/8")}
	loadOK := func(ctx context.Context) ([]netip.Prefix, error) {
		return good, nil
	}

	first, err := c.Get(context.Background(), loadOK)
	if err != nil {
		t.Fatalf("initial Get: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("initial Get() returned %d prefixes, want 1", len(first))
	}

	c.Invalidate()

	wantErr := context.DeadlineExceeded
	loadFail := func(ctx context.Context) ([]netip.Prefix, error) {
		return nil, wantErr
	}

	stale, err := c.Get(context.Background(), loadFail)
	if err != nil {
		t.Fatalf("Get() after a failed reload with prior good data returned an error = %v, want nil (stale-while-error)", err)
	}
	if len(stale) != 1 || stale[0] != good[0] {
		t.Errorf("Get() after failed reload = %v, want the last-known-good %v", stale, good)
	}

	// The cache must still be considered stale -- the very next call should
	// try to reload again, not latch onto the fallback data.
	var reloadedAfterFailure bool
	loadOKAgain := func(ctx context.Context) ([]netip.Prefix, error) {
		reloadedAfterFailure = true
		return []netip.Prefix{mustPrefix(t, "192.168.0.0/16")}, nil
	}
	fresh, err := c.Get(context.Background(), loadOKAgain)
	if err != nil {
		t.Fatalf("Get() after the stale-while-error fallback: %v", err)
	}
	if !reloadedAfterFailure {
		t.Error("cache did not attempt to reload on the next Get() after a stale-while-error fallback")
	}
	if len(fresh) != 1 || fresh[0].String() != "192.168.0.0/16" {
		t.Errorf("Get() after successful reload = %v, want the newly loaded value", fresh)
	}
}

// TestPrefixCache_StaleWhileError_TTLExpiry is the same scenario, but the
// staleness comes from TTL expiry rather than an explicit Invalidate.
func TestPrefixCache_StaleWhileError_TTLExpiry(t *testing.T) {
	c := NewPrefixCache(10 * time.Millisecond)
	good := []netip.Prefix{mustPrefix(t, "203.0.113.0/24")}
	loadOK := func(ctx context.Context) ([]netip.Prefix, error) {
		return good, nil
	}
	if _, err := c.Get(context.Background(), loadOK); err != nil {
		t.Fatalf("initial Get: %v", err)
	}

	time.Sleep(20 * time.Millisecond)

	loadFail := func(ctx context.Context) ([]netip.Prefix, error) {
		return nil, context.DeadlineExceeded
	}
	stale, err := c.Get(context.Background(), loadFail)
	if err != nil {
		t.Fatalf("Get() after TTL expiry + failed reload returned an error = %v, want nil (stale-while-error)", err)
	}
	if len(stale) != 1 || stale[0] != good[0] {
		t.Errorf("Get() after TTL expiry + failed reload = %v, want the last-known-good %v", stale, good)
	}
}
