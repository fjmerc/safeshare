package sqlite

import (
	"context"
	"errors"
	"testing"

	"github.com/fjmerc/safeshare/internal/repository"
)

func TestAdminRepository_BlockIP_CanonicalizesBareAddress(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAdminRepository(db)
	ctx := context.Background()

	if err := repo.BlockIP(ctx, "2001:DB8::0001", "test", "admin"); err != nil {
		t.Fatalf("BlockIP() error = %v", err)
	}

	blocked, err := repo.GetBlockedIPs(ctx)
	if err != nil {
		t.Fatalf("GetBlockedIPs() error = %v", err)
	}
	if len(blocked) != 1 {
		t.Fatalf("got %d blocked IPs, want 1", len(blocked))
	}
	if want := "2001:db8::1"; blocked[0].IPAddress != want {
		t.Errorf("stored IPAddress = %q, want %q (canonical form)", blocked[0].IPAddress, want)
	}
}

func TestAdminRepository_BlockUnblock_RoundTripDifferentSpelling(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAdminRepository(db)
	ctx := context.Background()

	if err := repo.BlockIP(ctx, "2001:DB8::1", "test", "admin"); err != nil {
		t.Fatalf("BlockIP() error = %v", err)
	}

	blocked, err := repo.IsIPBlocked(ctx, "2001:db8:0:0:0:0:0:1")
	if err != nil {
		t.Fatalf("IsIPBlocked() error = %v", err)
	}
	if !blocked {
		t.Fatal("IsIPBlocked() = false, want true for a differently-spelled equivalent address")
	}

	// Unblock using yet another spelling of the same address.
	if err := repo.UnblockIP(ctx, "2001:0DB8::0001"); err != nil {
		t.Fatalf("UnblockIP() error = %v", err)
	}

	blocked, err = repo.IsIPBlocked(ctx, "2001:db8::1")
	if err != nil {
		t.Fatalf("IsIPBlocked() error = %v", err)
	}
	if blocked {
		t.Fatal("IsIPBlocked() = true after UnblockIP, want false")
	}
}

func TestAdminRepository_UnblockIP_NotFound(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAdminRepository(db)
	ctx := context.Background()

	err := repo.UnblockIP(ctx, "203.0.113.5")
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("UnblockIP() error = %v, want ErrNotFound", err)
	}
}

func TestAdminRepository_BlockIP_DuplicateCanonicalValue(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAdminRepository(db)
	ctx := context.Background()

	if err := repo.BlockIP(ctx, "203.0.113.5", "first", "admin"); err != nil {
		t.Fatalf("BlockIP() error = %v", err)
	}

	// Same address, differently spelled via IPv4-mapped IPv6 -- canonicalizes
	// to the same stored value and must be rejected as a duplicate.
	err := repo.BlockIP(ctx, "::ffff:203.0.113.5", "second", "admin")
	if !errors.Is(err, repository.ErrDuplicateKey) {
		t.Fatalf("BlockIP() error = %v, want ErrDuplicateKey", err)
	}
}

func TestAdminRepository_BlockIP_RejectsTooBroadCIDR(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAdminRepository(db)
	ctx := context.Background()

	if err := repo.BlockIP(ctx, "10.0.0.0/4", "test", "admin"); err == nil {
		t.Fatal("BlockIP() with an overly broad CIDR succeeded, want error")
	}
}

func TestAdminRepository_IsIPBlocked_CIDRContainment(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAdminRepository(db)
	ctx := context.Background()

	if err := repo.BlockIP(ctx, "203.0.113.0/24", "range block", "admin"); err != nil {
		t.Fatalf("BlockIP() error = %v", err)
	}

	inside, err := repo.IsIPBlocked(ctx, "203.0.113.42")
	if err != nil {
		t.Fatalf("IsIPBlocked() error = %v", err)
	}
	if !inside {
		t.Error("IsIPBlocked() = false for an address inside the blocked /24, want true")
	}

	outside, err := repo.IsIPBlocked(ctx, "203.0.114.42")
	if err != nil {
		t.Fatalf("IsIPBlocked() error = %v", err)
	}
	if outside {
		t.Error("IsIPBlocked() = true for an address outside the blocked /24, want false")
	}
}

func TestAdminRepository_IsIPBlocked_IPv6CIDRContainment(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAdminRepository(db)
	ctx := context.Background()

	if err := repo.BlockIP(ctx, "2001:db8:1:2::/64", "range block", "admin"); err != nil {
		t.Fatalf("BlockIP() error = %v", err)
	}

	inside, err := repo.IsIPBlocked(ctx, "2001:DB8:1:2::AAAA")
	if err != nil {
		t.Fatalf("IsIPBlocked() error = %v", err)
	}
	if !inside {
		t.Error("IsIPBlocked() = false for an address inside the blocked /64, want true")
	}

	outside, err := repo.IsIPBlocked(ctx, "2001:db8:1:3::1")
	if err != nil {
		t.Fatalf("IsIPBlocked() error = %v", err)
	}
	if outside {
		t.Error("IsIPBlocked() = true for an address outside the blocked /64, want false")
	}
}

func TestAdminRepository_IsIPBlocked_CacheInvalidatedOnUnblock(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAdminRepository(db)
	ctx := context.Background()

	if err := repo.BlockIP(ctx, "203.0.113.0/24", "range block", "admin"); err != nil {
		t.Fatalf("BlockIP() error = %v", err)
	}
	// Warm the CIDR cache.
	if blocked, err := repo.IsIPBlocked(ctx, "203.0.113.5"); err != nil || !blocked {
		t.Fatalf("IsIPBlocked() = %v, %v, want true, nil", blocked, err)
	}

	if err := repo.UnblockIP(ctx, "203.0.113.0/24"); err != nil {
		t.Fatalf("UnblockIP() error = %v", err)
	}

	blocked, err := repo.IsIPBlocked(ctx, "203.0.113.5")
	if err != nil {
		t.Fatalf("IsIPBlocked() error = %v", err)
	}
	if blocked {
		t.Error("IsIPBlocked() = true after unblocking the containing CIDR, want false (stale cache)")
	}
}

func TestAdminRepository_IsIPBlocked_MalformedInput(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAdminRepository(db)
	ctx := context.Background()

	blocked, err := repo.IsIPBlocked(ctx, "not-an-ip")
	if err != nil {
		t.Fatalf("IsIPBlocked() error = %v", err)
	}
	if blocked {
		t.Error("IsIPBlocked() = true for malformed input, want false")
	}
}

// TestAdminRepository_LegacyBroadCIDR_NotEnforcedButRemovable is a
// security-review follow-up (T43): a blocked_ips row broader than the
// current /8 (v4) / /32 (v6) bound -- e.g. written before that bound
// existed, or by a future direct-SQL fixup -- must NOT be enforced via CIDR
// containment (pre-T43 blocklist matching was exact-string only, so a row
// this broad was never actually enforced as a range; silently starting to
// after an upgrade could newly block far more than intended), must never be
// re-insertable through BlockIP, and must still be removable (by its exact
// stored string, since it can't canonicalize).
func TestAdminRepository_LegacyBroadCIDR_NotEnforcedButRemovable(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAdminRepository(db)
	ctx := context.Background()

	// Simulate a legacy row written before T43's CIDR-broadness bound
	// existed, bypassing BlockIP's canonicalization/validation entirely.
	if _, err := db.ExecContext(ctx, `INSERT INTO blocked_ips (ip_address, reason, blocked_by) VALUES (?, ?, ?)`,
		"10.0.0.0/4", "legacy broad block", "admin"); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	// NOT enforced: an address inside the broad range is NOT blocked, since
	// loadCIDRPrefixes skips any row that fails ipcanon.CanonicalizePrefix
	// with ErrPrefixTooBroad.
	blocked, err := repo.IsIPBlocked(ctx, "10.1.2.3")
	if err != nil {
		t.Fatalf("IsIPBlocked() error = %v", err)
	}
	if blocked {
		t.Error("IsIPBlocked() = true for an address inside a legacy too-broad CIDR, want false (not enforced)")
	}

	// BlockIP rejects re-adding (or adding fresh) a range this broad today.
	if err := repo.BlockIP(ctx, "10.0.0.0/4", "test", "admin"); err == nil {
		t.Error("BlockIP() of a too-broad range unexpectedly succeeded")
	}

	// Still removable: UnblockIP falls back to an exact match on the stored
	// string, since "10.0.0.0/4" can't canonicalize.
	if err := repo.UnblockIP(ctx, "10.0.0.0/4"); err != nil {
		t.Fatalf("UnblockIP() by exact stored string error = %v", err)
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM blocked_ips`).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 0 {
		t.Errorf("blocked_ips row count = %d after removing the only row, want 0", count)
	}
}

// TestAdminRepository_UnblockIP_RetriesExactStringWhenCanonicalMisses is a
// code-review follow-up (T43): if a row ends up stored non-canonically
// despite being canonicalizable (e.g. left behind by a startup
// normalization that errored partway through), UnblockIP must still be able
// to remove it by retrying with the exact trimmed input when the canonical
// delete matches nothing -- e.g. an admin who unblocks by copying the exact
// (non-canonical) value GetBlockedIPs displays for that row.
func TestAdminRepository_UnblockIP_RetriesExactStringWhenCanonicalMisses(t *testing.T) {
	db := setupTestDB(t)
	repo := NewAdminRepository(db)
	ctx := context.Background()

	// A row that IS canonicalizable ("2001:db8::1" is its canonical form)
	// but is stored in a non-canonical spelling, simulating a row
	// normalization missed.
	if _, err := db.ExecContext(ctx, `INSERT INTO blocked_ips (ip_address, reason, blocked_by) VALUES (?, ?, ?)`,
		"2001:DB8::1", "un-normalized legacy row", "admin"); err != nil {
		t.Fatalf("seed insert: %v", err)
	}

	// Unblock using the exact (non-canonical) spelling stored -- the
	// canonical form UnblockIP computes and tries first ("2001:db8::1")
	// won't match the row stored as "2001:DB8::1", so this only succeeds if
	// UnblockIP retries with the exact (trimmed) input it was given.
	if err := repo.UnblockIP(ctx, "2001:DB8::1"); err != nil {
		t.Fatalf("UnblockIP() with the exact non-canonical spelling error = %v, want the exact-string retry to find the row", err)
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM blocked_ips`).Scan(&count); err != nil {
		t.Fatalf("count query: %v", err)
	}
	if count != 0 {
		t.Errorf("blocked_ips row count = %d after removing the only row, want 0", count)
	}
}
