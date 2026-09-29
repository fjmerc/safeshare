package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"

	"github.com/fjmerc/safeshare/internal/ipcanon"
)

// NormalizeBlockedIPs canonicalizes every existing blocked_ips.ip_address
// value in place (T43). It's idempotent and safe to call on every startup:
//
//   - A row whose value is already canonical is left untouched.
//   - A row whose value canonicalizes to something different (e.g.
//     "2001:DB8::1" -> "2001:db8::1") is updated in place.
//   - If normalizing two or more rows produces the same canonical value
//     (they were always the same logical address/range, just spelled
//     differently), all but the oldest (lowest id) row are deleted, and the
//     merge is logged at Info.
//   - A row that's a CIDR broader than T43's bounds (ipcanon.ErrPrefixTooBroad
//     -- e.g. a legacy "0.0.0.0/0" written before those bounds existed) is
//     left completely untouched and logged at Warn, suggesting removal: each
//     repository's loadCIDRPrefixes deliberately does NOT enforce a row like
//     this (pre-T43 blocklist matching was exact-string only, so a row this
//     broad was never actually enforced as a range in the first place --
//     silently starting to after an upgrade could newly block far more than
//     the operator intended), and it can no longer be edited through the
//     normal canonical path either -- see UnblockIP's exact-string fallback.
//   - Any other row that fails to parse as either a bare IP or a CIDR range
//     is likewise left untouched and logged at Warn, with a distinct
//     message -- normalization never deletes or rewrites something it can't
//     confidently canonicalize.
func NormalizeBlockedIPs(ctx context.Context, db *sql.DB) error {
	rows, err := db.QueryContext(ctx, `SELECT id, ip_address FROM blocked_ips ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("failed to query blocked IPs for normalization: %w", err)
	}

	type blockedRow struct {
		id int64
		ip string
	}
	var all []blockedRow
	for rows.Next() {
		var br blockedRow
		if err := rows.Scan(&br.id, &br.ip); err != nil {
			rows.Close()
			return fmt.Errorf("failed to scan blocked IP row: %w", err)
		}
		all = append(all, br)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("error iterating blocked IP rows: %w", err)
	}
	rows.Close()

	type updateOp struct {
		id  int64
		new string
	}
	keeperByCanonical := make(map[string]int64) // canonical value -> id of the first (oldest) row seen for it
	mergedInto := make(map[int64][]int64)       // keeper id -> ids merged away into it
	var updates []updateOp
	var deletes []int64

	for _, br := range all {
		canonical, _, cerr := ipcanon.CanonicalizeEntry(br.ip)
		if cerr != nil {
			if errors.Is(cerr, ipcanon.ErrPrefixTooBroad) {
				slog.Warn("blocked_ips row is a legacy CIDR broader than the current /8 (v4) / /32 (v6) limit; it is NOT being enforced (pre-T43 blocklist matching was exact-string only, so this row was never actually enforced as a range) -- remove it by its exact value shown in the admin dashboard",
					"id", br.id, "value", br.ip)
			} else {
				slog.Warn("blocked_ips row does not canonicalize as an IP address or CIDR range; leaving it as-is",
					"id", br.id, "value", br.ip, "error", cerr)
			}
			continue
		}

		if keeperID, exists := keeperByCanonical[canonical]; exists {
			deletes = append(deletes, br.id)
			mergedInto[keeperID] = append(mergedInto[keeperID], br.id)
			continue
		}

		keeperByCanonical[canonical] = br.id
		if canonical != br.ip {
			updates = append(updates, updateOp{id: br.id, new: canonical})
		}
	}

	if len(updates) == 0 && len(deletes) == 0 {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin blocked_ips normalization transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	// Deletes first: every duplicate-of-a-keeper row is removed before any
	// keeper is renamed to its canonical value, so a keeper's UPDATE can
	// never collide with the UNIQUE(ip_address) constraint on a
	// not-yet-deleted duplicate.
	for _, id := range deletes {
		if _, err := tx.ExecContext(ctx, `DELETE FROM blocked_ips WHERE id = ?`, id); err != nil {
			return fmt.Errorf("failed to delete duplicate blocked_ips row %d: %w", id, err)
		}
	}
	for _, u := range updates {
		if _, err := tx.ExecContext(ctx, `UPDATE blocked_ips SET ip_address = ? WHERE id = ?`, u.new, u.id); err != nil {
			return fmt.Errorf("failed to normalize blocked_ips row %d: %w", u.id, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit blocked_ips normalization: %w", err)
	}

	if len(updates) > 0 {
		slog.Info("normalized blocked IP entries to canonical form", "count", len(updates))
	}
	for keeperID, mergedIDs := range mergedInto {
		slog.Info("merged duplicate blocked_ips rows that canonicalize to the same address/range",
			"kept_id", keeperID, "merged_ids", mergedIDs)
	}

	return nil
}
