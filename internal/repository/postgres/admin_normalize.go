package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/fjmerc/safeshare/internal/ipcanon"
)

// NormalizeBlockedIPs canonicalizes every existing blocked_ips.ip_address
// value in place (T43). It's idempotent and safe to call on every startup.
// See the SQLite counterpart (internal/repository/sqlite/admin_normalize.go)
// for the full canonicalization/merge/warn rationale -- this mirrors it
// exactly, against a *Pool instead of *sql.DB, with two PostgreSQL-specific
// differences: the mutating statements run inside withRetryNoReturn (like
// the rest of this package) to absorb a transient serialization/deadlock
// error, and multiple instances may run this concurrently at startup in a
// multi-instance deployment.
//
// Multi-instance race (benign, code-review follow-up): every instance reads
// the same table and computes the same deterministic plan from it (oldest
// id always wins a merge, so there's no ordering ambiguity between
// instances). Under the pool's default (READ COMMITTED) isolation, whichever
// instance's transaction commits first performs the real work; every other
// instance's transaction, still working from its own pre-commit snapshot's
// plan, then either updates a row to the same canonical value it already
// has (a no-op write) or deletes a row another instance already deleted (a
// 0-rows-affected delete, not an error in PostgreSQL) -- so the outcome
// converges to the same normalized table regardless of which instance
// "wins," without any explicit coordination.
func NormalizeBlockedIPs(ctx context.Context, pool *Pool) error {
	rows, err := pool.Query(ctx, `SELECT id, ip_address FROM blocked_ips ORDER BY id ASC`)
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
	keeperByCanonical := make(map[string]int64)
	mergedInto := make(map[int64][]int64)
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

	err = withRetryNoReturn(ctx, 3, func() error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return fmt.Errorf("failed to begin blocked_ips normalization transaction: %w", err)
		}
		defer func() { _ = tx.Rollback(ctx) }() // no-op once Commit succeeds

		// Deletes first: every duplicate-of-a-keeper row is removed before
		// any keeper is renamed to its canonical value, so a keeper's
		// UPDATE can never collide with the UNIQUE(ip_address) constraint
		// on a not-yet-deleted duplicate.
		for _, id := range deletes {
			if _, err := tx.Exec(ctx, `DELETE FROM blocked_ips WHERE id = $1`, id); err != nil {
				return fmt.Errorf("failed to delete duplicate blocked_ips row %d: %w", id, err)
			}
		}
		for _, u := range updates {
			if _, err := tx.Exec(ctx, `UPDATE blocked_ips SET ip_address = $1 WHERE id = $2`, u.new, u.id); err != nil {
				return fmt.Errorf("failed to normalize blocked_ips row %d: %w", u.id, err)
			}
		}

		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit blocked_ips normalization: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
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
