package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/fjmerc/safeshare/internal/ipcanon"
	"github.com/fjmerc/safeshare/internal/proxytrust"
	"github.com/fjmerc/safeshare/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// dummyBcryptHash is a pre-generated valid bcrypt hash used for timing attack mitigation.
// This ensures constant-time behavior when checking credentials for non-existent users.
// Hash of "dummy-password-for-timing-attack-prevention" with cost 12.
const dummyBcryptHash = "$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4UWYz/XLKF0S3dCy"

// blockedIPsCIDRCacheTTL bounds how stale r.cidrCache can get from an edit
// that doesn't go through BlockIP/UnblockIP -- e.g. the sqlite3 shell, a
// direct-DB CLI tool, or a restored backup (security-review follow-up: a
// ttl of 0 relied entirely on Invalidate() being called by every writer,
// which none of those are). BlockIP/UnblockIP still call Invalidate()
// themselves, so the common case (using the admin dashboard/API) sees a
// change immediately; this ttl only bounds the uncommon case.
const blockedIPsCIDRCacheTTL = 30 * time.Second

// AdminRepository implements repository.AdminRepository for SQLite.
type AdminRepository struct {
	db *sql.DB

	// cidrCache caches the blocked_ips rows that are CIDR ranges (rather
	// than bare addresses), used by IsIPBlocked's containment check. See
	// blockedIPsCIDRCacheTTL and ipcanon.PrefixCache's doc for the full
	// invalidation rationale.
	cidrCache *ipcanon.PrefixCache
}

// NewAdminRepository creates a new SQLite admin repository.
func NewAdminRepository(db *sql.DB) *AdminRepository {
	return &AdminRepository{db: db, cidrCache: ipcanon.NewPrefixCache(blockedIPsCIDRCacheTTL)}
}

// ValidateCredentials checks if the provided username and password are valid.
// Returns true if valid, false if invalid.
//
// SECURITY: Uses bcrypt constant-time comparison. Does not differentiate between
// "user not found" and "wrong password" to prevent user enumeration.
func (r *AdminRepository) ValidateCredentials(ctx context.Context, username, password string) (bool, error) {
	query := `SELECT password_hash FROM admin_credentials WHERE username = ?`

	var hashedPassword string
	err := r.db.QueryRowContext(ctx, query, username).Scan(&hashedPassword)

	if err == sql.ErrNoRows {
		// User not found - perform a dummy bcrypt comparison to prevent timing attacks
		// that could reveal whether the username exists.
		// Uses a valid pre-generated hash to ensure full bcrypt comparison runs.
		_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(password)) //nolint:errcheck // Intentional: timing attack mitigation
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("credential validation failed: %w", err)
	}

	// Constant-time comparison using bcrypt
	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	if err != nil {
		return false, nil // Invalid password
	}

	return true, nil
}

// InitializeCredentials creates or updates admin credentials in the database.
// The password parameter is plaintext and will be hashed using bcrypt with cost 12.
//
// SECURITY: Plaintext password is never stored or logged.
// Uses UPSERT pattern for atomic operation to prevent race conditions.
func (r *AdminRepository) InitializeCredentials(ctx context.Context, username, password string) error {
	// Validate inputs
	if username == "" {
		return fmt.Errorf("username cannot be empty")
	}
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}
	// bcrypt silently truncates at 72 bytes - warn/reject if longer
	if len(password) > 72 {
		return fmt.Errorf("password cannot exceed 72 characters (bcrypt limitation)")
	}

	// Hash the password with bcrypt cost 12 (security requirement)
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}
	hashedPassword := string(hashedBytes)

	// Use UPSERT pattern for atomic operation to prevent race conditions
	// This ensures only one admin credential row exists (id=1)
	query := `INSERT INTO admin_credentials (id, username, password_hash) VALUES (1, ?, ?)
		ON CONFLICT(id) DO UPDATE SET username = excluded.username, password_hash = excluded.password_hash`
	_, err = r.db.ExecContext(ctx, query, username, hashedPassword)
	if err != nil {
		return fmt.Errorf("failed to initialize admin credentials: %w", err)
	}

	slog.Info("admin credentials initialized/updated", "username", username)
	return nil
}

// CreateSession creates a new admin session.
func (r *AdminRepository) CreateSession(ctx context.Context, token string, expiresAt time.Time, ipAddress, userAgent string) error {
	query := `INSERT INTO admin_sessions (session_token, expires_at, ip_address, user_agent)
		VALUES (?, ?, ?, ?)`

	// Format as RFC3339 for consistent SQLite datetime parsing
	expiresAtRFC3339 := expiresAt.Format(time.RFC3339)

	_, err := r.db.ExecContext(ctx, query, token, expiresAtRFC3339, ipAddress, userAgent)
	if err != nil {
		return fmt.Errorf("failed to create admin session: %w", err)
	}

	return nil
}

// GetSession retrieves a session by token.
// Returns nil, nil if the session doesn't exist or is expired.
func (r *AdminRepository) GetSession(ctx context.Context, token string) (*repository.AdminSession, error) {
	// Note: datetime(expires_at) normalizes RFC3339 format for proper comparison
	query := `SELECT id, session_token, created_at, expires_at, last_activity, ip_address, user_agent
		FROM admin_sessions WHERE session_token = ? AND datetime(expires_at) > datetime('now')`

	var session repository.AdminSession
	var createdAt, expiresAt, lastActivity string

	err := r.db.QueryRowContext(ctx, query, token).Scan(
		&session.ID,
		&session.SessionToken,
		&createdAt,
		&expiresAt,
		&lastActivity,
		&session.IPAddress,
		&session.UserAgent,
	)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get admin session: %w", err)
	}

	// Parse timestamps
	session.CreatedAt, err = time.Parse(time.RFC3339, createdAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse created_at: %w", err)
	}

	session.ExpiresAt, err = time.Parse(time.RFC3339, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse expires_at: %w", err)
	}

	session.LastActivity, err = time.Parse(time.RFC3339, lastActivity)
	if err != nil {
		return nil, fmt.Errorf("failed to parse last_activity: %w", err)
	}

	return &session, nil
}

// UpdateSessionActivity updates the last activity timestamp for a session.
func (r *AdminRepository) UpdateSessionActivity(ctx context.Context, token string) error {
	query := `UPDATE admin_sessions SET last_activity = CURRENT_TIMESTAMP WHERE session_token = ?`

	_, err := r.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to update admin session activity: %w", err)
	}

	return nil
}

// DeleteSession deletes a session (logout).
func (r *AdminRepository) DeleteSession(ctx context.Context, token string) error {
	query := `DELETE FROM admin_sessions WHERE session_token = ?`

	_, err := r.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to delete admin session: %w", err)
	}

	return nil
}

// CleanupExpiredSessions removes expired admin sessions.
func (r *AdminRepository) CleanupExpiredSessions(ctx context.Context) error {
	// Note: datetime(expires_at) normalizes RFC3339 format for proper comparison
	query := `DELETE FROM admin_sessions WHERE datetime(expires_at) < datetime('now')`

	result, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup expired admin sessions: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected > 0 {
		slog.Debug("cleaned up expired admin sessions", "count", rowsAffected)
	}

	return nil
}

// isUniqueConstraintViolation reports whether err is a SQLite UNIQUE
// constraint failure. modernc.org/sqlite doesn't expose a typed error for
// this, so (matching the existing convention elsewhere in this package --
// see partial_upload_repository.go's isFilesPartialUploadIDViolation) it's
// a substring check on the driver's error text.
func isUniqueConstraintViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// BlockIP adds an IP address or CIDR range to the blocklist. ipAddress is
// canonicalized before storage (T43): a bare address is normalized the same
// way GetClientIPWithTrust normalizes every request's client IP (IPv4-mapped
// unmapped, zone dropped, lowercase, compressed), and a CIDR range (e.g.
// "203.0.113.0/24") is masked to its canonical form, rejecting a prefix
// broad enough to risk self-lockout (wider than /8 IPv4 / /32 IPv6) --
// see ipcanon.CanonicalizeEntry.
//
// Returns repository.ErrDuplicateKey if the canonical value is already
// blocked, including under a different original spelling.
func (r *AdminRepository) BlockIP(ctx context.Context, ipAddress, reason, blockedBy string) error {
	canonical, isPrefix, err := ipcanon.CanonicalizeEntry(ipAddress)
	if err != nil {
		return fmt.Errorf("invalid IP address or CIDR: %w", err)
	}

	query := `INSERT INTO blocked_ips (ip_address, reason, blocked_by)
		VALUES (?, ?, ?)`

	_, err = r.db.ExecContext(ctx, query, canonical, reason, blockedBy)
	if err != nil {
		if isUniqueConstraintViolation(err) {
			return repository.ErrDuplicateKey
		}
		return fmt.Errorf("failed to block IP: %w", err)
	}

	if isPrefix {
		r.cidrCache.Invalidate()
	}

	slog.Info("IP blocked", "ip", canonical, "is_cidr", isPrefix, "reason", reason, "blocked_by", blockedBy)
	return nil
}

// deleteBlockedIPByExactValue deletes the blocked_ips row whose ip_address
// column exactly equals value, and reports how many rows were affected (0
// or 1, since ip_address is UNIQUE).
func (r *AdminRepository) deleteBlockedIPByExactValue(ctx context.Context, value string) (int64, error) {
	result, err := r.db.ExecContext(ctx, `DELETE FROM blocked_ips WHERE ip_address = ?`, value)
	if err != nil {
		return 0, fmt.Errorf("failed to unblock IP: %w", err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to check affected rows: %w", err)
	}
	return rows, nil
}

// UnblockIP removes an IP address or CIDR range from the blocklist.
// ipAddress is canonicalized the same way BlockIP canonicalizes it before
// storage, so e.g. "2001:DB8::1" successfully unblocks a row stored (or
// later normalized) as "2001:db8::1" (T43).
//
// If ipAddress fails to canonicalize, UnblockIP deletes by its exact
// (trimmed) string instead of rejecting the request (code-review
// follow-up): a legacy CIDR broader than T43's bounds (e.g. "10.0.0.0/4")
// can never canonicalize, but is still shown by GetBlockedIPs (and, for
// containment purposes, intentionally NOT enforced -- see loadCIDRPrefixes),
// so it must remain removable by the exact string the admin dashboard
// displays for it.
//
// If ipAddress DOES canonicalize but deleting by that canonical value
// matches nothing, UnblockIP retries once by the exact trimmed input before
// giving up (code-review follow-up): a row can end up stored in a
// non-canonical form despite being canonicalizable -- e.g. a startup
// normalization that errored partway through (NormalizeBlockedIPs' updates
// aren't atomic across rows), or a row written directly by external tooling
// that doesn't canonicalize. Without this retry, such a row could only ever
// be unblocked by typing its exact original (non-canonical) spelling, which
// an admin working from the canonical GetClientIPWithTrust output they're
// trying to match would have no reason to know.
//
// Returns ErrNotFound if nothing matched either way.
func (r *AdminRepository) UnblockIP(ctx context.Context, ipAddress string) error {
	trimmed := strings.TrimSpace(ipAddress)
	canonical, _, cerr := ipcanon.CanonicalizeEntry(ipAddress)

	target := trimmed
	if cerr == nil {
		target = canonical
	}

	rows, err := r.deleteBlockedIPByExactValue(ctx, target)
	if err != nil {
		return err
	}

	if rows == 0 && target != trimmed {
		rows, err = r.deleteBlockedIPByExactValue(ctx, trimmed)
		if err != nil {
			return err
		}
	}

	if rows == 0 {
		return repository.ErrNotFound
	}

	// Always invalidate: even if this wasn't a CIDR row, a stale cache
	// costs one extra (cheap) reload query at worst, whereas skipping it
	// selectively would need to know in advance whether the deleted row was
	// a CIDR entry.
	r.cidrCache.Invalidate()

	slog.Info("IP unblocked", "ip", target)
	return nil
}

// IsIPBlocked checks if an IP address is blocked -- either as an exact
// (canonicalized) match, or by falling inside any blocked CIDR range.
// ipAddress is expected to already be a bare client IP (GetClientIPWithTrust
// already returns one in canonical form), but is canonicalized defensively
// here too, so a caller passing a differently-formatted address still
// matches (T43).
func (r *AdminRepository) IsIPBlocked(ctx context.Context, ipAddress string) (bool, error) {
	canonical, err := ipcanon.Canonicalize(ipAddress)
	if err != nil {
		// Not a parseable bare address: falls back to comparing the raw
		// string, matching pre-T43 behavior (which also never matched a
		// canonical stored value for malformed input).
		canonical = ipAddress
	}

	query := `SELECT COUNT(*) FROM blocked_ips WHERE ip_address = ?`

	var count int
	if err := r.db.QueryRowContext(ctx, query, canonical).Scan(&count); err != nil {
		return false, fmt.Errorf("failed to check if IP is blocked: %w", err)
	}
	if count > 0 {
		return true, nil
	}

	addr, err := netip.ParseAddr(canonical)
	if err != nil {
		// Unparsable input can't fall inside any CIDR range either.
		return false, nil
	}

	prefixes, err := r.cidrCache.Get(ctx, r.loadCIDRPrefixes)
	if err != nil {
		return false, fmt.Errorf("failed to load blocked CIDR ranges: %w", err)
	}

	return proxytrust.Trusted(addr, prefixes), nil
}

// loadCIDRPrefixes reloads the CIDR-range rows of blocked_ips (rows whose
// stored value contains "/") for r.cidrCache. Exact-address rows are
// excluded -- IsIPBlocked already checks those via the indexed exact-match
// query above.
//
// Each row is canonicalized via ipcanon.CanonicalizePrefix -- the same
// function BlockIP's write path uses -- rather than a bare netip.ParsePrefix
// (code-review follow-up): this both matches a legacy mapped row like
// "::ffff:10.0.0.0/100" against plain IPv4 clients (NormalizePrefix), and
// (see the ErrPrefixTooBroad case below) keeps a too-broad legacy row from
// suddenly being enforced.
//
// A row broader than CanonicalizePrefix's current bounds (e.g. a legacy
// "0.0.0.0/0" or "::/0" written before T43 introduced those bounds) is
// deliberately NOT enforced here (security-review follow-up): before T43,
// blocklist matching was exact-string only, so a row like that was never
// actually enforced as a range in the first place. Silently starting to
// enforce it as CIDR containment after an upgrade would newly block far
// more than the operator ever intended. NormalizeBlockedIPs already warns
// about any such row once at startup; this method doesn't warn again on
// every reload (the PostgreSQL cache in particular reloads every few
// seconds) to avoid log spam -- it's a silent skip.
func (r *AdminRepository) loadCIDRPrefixes(ctx context.Context) ([]netip.Prefix, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT ip_address FROM blocked_ips WHERE ip_address LIKE '%/%'`)
	if err != nil {
		return nil, fmt.Errorf("failed to query blocked CIDR ranges: %w", err)
	}
	defer rows.Close()

	var prefixes []netip.Prefix
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("failed to scan blocked CIDR range: %w", err)
		}
		p, err := ipcanon.CanonicalizePrefix(raw)
		if err != nil {
			if errors.Is(err, ipcanon.ErrPrefixTooBroad) {
				continue // not enforced -- see doc comment above
			}
			slog.Warn("blocked_ips row contains an unparsable CIDR range; skipping it for containment checks",
				"value", raw, "error", err)
			continue
		}
		prefixes = append(prefixes, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating blocked CIDR ranges: %w", err)
	}
	return prefixes, nil
}

// GetBlockedIPs retrieves all blocked IP addresses.
func (r *AdminRepository) GetBlockedIPs(ctx context.Context) ([]repository.BlockedIP, error) {
	query := `SELECT id, ip_address, reason, blocked_at, blocked_by
		FROM blocked_ips ORDER BY blocked_at DESC`

	rows, err := r.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query blocked IPs: %w", err)
	}
	defer rows.Close()

	var blockedIPs []repository.BlockedIP
	for rows.Next() {
		var ip repository.BlockedIP
		var blockedAt string

		err := rows.Scan(&ip.ID, &ip.IPAddress, &ip.Reason, &blockedAt, &ip.BlockedBy)
		if err != nil {
			return nil, fmt.Errorf("failed to scan blocked IP: %w", err)
		}

		// Parse timestamp
		ip.BlockedAt, err = time.Parse(time.RFC3339, blockedAt)
		if err != nil {
			// Try alternate format from SQLite
			ip.BlockedAt, err = time.Parse("2006-01-02 15:04:05", blockedAt)
			if err != nil {
				return nil, fmt.Errorf("failed to parse blocked_at: %w", err)
			}
		}

		blockedIPs = append(blockedIPs, ip)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating blocked IPs: %w", err)
	}

	return blockedIPs, nil
}

// Ensure AdminRepository implements repository.AdminRepository.
var _ repository.AdminRepository = (*AdminRepository)(nil)
