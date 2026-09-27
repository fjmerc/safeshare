package utils

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/fjmerc/safeshare/internal/repository"
)

// Defaults for the download-session reaper (ADR-014, amending ADR-012/SH-2.3).
//
// Two independent TTLs now govern reaping, replacing the single reservation
// TTL:
//
//   - The lease TTL (DOWNLOAD_RESERVATION_TTL) governs UNCOMMITTED sessions —
//     an abandoned probe or a crashed process. Lowered from the ADR-012
//     default of 30m to 5m: an uncommitted session is renewed every time the
//     client is actively fetching bytes (see internal/handlers/session_writer.go's
//     heartbeat), so 5m of silence reliably means the request is gone, not
//     just slow.
//   - The idle TTL (DOWNLOAD_SESSION_IDLE_TTL) governs COMMITTED sessions —
//     the download was already credited, so this only bounds how long a
//     resumable token stays valid between Range requests (e.g. a paused web
//     UI download). This is the fix for T5: the old single TTL (30m) was
//     shorter than the up-to-6h transfer deadline (extendTransferDeadline in
//     internal/handlers/helpers.go), so the reaper could free a slot that was
//     still genuinely streaming. Committed sessions are now also bounded by
//     SessionMaxAge, an absolute (not idle-renewed) cutoff.
const (
	DefaultReservationTTL      = 5 * time.Minute
	defaultReservationInterval = 1 * time.Minute
	minReservationTTL          = 1 * time.Minute
	maxReservationTTL          = 24 * time.Hour
	reservationTTLEnvVar       = "DOWNLOAD_RESERVATION_TTL"

	// DefaultSessionIdleTTL is how long a committed-but-idle session (no bytes
	// touched via TouchDownloadSession) stays resumable before the reaper
	// deletes the row. Deleting it doesn't uncount the download — it was
	// already credited at commit time — it just stops the token from being
	// honoured on a later resume request.
	DefaultSessionIdleTTL = 1 * time.Hour
	minSessionIdleTTL     = 5 * time.Minute
	maxSessionIdleTTL     = 24 * time.Hour
	sessionIdleTTLEnvVar  = "DOWNLOAD_SESSION_IDLE_TTL"

	// SessionMaxAge bounds a committed session's absolute lifetime regardless
	// of activity — belt-and-suspenders against a token being kept alive
	// indefinitely by a client that touches it just often enough to dodge the
	// idle TTL. Not operator-configurable: it's a hard backstop, not a tuning
	// knob.
	SessionMaxAge = 24 * time.Hour

	// reaperTickTimeout bounds how long a single reaper iteration can run
	// against the database before being cancelled. Guards against a hung DB
	// from blocking the reaper indefinitely.
	reaperTickTimeout = 30 * time.Second
)

// ResolveReservationTTL returns the configured lease TTL for UNCOMMITTED
// download sessions. Reads DOWNLOAD_RESERVATION_TTL (parsed via
// time.ParseDuration; e.g. "5m", "45m", "2h"). Falls back to
// DefaultReservationTTL on empty, unparseable, or out-of-bounds values. The
// bounds enforce sanity: too-short TTLs falsely reap legitimate slow
// downloads, too-long TTLs delay recovery from process crashes for
// max_downloads=1 files.
func ResolveReservationTTL() time.Duration {
	raw := os.Getenv(reservationTTLEnvVar)
	if raw == "" {
		return DefaultReservationTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		slog.Warn("invalid "+reservationTTLEnvVar+"; using default",
			"raw", raw,
			"default", DefaultReservationTTL,
			"error", err,
		)
		return DefaultReservationTTL
	}
	if d < minReservationTTL || d > maxReservationTTL {
		slog.Warn(reservationTTLEnvVar+" out of allowed range; using default",
			"raw", raw,
			"parsed", d,
			"min", minReservationTTL,
			"max", maxReservationTTL,
			"default", DefaultReservationTTL,
		)
		return DefaultReservationTTL
	}
	return d
}

// ResolveSessionIdleTTL returns the configured idle TTL for COMMITTED download
// sessions. Reads DOWNLOAD_SESSION_IDLE_TTL (parsed via time.ParseDuration).
// Falls back to DefaultSessionIdleTTL on empty, unparseable, or out-of-bounds
// values. See the package doc comment above for how this differs from the
// lease TTL.
func ResolveSessionIdleTTL() time.Duration {
	raw := os.Getenv(sessionIdleTTLEnvVar)
	if raw == "" {
		return DefaultSessionIdleTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		slog.Warn("invalid "+sessionIdleTTLEnvVar+"; using default",
			"raw", raw,
			"default", DefaultSessionIdleTTL,
			"error", err,
		)
		return DefaultSessionIdleTTL
	}
	if d < minSessionIdleTTL || d > maxSessionIdleTTL {
		slog.Warn(sessionIdleTTLEnvVar+" out of allowed range; using default",
			"raw", raw,
			"parsed", d,
			"min", minSessionIdleTTL,
			"max", maxSessionIdleTTL,
			"default", DefaultSessionIdleTTL,
		)
		return DefaultSessionIdleTTL
	}
	return d
}

// StartReservationReaper runs a background goroutine that, every 1 minute,
// asks the repository to sweep stale download_sessions rows via
// ReapDownloadSessions: uncommitted rows past leaseTTL are cancelled (refund
// in_flight, credit uncounted_bytes), committed rows idle past idleTTL or
// older than the absolute SessionMaxAge are deleted outright (no counter
// change — already credited at commit time).
//
// The interval is fixed (not operator-tunable) so that crash-recovery latency
// is always bounded by leaseTTL + 1 minute regardless of operator config errors.
//
// See ADR-012 §8 for the original design and ADR-014 for why a single TTL was
// replaced by this lease/idle split (T5).
func StartReservationReaper(ctx context.Context, repos *repository.Repositories, leaseTTL, idleTTL time.Duration) {
	if leaseTTL < minReservationTTL {
		leaseTTL = DefaultReservationTTL
	}
	if idleTTL < minSessionIdleTTL {
		idleTTL = DefaultSessionIdleTTL
	}

	ticker := time.NewTicker(defaultReservationInterval)
	defer ticker.Stop()

	slog.Info("download session reaper started",
		"lease_ttl", leaseTTL,
		"idle_ttl", idleTTL,
		"max_age", SessionMaxAge,
		"interval", defaultReservationInterval,
	)

	runOnce := func() {
		// Per-tick timeout guards against a hung DB blocking the reaper. The parent
		// `ctx` propagates shutdown cancellation — we want that, so don't strip it.
		tickCtx, cancel := context.WithTimeout(ctx, reaperTickTimeout)
		defer cancel()
		// Pass the TTLs directly; the repository computes the cutoffs DB-side
		// (NOW() - ttl) so wall-clock skew between app and DB can't mis-reap
		// (bug-hunter M4).
		cancelled, expired, err := repos.Files.ReapDownloadSessions(tickCtx, leaseTTL, idleTTL, SessionMaxAge)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			slog.Error("download session reaper iteration failed",
				"error", err,
				"lease_ttl", leaseTTL,
				"idle_ttl", idleTTL,
			)
			return
		}
		if cancelled > 0 || expired > 0 {
			slog.Info("reaped stale download sessions",
				"cancelled", cancelled,
				"expired", expired,
				"lease_ttl", leaseTTL,
				"idle_ttl", idleTTL,
			)
		}
	}

	// Run once immediately on startup so crashed-process state from the previous
	// run gets cleaned up without waiting a full tick.
	runOnce()

	for {
		select {
		case <-ctx.Done():
			slog.Info("download session reaper shutting down")
			return
		case <-ticker.C:
			runOnce()
		}
	}
}

// ReservationTTLDescription returns a human-readable label of the uncommitted-
// session lease TTL for startup-log lines and health endpoints. Pure
// formatting helper.
func ReservationTTLDescription(ttl time.Duration) string {
	return fmt.Sprintf("%s (env %s)", ttl, reservationTTLEnvVar)
}

// SessionIdleTTLDescription returns a human-readable label of the committed-
// session idle TTL for startup-log lines and health endpoints.
func SessionIdleTTLDescription(ttl time.Duration) string {
	return fmt.Sprintf("%s (env %s)", ttl, sessionIdleTTLEnvVar)
}
