package utils

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
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

	// DefaultCompleteGrace (T42, amending ADR-014 — see ADR-014 addendum) is
	// how long after a download session's completed_at a trusted-token resume
	// is still allowed to resolve and stream from it, instead of being
	// unconditionally treated as an unresolved token (410 once the file's cap
	// is spent). This closes the gap where a client pauses a capped download
	// right after the server has handed the last byte to the kernel/network
	// stack — completing the session server-side — but before the client has
	// actually finished receiving it. 0 disables the grace window entirely
	// and restores the pre-T42 behaviour (a completed session is always
	// treated as not found). Resumes inside the window stay bounded by the
	// existing 2x-file-size ReserveSessionBytes ceiling, so this can never be
	// used to replay a completed download an unbounded number of times.
	DefaultCompleteGrace = 5 * time.Minute
	minCompleteGrace     = 1 * time.Second
	maxCompleteGrace     = 1 * time.Hour
	completeGraceEnvVar  = "DOWNLOAD_SESSION_COMPLETE_GRACE"

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

// ResolveCompleteGrace returns the configured T42 post-completion grace
// window (see DefaultCompleteGrace's doc comment). Reads
// DOWNLOAD_SESSION_COMPLETE_GRACE (parsed via time.ParseDuration, plus a
// handful of explicit "disabled" spellings — see below).
//
// Unlike the other Resolve* helpers in this file, an explicit zero is valid,
// meaningful configuration (it disables the grace window) and is honoured
// exactly, not replaced by the default. But this control is security-
// adjacent (it widens when a session token can still be used), so invalid
// input must fail CLOSED, not open: an unparseable value or a negative
// duration disables the grace window (returns 0) rather than silently
// falling back to the 5-minute default the way the other Resolve* helpers in
// this file do for their own (non-security-sensitive) settings. Only a
// valid, in-range positive duration is honoured; a positive but
// out-of-[minCompleteGrace, maxCompleteGrace] value is clamped to the
// nearer bound rather than replaced outright, since the operator's intent
// ("enable it, roughly this long") is unambiguous there.
//
// Called once, at startup, by main.go, which installs the result into both
// the reaper (StartReservationReaper) and the claim handler
// (handlers.SetCompleteGrace) — see those call sites' docs for why this is
// NOT re-resolved per request.
func ResolveCompleteGrace() time.Duration {
	raw := os.Getenv(completeGraceEnvVar)
	if raw == "" {
		return DefaultCompleteGrace
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "off", "false", "disabled", "none", "no":
		return 0
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		slog.Error(completeGraceEnvVar+": unparseable value; disabling the T42 resume grace window (failing closed, not defaulting to enabled)",
			"raw", raw,
			"error", err,
		)
		return 0
	}
	if d < 0 {
		slog.Error(completeGraceEnvVar+": negative value; disabling the T42 resume grace window (failing closed, not defaulting to enabled)",
			"raw", raw,
			"parsed", d,
		)
		return 0
	}
	if d == 0 {
		return 0
	}
	if d < minCompleteGrace {
		slog.Warn(completeGraceEnvVar+": below minimum; clamping up",
			"raw", raw,
			"parsed", d,
			"min", minCompleteGrace,
		)
		return minCompleteGrace
	}
	if d > maxCompleteGrace {
		slog.Warn(completeGraceEnvVar+": above maximum; clamping down",
			"raw", raw,
			"parsed", d,
			"max", maxCompleteGrace,
		)
		return maxCompleteGrace
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
// replaced by this lease/idle split (T5). completeGrace (T42, amending
// ADR-014) additionally protects a just-completed session from being reaped
// by the idle/max-age rule before its own grace window elapses — see
// ReapDownloadSessions' interface doc. A negative completeGrace is clamped to
// 0 (disabled); callers should normally pass the value from
// ResolveCompleteGrace, which already validates it.
func StartReservationReaper(ctx context.Context, repos *repository.Repositories, leaseTTL, idleTTL, completeGrace time.Duration) {
	if leaseTTL < minReservationTTL {
		leaseTTL = DefaultReservationTTL
	}
	if idleTTL < minSessionIdleTTL {
		idleTTL = DefaultSessionIdleTTL
	}
	if completeGrace < 0 {
		completeGrace = 0
	}

	ticker := time.NewTicker(defaultReservationInterval)
	defer ticker.Stop()

	slog.Info("download session reaper started",
		"lease_ttl", leaseTTL,
		"idle_ttl", idleTTL,
		"max_age", SessionMaxAge,
		"complete_grace", completeGrace,
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
		cancelled, expired, err := repos.Files.ReapDownloadSessions(tickCtx, leaseTTL, idleTTL, SessionMaxAge, completeGrace)
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

// CompleteGraceDescription returns a human-readable label of the T42
// post-completion resume grace window for startup-log lines and health
// endpoints. Reports "disabled" for a zero grace rather than "0s" so the
// deliberate-opt-out case reads clearly in logs.
func CompleteGraceDescription(grace time.Duration) string {
	if grace <= 0 {
		return fmt.Sprintf("disabled (env %s)", completeGraceEnvVar)
	}
	return fmt.Sprintf("%s (env %s)", grace, completeGraceEnvVar)
}
