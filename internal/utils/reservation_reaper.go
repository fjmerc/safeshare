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

// Defaults for the download-reservation reaper (SH-2.3 / ADR-012).
const (
	DefaultReservationTTL      = 30 * time.Minute
	defaultReservationInterval = 1 * time.Minute
	minReservationTTL          = 1 * time.Minute
	maxReservationTTL          = 24 * time.Hour
	reservationTTLEnvVar       = "DOWNLOAD_RESERVATION_TTL"
	// reaperTickTimeout bounds how long a single reaper iteration can run
	// against the database before being cancelled. Guards against a hung DB
	// from blocking the reaper indefinitely.
	reaperTickTimeout = 30 * time.Second
)

// ResolveReservationTTL returns the configured reservation TTL.
// Reads DOWNLOAD_RESERVATION_TTL (parsed via time.ParseDuration; e.g. "5m", "45m", "2h").
// Falls back to DefaultReservationTTL on empty, unparseable, or out-of-bounds values.
// The bounds enforce sanity: too-short TTLs falsely reap legitimate slow downloads,
// too-long TTLs delay recovery from process crashes for max_downloads=1 files.
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

// StartReservationReaper runs a background goroutine that, every 1 minute,
// asks the repository to delete download_reservations rows older than `ttl`
// and decrement files.in_flight_reservations accordingly.
//
// The interval is fixed (not operator-tunable) so that crash-recovery latency
// is always bounded by TTL + 1 minute regardless of operator config errors.
//
// See ADR-012 §8 for the design and §9 for the TTL rationale.
func StartReservationReaper(ctx context.Context, repos *repository.Repositories, ttl time.Duration) {
	if ttl < minReservationTTL {
		ttl = DefaultReservationTTL
	}

	ticker := time.NewTicker(defaultReservationInterval)
	defer ticker.Stop()

	slog.Info("reservation reaper started",
		"ttl", ttl,
		"interval", defaultReservationInterval,
	)

	runOnce := func() {
		// Per-tick timeout guards against a hung DB blocking the reaper. The parent
		// `ctx` propagates shutdown cancellation — we want that, so don't strip it.
		tickCtx, cancel := context.WithTimeout(ctx, reaperTickTimeout)
		defer cancel()
		// Pass the TTL directly; the repository computes the cutoff DB-side
		// (NOW() - ttl) so wall-clock skew between app and DB can't mis-reap
		// (bug-hunter M4).
		n, err := repos.Files.ReapStaleReservations(tickCtx, ttl)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			slog.Error("reservation reaper iteration failed",
				"error", err,
				"ttl", ttl,
			)
			return
		}
		if n > 0 {
			slog.Info("reaped stale download reservations",
				"count", n,
				"ttl", ttl,
			)
		}
	}

	// Run once immediately on startup so crashed-process state from the previous
	// run gets cleaned up without waiting a full tick.
	runOnce()

	for {
		select {
		case <-ctx.Done():
			slog.Info("reservation reaper shutting down")
			return
		case <-ticker.C:
			runOnce()
		}
	}
}

// ReservationTTLDescription returns a human-readable label of the reservation
// TTL for startup-log lines and health endpoints. Pure formatting helper.
func ReservationTTLDescription(ttl time.Duration) string {
	return fmt.Sprintf("%s (env %s)", ttl, reservationTTLEnvVar)
}
