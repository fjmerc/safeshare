package utils

import (
	"log/slog"
	"os"
	"strconv"
	"time"
)

// ADR-016 assembly-lease tuning. Mirrors the style of ResolveReservationTTL
// (reservation_reaper.go): each knob has a bounded, sane default and falls
// back to it on an empty, unparseable, or out-of-range env var.
const (
	// DefaultAssemblyLeaseTTL is how long an assembly worker's lease is
	// valid before it must renew (heartbeat) or be considered abandoned and
	// eligible for takeover by the recovery worker.
	DefaultAssemblyLeaseTTL = 2 * time.Minute
	minAssemblyLeaseTTL     = 30 * time.Second
	maxAssemblyLeaseTTL     = 30 * time.Minute
	assemblyLeaseTTLEnvVar  = "ASSEMBLY_LEASE_TTL"

	// DefaultAssemblyMaxAttempts caps how many times a given chunked upload
	// will be (re)attempted — via retry after a transient failure, or
	// takeover after a crashed/stalled worker — before it's marked
	// terminally failed with ASSEMBLY_RETRIES_EXHAUSTED.
	DefaultAssemblyMaxAttempts = 5
	minAssemblyMaxAttempts     = 1
	maxAssemblyMaxAttempts     = 20
	assemblyMaxAttemptsEnvVar  = "ASSEMBLY_MAX_ATTEMPTS"

	// DefaultAssemblyShutdownGrace is how long graceful shutdown waits for
	// in-progress assembly workers to finish (or yield their lease) before
	// giving up and letting the process exit; a yielded lease is picked up
	// by the next process's recovery worker almost immediately.
	DefaultAssemblyShutdownGrace = 30 * time.Second
	minAssemblyShutdownGrace     = 5 * time.Second
	maxAssemblyShutdownGrace     = 5 * time.Minute
	assemblyShutdownGraceEnvVar  = "ASSEMBLY_SHUTDOWN_GRACE"
)

// ResolveAssemblyLeaseTTL returns the configured assembly lease TTL. Reads
// ASSEMBLY_LEASE_TTL (parsed via time.ParseDuration). Falls back to
// DefaultAssemblyLeaseTTL on empty, unparseable, or out-of-bounds values.
func ResolveAssemblyLeaseTTL() time.Duration {
	raw := os.Getenv(assemblyLeaseTTLEnvVar)
	if raw == "" {
		return DefaultAssemblyLeaseTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		slog.Warn("invalid "+assemblyLeaseTTLEnvVar+"; using default",
			"raw", raw, "default", DefaultAssemblyLeaseTTL, "error", err)
		return DefaultAssemblyLeaseTTL
	}
	if d < minAssemblyLeaseTTL || d > maxAssemblyLeaseTTL {
		slog.Warn(assemblyLeaseTTLEnvVar+" out of allowed range; using default",
			"raw", raw, "parsed", d, "min", minAssemblyLeaseTTL, "max", maxAssemblyLeaseTTL,
			"default", DefaultAssemblyLeaseTTL)
		return DefaultAssemblyLeaseTTL
	}
	return d
}

// ResolveAssemblyMaxAttempts returns the configured max assembly attempts.
// Reads ASSEMBLY_MAX_ATTEMPTS as an integer. Falls back to
// DefaultAssemblyMaxAttempts on empty, unparseable, or out-of-bounds values.
func ResolveAssemblyMaxAttempts() int {
	raw := os.Getenv(assemblyMaxAttemptsEnvVar)
	if raw == "" {
		return DefaultAssemblyMaxAttempts
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		slog.Warn("invalid "+assemblyMaxAttemptsEnvVar+"; using default",
			"raw", raw, "default", DefaultAssemblyMaxAttempts, "error", err)
		return DefaultAssemblyMaxAttempts
	}
	if n < minAssemblyMaxAttempts || n > maxAssemblyMaxAttempts {
		slog.Warn(assemblyMaxAttemptsEnvVar+" out of allowed range; using default",
			"raw", raw, "parsed", n, "min", minAssemblyMaxAttempts, "max", maxAssemblyMaxAttempts,
			"default", DefaultAssemblyMaxAttempts)
		return DefaultAssemblyMaxAttempts
	}
	return n
}

// ResolveAssemblyShutdownGrace returns the configured shutdown grace period
// for in-progress assembly workers. Reads ASSEMBLY_SHUTDOWN_GRACE (parsed
// via time.ParseDuration). Falls back to DefaultAssemblyShutdownGrace on
// empty, unparseable, or out-of-bounds values.
func ResolveAssemblyShutdownGrace() time.Duration {
	raw := os.Getenv(assemblyShutdownGraceEnvVar)
	if raw == "" {
		return DefaultAssemblyShutdownGrace
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		slog.Warn("invalid "+assemblyShutdownGraceEnvVar+"; using default",
			"raw", raw, "default", DefaultAssemblyShutdownGrace, "error", err)
		return DefaultAssemblyShutdownGrace
	}
	if d < minAssemblyShutdownGrace || d > maxAssemblyShutdownGrace {
		slog.Warn(assemblyShutdownGraceEnvVar+" out of allowed range; using default",
			"raw", raw, "parsed", d, "min", minAssemblyShutdownGrace, "max", maxAssemblyShutdownGrace,
			"default", DefaultAssemblyShutdownGrace)
		return DefaultAssemblyShutdownGrace
	}
	return d
}
