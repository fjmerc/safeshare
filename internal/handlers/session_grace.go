package handlers

import "time"

// completeGraceWindow is the process-wide T42 post-completion resume grace
// window used by serveCappedDownload (claim_session.go) — see
// SetCompleteGrace. The zero value (before SetCompleteGrace is ever called,
// e.g. in tests that don't need it) means the grace window is disabled,
// matching utils.ResolveCompleteGrace's own "0 disables it" contract and
// failing closed by default rather than open.
var completeGraceWindow time.Duration

// SetCompleteGrace installs the process-wide T42 post-completion resume
// grace window, sized from DOWNLOAD_SESSION_COMPLETE_GRACE (via
// utils.ResolveCompleteGrace) once at startup by main.go — the same
// resolved value main.go also passes to StartReservationReaper, so the
// handler and the reaper always agree on the window's length.
//
// Deliberately resolved once at startup and read from this package-level
// variable, NOT re-resolved from the environment on every request: this
// mirrors the existing SetDecryptAdmission / SetInFlightTracker /
// SetWebAuthnService pattern in this package, avoids a slog call (and an
// os.Getenv + time.ParseDuration) on every capped-download request, and
// means a single startup log line (from ResolveCompleteGrace itself)
// reports any invalid/clamped configuration once instead of once per
// request (security-audit follow-up to T42).
func SetCompleteGrace(d time.Duration) {
	completeGraceWindow = d
}
