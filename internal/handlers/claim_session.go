package handlers

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webhooks"
)

// downloadSessionHeartbeatMaxInterval is the longest a streaming capped
// download ever waits between session-lease renewals (TouchDownloadSession)
// while bytes are actively flowing. See sessionHeartbeatInterval: the actual
// interval is also bounded to leaseTTL/3, so a short DOWNLOAD_RESERVATION_TTL
// (minimum 1m) can't leave a live transfer with only one or two renewal
// opportunities before its lease could lapse — see ADR-014 (T5).
const downloadSessionHeartbeatMaxInterval = 60 * time.Second

// sessionHeartbeatInterval picks the heartbeat renewal interval for a given
// lease TTL: min(downloadSessionHeartbeatMaxInterval, leaseTTL/3). At the
// default 5m TTL this is still the 60s ceiling; at the configurable minimum
// of 1m it drops to 20s, so a slow first write (e.g. a legacy
// decrypt-fully-into-memory-then-write path) still gets at least a couple of
// renewal attempts inside the lease window instead of racing a single 60s
// tick against a TTL that's the same size as the interval (bug-hunter
// finding — spurious SlotLost, not over-delivery, but still a needless
// failure for a genuinely-in-progress download).
func sessionHeartbeatInterval(leaseTTL time.Duration) time.Duration {
	if third := leaseTTL / 3; third < downloadSessionHeartbeatMaxInterval {
		return third
	}
	return downloadSessionHeartbeatMaxInterval
}

// serveCappedDownload handles the ADR-014 resumable download-session flow
// for files with max_downloads set (extracted out of ClaimHandler, which
// otherwise reads as orchestration — see its doc comment for the split
// between this and the unlimited-download fast path).
//
// Session token resolution deliberately does NOT commit a resumed token's
// session up front: CommitDownloadSession only ever runs from sessionWriter,
// gated on an actual successful (2xx) write — see session_writer.go's type
// doc. Committing here, before filePath has even been opened, would spend a
// recipient's one download on a request that then 404s (file deleted on
// disk, decryption failure, ...) with zero bytes delivered.
func serveCappedDownload(ctx context.Context, w http.ResponseWriter, r *http.Request, repos *repository.Repositories, cfg *config.Config, file *models.File, filePath, originalClaimCode, claimCode string) {
	// Cache-Control: private, no-store is set unconditionally for every
	// claim response by ClaimHandler before it dispatches here (ADR-017 /
	// T10) — capped-file responses especially depend on per-recipient state
	// that can change from one request to the next, but the header now
	// applies uniformly, not just to this path.

	// Determine, before any bytes are written: whether this request covers
	// the entire file (always counts under ADR-012 Policy A regardless of
	// threshold — see session_writer.go), how many bytes it will attempt to
	// serve (used below to bound replay via ReserveSessionBytes), and whether
	// its range reaches the file's last byte (used below to decide
	// completion — a resumed tail request like `bytes=X-` doesn't start at 0,
	// so it isn't wholeFile, but finishing it IS what completes the download).
	//
	// claimRangeDecision is the exact same function serveFileWithRangeSupport
	// calls below to actually decide and rewrite the request — deterministic
	// given the same request/file, so the two calls can never disagree about
	// what gets served. Its ETag return value is discarded here: this call
	// only needs the range decision for sizing; serveFileWithRangeSupport
	// sets the actual `ETag` response header from its own call.
	var wholeFile, rangeEndsAtEOF bool
	var rangeLen int64
	decisionForSizing, _ := claimRangeDecision(r, file)
	switch decisionForSizing.Kind {
	case utils.RangeFull:
		wholeFile = true
		rangeEndsAtEOF = true
		rangeLen = file.FileSize
	case utils.RangePartial:
		wholeFile = decisionForSizing.Start == 0 && decisionForSizing.End == file.FileSize-1
		rangeEndsAtEOF = decisionForSizing.End == file.FileSize-1
		rangeLen = decisionForSizing.End - decisionForSizing.Start + 1
	case utils.RangeUnsatisfiable:
		// serveFileWithRangeSupport will independently reach the same
		// conclusion and reply 416 before any bytes are written, so these
		// values are moot — sessionWriter only applies the commit
		// threshold to a 200/206 response, and nothing will actually be
		// served here.
		wholeFile = false
		rangeEndsAtEOF = false
		rangeLen = 0
	}

	// Resume path: a client presenting a session token from an earlier
	// request on this file. Any token that is missing, foreign to this
	// file, stale (past idleTTL/maxAge), or completed for longer than
	// completeGrace gets no oracle — Lookup returns nil and we silently fall
	// through to the fresh-reservation path below, exactly as if no token had
	// been sent.
	//
	// A Lookup hit is not by itself enough to trust the token: without a
	// further bound, a committed session's token could be replayed
	// indefinitely (within its idle/max-age TTL if still in-flight, or within
	// completeGrace if already finished — T42) to redeliver the whole file to
	// anyone holding it (bug-hunter finding — HIGH, extended by T42).
	// ReserveSessionBytes closes that in both cases by atomically bounding
	// total bytes_reserved for the session to ~2x the file size — generous
	// enough for legitimate overlapping retries (or a client resuming just
	// past the server-side completion point), finite enough that a token
	// can't be curled forever. Neither call commits or completes anything
	// itself — CommitDownloadSession/CompleteDownloadSession are both
	// idempotent no-ops for an already-committed/-completed session, so a
	// grace-window resume never double-credits download_count or re-fires
	// file.downloaded (see the function doc for why committing is deferred to
	// sessionWriter).
	sessionIdleTTL := utils.ResolveSessionIdleTTL()
	// T42 (amending ADR-014): the window after a session's own completed_at
	// during which a trusted-token resume is still allowed to resolve it —
	// see LookupDownloadSession's doc comment for why an already-completed
	// session isn't unconditionally rejected anymore, and why that can never
	// double-credit download_count or re-fire file.downloaded. Read from the
	// package-level variable main.go installs once at startup via
	// SetCompleteGrace (security-audit follow-up) — NOT re-resolved from the
	// environment on every request; see session_grace.go.
	completeGrace := completeGraceWindow
	// SessionByteLimit bounds bytes_reserved for the session's ENTIRE
	// lifetime now (security-audit follow-up to T42, see below) — computed
	// once and reused by both the trusted-resume charge and the initial
	// reservation's own charge.
	byteLimit := repository.SessionByteLimit(file.FileSize)
	tokenHeader := r.Header.Get("X-Download-Session")
	var (
		token            string
		trustedToken     bool
		justCredited     bool
		probeGrant       int64
		resumedCompleted bool // T42: this resume matched an already-completed session inside its grace window
	)
	if tokenHeader != "" {
		sess, lookupErr := repos.Files.LookupDownloadSession(ctx, file.ID, tokenHeader, sessionIdleTTL, utils.SessionMaxAge, completeGrace)
		if lookupErr != nil {
			slog.Warn("failed to look up download session; treating as new tokenless download",
				"file_id", file.ID, "error", lookupErr)
		}
		if sess != nil && sess.Completed {
			// Security-audit follow-up to T42: a grace-window resume must
			// only ever be able to deliver the tail bytes a paused client is
			// actually missing — a partial Range that starts after byte 0
			// and reaches EOF. Anything else against a completed session (a
			// plain GET, a Range starting at 0, a Range that doesn't reach
			// EOF) would let the grace window itself be used to re-request
			// arbitrary — even whole-file — content, not just complete an
			// interrupted receive. Reject the shape here, before any bytes
			// are known to have gone out, exactly like an unresolved token.
			if !(decisionForSizing.Kind == utils.RangePartial && decisionForSizing.Start > 0 && rangeEndsAtEOF) {
				sess = nil
			}
		}
		if sess != nil {
			granted, reserveErr := repos.Files.ReserveSessionBytes(ctx, file.ID, tokenHeader, rangeLen, byteLimit, completeGrace)
			if reserveErr != nil {
				slog.Warn("failed to reserve session bytes; treating as new tokenless download",
					"file_id", file.ID, "error", reserveErr)
			} else if granted {
				token = tokenHeader
				trustedToken = true
				resumedCompleted = sess.Completed
				if resumedCompleted {
					slog.Info("resumed capped download inside T42 completion grace window",
						"file_id", file.ID,
						"token_hash", logTokenHash(tokenHeader),
						"completed_at", sess.CompletedAt,
						"grace", completeGrace,
					)
				}
			}
			// !granted: the session's replay ceiling is spent (or it was
			// completed/deleted between Lookup and here) — fall through to a
			// fresh reservation below, same as an unrecognised token.
		}
	}

	if token == "" {
		newToken, granted, err := repos.Files.ReserveDownload(ctx, file.ID, originalClaimCode)
		if err != nil {
			if errors.Is(err, repository.ErrClaimCodeChanged) {
				slog.Warn("claim code changed before reservation",
					"file_id", file.ID,
					"original_code", redactClaimCode(originalClaimCode),
					"client_ip", logIP(getClientIP(r), cfg),
				)
				sendErrorResponse(w, r, "File Not Found or Expired", "This file does not exist or has expired. Files on SafeShare are automatically deleted after their expiration time. Please contact the sender if you need the file again.", "NOT_FOUND", http.StatusNotFound)
				return
			}
			slog.Error("failed to reserve download slot", "file_id", file.ID, "error", err)
			sendErrorResponse(w, r, "Server Error", "An internal error occurred while preparing the download. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
		if newToken == "" {
			// Cap hit — download_count + in_flight_reservations >= max_downloads.
			slog.Warn("file access denied",
				"reason", "download_limit_reached",
				"claim_code", redactClaimCode(claimCode),
				"filename", file.OriginalFilename,
				"client_ip", logIP(getClientIP(r), cfg),
			)
			sendErrorResponse(w, r, "Download Limit Reached", "This file has reached its maximum number of downloads and is no longer available. Please contact the sender if you need the file again.", "DOWNLOAD_LIMIT_REACHED", http.StatusGone)
			return
		}
		token = newToken
		probeGrant = granted

		// Security-audit follow-up to T42: charge THIS request's own
		// declared range against the same bytes_reserved ceiling a trusted
		// resume already charges against, immediately — before any bytes are
		// written. Previously only resumes were charged, so the request that
		// actually creates the session (a plain first download, or the
		// initial leg of a hostile Range-split) streamed for free against
		// this ceiling; a client could then use resumes (before OR after
		// completion) to extract up to another full 2x-file-size on top of
		// that uncharged first request — up to ~3x the file size total
		// instead of the intended 2x. Charging here closes that at the
		// source: byteLimit now bounds bytes_reserved across the session's
		// ENTIRE lifetime (the request that creates it plus every resume),
		// not just the resumes. For a single request's own range this charge
		// always fits (0 + rangeLen <= byteLimit), so an error or a denial
		// means something is wrong (e.g. the database is unavailable): fail
		// closed like the ReserveDownload error path above rather than
		// serving the file uncharged, and release the slot just reserved.
		chargeGranted, err := repos.Files.ReserveSessionBytes(ctx, file.ID, token, rangeLen, byteLimit, completeGrace)
		if err != nil || !chargeGranted {
			slog.Error("failed to charge initial reservation against the session byte ceiling",
				"file_id", file.ID, "token_hash", logTokenHash(token), "granted", chargeGranted, "error", err)
			if cancelErr := repos.Files.CancelDownload(context.WithoutCancel(ctx), file.ID, token); cancelErr != nil {
				slog.Error("failed to cancel download session", "file_id", file.ID, "token_hash", logTokenHash(token), "error", cancelErr)
			}
			sendErrorResponse(w, r, "Server Error", "An internal error occurred while preparing the download. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
			return
		}
	}

	// Handed back on every response so the client can present it again on
	// a resumed Range request. NOTE for any future CORS layer: this header
	// must be added to Access-Control-Expose-Headers (and allowed as a
	// request header via Access-Control-Allow-Headers) or cross-origin
	// resumable downloads will silently lose the session.
	w.Header().Set("X-Download-Session", token)

	// Safety net: if we exit early before deciding Commit/Cancel, Cancel
	// runs so an uncommitted slot doesn't leak. Idempotent no-op once the
	// session is committed or already cancelled.
	finalised := false
	defer func() {
		if finalised {
			return
		}
		if err := repos.Files.CancelDownload(context.Background(), file.ID, token); err != nil {
			slog.Error("safety-net session cancel failed", "file_id", file.ID, "token_hash", logTokenHash(token), "error", err)
		}
	}()

	sw := newSessionWriter(ctx, w, repos, file.ID, token, probeGrant, trustedToken, wholeFile)

	// Heartbeat: renew the session lease (last_seen_at) while bytes are
	// actively flowing. A stalled connection stops renewing — see
	// TouchDownloadSession's doc — so the reaper can still recover it. This
	// is the T5 fix: a genuinely slow multi-hour transfer (up to
	// maxTransferDeadline) now keeps its slot alive instead of being reaped
	// out from under it at the old fixed 30m TTL. The interval is scaled
	// down from the configured lease TTL so a short TTL still gets several
	// renewal opportunities (see sessionHeartbeatInterval).
	heartbeat := startSessionHeartbeat(ctx, repos, file.ID, token, sw, sessionHeartbeatInterval(utils.ResolveReservationTTL()))
	// Guards against a goroutine leak if serveFileWithRangeSupport panics:
	// the explicit Stop below covers the normal path, this covers anything
	// that unwinds past it. Stop is idempotent.
	defer heartbeat.Stop()

	transferDeadline := extendTransferDeadline(w, cfg, file.FileSize)
	commitable := serveFileWithRangeSupport(sw, r, file, filePath, cfg, transferDeadline)

	heartbeat.Stop()

	finalizeCtx, cancelFinalize := context.WithTimeout(context.WithoutCancel(ctx), reservationFinalizeTimeout)
	defer cancelFinalize()

	// Flush any bytes written since the last heartbeat tick so bytes_served
	// (used for the probe-budget accounting on Cancel) reflects this
	// request's full contribution.
	heartbeat.FinalFlush(finalizeCtx)

	// Every request against a session — the one that creates it (charged
	// just above, in the `token == ""` branch) or a later trusted-token
	// resume (charged via ReserveSessionBytes before this function was
	// reached) — charges its whole requested range against the session's
	// replay ceiling up front, before any bytes were known to have actually
	// gone out. Give back whatever portion it didn't manage to send —
	// paused, aborted, or errored partway. Without this, a normal
	// pause/resume sequence (the web UI's own resumable-downloader.js
	// resumes with `Range: bytes=<received>-` on every pause) would
	// permanently eat into the 2x-file-size ceiling for bytes it never
	// delivered, exhausting it — and turning the *next* resume into a fresh,
	// tokenless, potentially-410'd request — well before the recipient's one
	// legitimate download finishes (bug-hunter finding). Unconditional since
	// the security-audit follow-up to T42 made the initial charge
	// unconditional too — see the `token == ""` branch above. Only file
	// content counts as sent; an error body (404/500) delivered none.
	contentSent := int64(0)
	if sw.ResponseOK() {
		contentSent = sw.BytesWritten()
	}
	if unsent := rangeLen - contentSent; unsent > 0 {
		if err := repos.Files.ReleaseSessionBytes(finalizeCtx, file.ID, token, unsent); err != nil {
			slog.Warn("failed to release unsent session bytes", "file_id", file.ID, "token_hash", logTokenHash(token), "error", err)
		}
	}

	committed := sw.Committed()
	// SH-2.3 bug-hunter M1, carried forward to ADR-014: once a commit has
	// actually been attempted — even if it errored — bytes may already be
	// on the wire to the client, so we must never fall back to Cancel
	// afterwards (that would release the slot for a second recipient while
	// the first already received data). commitAttempted tracks that
	// independently of whether the attempt succeeded.
	commitAttempted := sw.CommitAttempted()
	if sw.CreditedNow() {
		// sessionWriter's own commit attempt was the one that moved this
		// session from uncommitted to committed (as opposed to finding it
		// already committed by an earlier request) — this request is the one
		// that spent the download.
		justCredited = true
	}
	if commitable && !committed {
		// Defensive: covers a whole-file request that never actually wrote
		// a byte (e.g. a zero-length file) so sessionWriter's Write() never
		// ran the commit check.
		commitAttempted = true
		result, err := repos.Files.CommitDownloadSession(finalizeCtx, file.ID, token)
		if err != nil {
			slog.Error("failed to commit download session", "file_id", file.ID, "token_hash", logTokenHash(token), "error", err)
		} else {
			switch result {
			case repository.DownloadCommitCredited:
				committed = true
				justCredited = true
			case repository.DownloadCommitAlreadyCommitted:
				committed = true
			}
		}
	}
	if !committed && !commitAttempted {
		if err := repos.Files.CancelDownload(finalizeCtx, file.ID, token); err != nil {
			slog.Error("failed to cancel download session", "file_id", file.ID, "token_hash", logTokenHash(token), "error", err)
		}
	}
	finalised = true

	// A committed session is "done" when THIS request's own range reached
	// the file's last byte and it actually finished streaming that range
	// successfully — regardless of whether the range started at 0, which is
	// what lets a resumed tail request (`bytes=X-`) complete a download that
	// started with an earlier, separate request.
	//
	// This is deliberately NOT based on the session's cumulative bytes_served
	// across every request that has ever touched it: BytesWritten only
	// counts bytes successfully handed to (and returned from) the
	// ResponseWriter for *this* request, but overlapping retries or a
	// download manager re-requesting an already-in-flight range could sum to
	// >= the file size while the recipient still never received the tail —
	// prematurely completing the session and making a later, genuinely-needed
	// resume request find the token already spent (bug-hunter finding). Using
	// only this request's own end-of-file delivery avoids that; the 2x
	// ReserveSessionBytes ceiling (not cumulative-bytes accounting) is what
	// bounds total replay.
	//
	// CompleteDownloadSession is guarded by completed_at IS NULL, so `first`
	// fires file.downloaded exactly once per download regardless of how many
	// requests (or token replays) touch this session afterwards.
	completedNow := false
	if committed && rangeEndsAtEOF && sw.ResponseOK() && contentSent == rangeLen {
		first, err := repos.Files.CompleteDownloadSession(finalizeCtx, file.ID, token)
		if err != nil {
			slog.Error("failed to complete download session", "file_id", file.ID, "token_hash", logTokenHash(token), "error", err)
		} else {
			completedNow = first
		}
	}

	// Webhook semantics (ADR-014): download_count and completed_downloads
	// are decoupled. file.downloaded reflects COMPLETION — every byte of the
	// file has actually been delivered (possibly across several requests) —
	// and fires from `completedNow` below. A download can already be
	// credited toward max_downloads well before that, the moment a commit
	// crosses the probe threshold; that earlier event is not itself a
	// webhook, only the trigger the file.expired check (further down) reacts
	// to. A capped file can therefore reach its download limit before any
	// file.downloaded webhook has fired for the request that filled it.
	if completedNow {
		now := time.Now()
		EmitWebhookEvent(&webhooks.Event{
			Type:      webhooks.EventFileDownloaded,
			Timestamp: now,
			File: webhooks.FileData{
				ID:           file.ID,
				ClaimCode:    file.ClaimCode,
				Filename:     file.OriginalFilename,
				Size:         file.FileSize,
				MimeType:     file.MimeType,
				ExpiresAt:    file.ExpiresAt,
				DownloadedAt: &now,
			},
		})
	}

	// file.expired fires when a credit *this request* performed brings the
	// counter to the cap — not gated on this request's own stream having
	// finished, since under ADR-014 the credit (CommitDownloadSession) and
	// the completion (CompleteDownloadSession) are decoupled: a resumed
	// download can fill the cap on the request that crosses the probe
	// threshold, well before the bytes finish streaming. justCredited is
	// true at most once per session (CommitDownloadSession is guarded by
	// committed_at IS NULL), so this fires at most once per download.
	var remainingDownloads string
	if justCredited {
		fresh, err := repos.Files.GetByID(finalizeCtx, file.ID)
		switch {
		case err != nil:
			slog.Warn("failed to re-read file after session commit; falling back to pre-Reserve snapshot for webhook decision",
				"file_id", file.ID,
				"error", err,
			)
			remainingDownloads = fmt.Sprintf("%d", *file.MaxDownloads-(file.DownloadCount+1))
		case fresh == nil:
			// File was deleted between commit and re-read (cleanup worker).
			remainingDownloads = "0"
		default:
			remaining := *file.MaxDownloads - fresh.DownloadCount
			remainingDownloads = fmt.Sprintf("%d", remaining)
			if fresh.DownloadCount >= *file.MaxDownloads {
				reason := "download_limit_reached"
				EmitWebhookEvent(&webhooks.Event{
					Type:      webhooks.EventFileExpired,
					Timestamp: time.Now(),
					File: webhooks.FileData{
						ClaimCode: claimCode,
						Filename:  file.OriginalFilename,
						Size:      file.FileSize,
						MimeType:  file.MimeType,
						ExpiresAt: file.ExpiresAt,
						Reason:    &reason,
					},
				})
				slog.Info("file expired due to download limit",
					"claim_code", redactClaimCode(claimCode),
					"filename", file.OriginalFilename,
					"download_count", fresh.DownloadCount,
					"max_downloads", *file.MaxDownloads,
				)
			}
		}
	} else {
		remainingDownloads = fmt.Sprintf("%d", *file.MaxDownloads-file.DownloadCount)
	}

	slog.Debug("download completed",
		"claim_code", redactClaimCode(claimCode),
		"committed", committed,
		"completed_now", completedNow,
		"remaining_downloads", remainingDownloads,
		"resumed_completed", resumedCompleted,
	)
}

// sessionHeartbeat periodically renews a download session's lease
// (TouchDownloadSession) while sessionWriter is actively delivering bytes,
// and flushes any remaining untouched bytes once streaming ends. See
// ADR-014 (T5): tying lease survival to observed activity, instead of a
// fixed wall-clock TTL, is what lets a genuinely slow multi-hour transfer
// keep its slot without letting a truly stalled one hold it forever.
type sessionHeartbeat struct {
	repos    *repository.Repositories
	fileID   int64
	token    string
	sw       *sessionWriter
	interval time.Duration

	lastTouched int64 // only touched from run() until Stop() returns; safe to read from FinalFlush after that happens-before
	stop        chan struct{}
	stopOnce    sync.Once
	done        chan struct{}
}

// startSessionHeartbeat starts the heartbeat goroutine and returns a handle
// to control it. Callers must eventually call Stop.
func startSessionHeartbeat(ctx context.Context, repos *repository.Repositories, fileID int64, token string, sw *sessionWriter, interval time.Duration) *sessionHeartbeat {
	h := &sessionHeartbeat{
		repos:    repos,
		fileID:   fileID,
		token:    token,
		sw:       sw,
		interval: interval,
		stop:     make(chan struct{}),
		done:     make(chan struct{}),
	}
	go h.run(ctx)
	return h
}

func (h *sessionHeartbeat) run(ctx context.Context) {
	defer close(h.done)
	ticker := time.NewTicker(h.interval)
	defer ticker.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-ticker.C:
			h.touch(ctx)
		}
	}
}

// touch renews the lease if bytes have flowed since the last tick. A
// stalled connection (no new bytes) stops renewing, so the reaper can still
// recover it.
func (h *sessionHeartbeat) touch(ctx context.Context) {
	current := h.sw.BytesWritten()
	delta := current - h.lastTouched
	if delta <= 0 {
		return
	}
	if err := h.repos.Files.TouchDownloadSession(ctx, h.fileID, h.token, delta); err != nil {
		slog.Warn("failed to renew download session lease", "file_id", h.fileID, "token_hash", logTokenHash(h.token), "error", err)
		return
	}
	h.lastTouched = current
}

// Stop halts the heartbeat goroutine and waits for it to exit. Idempotent —
// safe to call from both the normal stop point and a deferred safety net.
func (h *sessionHeartbeat) Stop() {
	h.stopOnce.Do(func() { close(h.stop) })
	<-h.done
}

// FinalFlush touches any bytes written since the last heartbeat tick, using
// the given (typically detached-from-the-request) context. Call after Stop
// so run() is no longer concurrently reading/writing lastTouched.
func (h *sessionHeartbeat) FinalFlush(ctx context.Context) {
	h.touch(ctx)
}
