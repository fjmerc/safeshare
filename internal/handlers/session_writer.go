package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"

	"github.com/fjmerc/safeshare/internal/repository"
)

// ErrDownloadSlotLost is returned by sessionWriter.Write when a mid-stream
// commit attempt finds the download's slot already gone — the reaper
// cancelled the reservation (lease TTL elapsed) and either nobody or someone
// else took the freed slot. The stream must abort immediately: byte P+1 must
// never be written without a held slot backing it.
var ErrDownloadSlotLost = errors.New("download slot lost: reservation was reaped and could not be re-acquired")

// sessionWriter wraps an http.ResponseWriter for a capped-download (max_downloads
// set) request and applies the ADR-014 commit-threshold policy:
//
//   - A request presenting a token that resolved to a valid session
//     (`trustedToken`) is fully trusted: its threshold is forced to 0, so the
//     commit is attempted on the very first successful write — but it is
//     NOT skipped. Committing before the write means the credit would be
//     spent even if the file then turns out to be unreadable (deleted on
//     disk, decryption failure, ...); forcing threshold 0 instead keeps the
//     commit gated on data actually flowing, exactly like the tokenless
//     path, while still bypassing the byte-count math a fresh probe needs.
//     CommitDownloadSession is idempotent, so a trusted session that was
//     already committed by an earlier request just gets a fast no-op
//     (DownloadCommitAlreadyCommitted) here.
//   - A tokenless (or invalid/expired-token) request may stream up to
//     `threshold` bytes for free; the write that would push it past
//     `threshold` first commits the session via CommitDownloadSession.
//   - `wholeFile` requests (no Range header, or a Range covering the entire
//     file) commit on the very first byte regardless of `threshold` — ADR-012
//     Policy A always counts full-file delivery.
//   - The commit-threshold check only applies to a 200 or 206 response
//     (success). Error responses (404/416/500/...) always call WriteHeader
//     with a non-2xx status before writing their body, so those bodies never
//     trigger a commit — this is what keeps a resume against a since-deleted
//     file (a 404, streamed with zero bytes) from spending the credit.
//
// If a mid-stream commit reports DownloadCommitSlotLost, Write returns
// ErrDownloadSlotLost and the writer sticks in the errored state — the caller
// must treat this as a stream abort, not attempt to recover mid-response.
type sessionWriter struct {
	http.ResponseWriter

	ctx       context.Context
	repos     *repository.Repositories
	fileID    int64
	token     string
	threshold int64
	wholeFile bool

	statusCode      int
	committed       bool
	creditedNow     bool
	commitAttempted bool
	written         atomic.Int64
	err             error
}

// newSessionWriter constructs a sessionWriter. `trustedToken` means the
// caller resolved this token to a valid (not necessarily yet committed)
// session via LookupDownloadSession — see the type doc for why that forces
// threshold 0 rather than skipping the commit outright; `probeGrant` is
// ignored in that case. `wholeFile` means this request is known, before any
// bytes are written, to cover the entire file (see claim_session.go's
// Range-coverage check). `probeGrant` is the probe-threshold allowance this
// session was atomically charged for at Reserve time (repository.ReserveDownload's
// second return value) — it already accounts for the file's current
// uncounted-bytes budget, so, unlike round 2, sessionWriter does no threshold
// math of its own: computing P/B against a value read separately from the
// reservation would race against concurrent reservations on the same file
// (bug-hunter finding).
func newSessionWriter(ctx context.Context, w http.ResponseWriter, repos *repository.Repositories, fileID int64, token string, probeGrant int64, trustedToken, wholeFile bool) *sessionWriter {
	sw := &sessionWriter{
		ResponseWriter: w,
		ctx:            ctx,
		repos:          repos,
		fileID:         fileID,
		token:          token,
		wholeFile:      wholeFile,
	}
	if !trustedToken {
		sw.threshold = probeGrant
	}
	return sw
}

// ResponseOK reports whether the response is a success (200 or 206), i.e.
// whether bytes written are file content rather than an error body.
// net/http implicitly sends a 200 on the first Write if WriteHeader was never
// called — http.ServeContent (via serveFileWithRangeSupport) relies on
// exactly that behaviour for a full, non-Range download — so an unset
// status counts as 200.
func (sw *sessionWriter) ResponseOK() bool {
	status := sw.statusCode
	if status == 0 {
		status = http.StatusOK
	}
	return status == http.StatusOK || status == http.StatusPartialContent
}

// WriteHeader records the status code so Write can gate the commit-threshold
// check to success responses only, then delegates as usual.
func (sw *sessionWriter) WriteHeader(statusCode int) {
	sw.statusCode = statusCode
	sw.ResponseWriter.WriteHeader(statusCode)
}

// Write applies the commit-threshold policy described on sessionWriter, then
// delegates to the wrapped ResponseWriter.
func (sw *sessionWriter) Write(p []byte) (int, error) {
	if sw.err != nil {
		return 0, sw.err
	}

	// net/http implicitly sends a 200 on the first Write if WriteHeader was
	// never called — http.ServeContent relies on exactly that behaviour, so
	// mirror it here rather than requiring every call site to WriteHeader
	// explicitly.
	if sw.ResponseOK() && !sw.committed && (sw.wholeFile || sw.written.Load()+int64(len(p)) > sw.threshold) {
		if err := sw.commitNow(); err != nil {
			sw.err = err
			return 0, err
		}
	}

	n, err := sw.ResponseWriter.Write(p)
	sw.written.Add(int64(n))
	return n, err
}

// commitNow calls CommitDownloadSession and marks the writer committed on
// success, or sets ErrDownloadSlotLost if the slot could not be re-acquired.
// commitAttempted is set before the call, regardless of outcome: once a
// commit has actually been attempted, bytes may already be in flight to the
// client, so the caller must never fall back to CancelDownload afterwards
// even if this attempt errors out (bug-hunter M1 — see claim.go's finalize
// logic, which checks CommitAttempted alongside Committed).
func (sw *sessionWriter) commitNow() error {
	sw.commitAttempted = true
	result, err := sw.repos.Files.CommitDownloadSession(sw.ctx, sw.fileID, sw.token)
	if err != nil {
		return fmt.Errorf("commit download session mid-stream: %w", err)
	}
	if result == repository.DownloadCommitSlotLost {
		return ErrDownloadSlotLost
	}
	sw.committed = true
	if result == repository.DownloadCommitCredited {
		sw.creditedNow = true
	}
	return nil
}

// Committed reports whether the session has been credited — either it was
// already committed before this call (a trusted, previously-committed token),
// or this request's own commit attempt succeeded.
func (sw *sessionWriter) Committed() bool {
	return sw.committed
}

// CreditedNow reports whether THIS writer's own commit attempt was the one
// that moved the session from uncommitted to committed (DownloadCommitCredited),
// as opposed to finding it already committed by an earlier request
// (DownloadCommitAlreadyCommitted) or never attempting a commit at all. The
// caller uses this — not Committed — to decide whether to treat this request
// as the one that filled the download_count cap (see claim.go's justCredited).
func (sw *sessionWriter) CreditedNow() bool {
	return sw.creditedNow
}

// CommitAttempted reports whether a mid-stream commit was ever attempted,
// regardless of whether it succeeded. See commitNow's doc comment.
func (sw *sessionWriter) CommitAttempted() bool {
	return sw.commitAttempted
}

// BytesWritten returns the number of bytes written to the underlying
// ResponseWriter so far. Safe to call concurrently with Write (used by the
// heartbeat goroutine in claim.go to compute the delta for TouchDownloadSession).
func (sw *sessionWriter) BytesWritten() int64 {
	return sw.written.Load()
}

// Flush implements http.Flusher by delegating to the wrapped ResponseWriter
// if it supports it — needed so streamed downloads still get early
// time-to-first-byte flushing through this wrapper.
func (sw *sessionWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the wrapped ResponseWriter for http.ResponseController and
// any other type-assertion-based middleware that walks the wrapper chain
// (net/http has supported this pattern since Go 1.20).
func (sw *sessionWriter) Unwrap() http.ResponseWriter {
	return sw.ResponseWriter
}
