package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
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

// sessionWriterReadFromChunk bounds how many bytes a single call into the
// underlying ResponseWriter's own ReadFrom (net/http's sendfile-capable
// *response, reached once this stream is past the commit gate — see
// ReadFrom below) is allowed to move before sessionWriter regains control to
// update `written`. A raw, unbounded ReadFrom call blocks in the kernel for
// the whole remainder of a large transfer with no opportunity for Go code to
// run, which would leave BytesWritten() — read concurrently by the
// heartbeat goroutine in claim_session.go to compute bytes_served deltas —
// stale for that entire span. Chunking bounds that staleness to roughly one
// chunk's transfer time while still collapsing the overwhelming majority of
// a large download into a handful of sendfile syscalls instead of one
// io.Copy Write call per ~32KB buffer.
//
// 1MiB (not larger): keeps the heartbeat's bytes_served view reasonably
// fresh — at 1MiB, even a slow ~1MB/s connection updates roughly once a
// second, not once every several — for a syscall-count cost that's still
// negligible next to the win sendfile itself provides. A 512MB file is
// ~512 ReadFrom/sendfile calls at this size versus ~16000 buffered Write
// calls without sendfile at all (32KB io.Copy buffer); each additional
// syscall from shrinking the chunk 4x (relative to an earlier 4MiB value)
// costs low-single-digit microseconds, on the order of a millisecond total
// even for a multi-GB transfer — immaterial next to the ~860ms/512MB
// (measured) sendfile itself saves over the buffered-copy fallback.
const sessionWriterReadFromChunk = 1 * 1024 * 1024

// ReadFrom implements io.ReaderFrom so a capped (max_downloads-limited)
// plaintext download can still reach the sendfile fast path instead of
// falling back to a buffered io.Copy loop through Write for every chunk —
// claimServeWriter.ReadFrom (claim_range.go) delegates to this when present.
//
// It is built to be provably equivalent to driving the same bytes through
// repeated Write calls, for every value Write's callers observe:
// ResponseOK/committed/wholeFile/threshold drive the same commit decision;
// BytesWritten/Committed/CreditedNow/CommitAttempted end at the same values;
// and, critically, a stream that ends exactly at or before the free
// threshold never commits — matching what happens when a Write-based
// caller's loop simply stops issuing calls at that point, rather than ever
// calling Write with a (possibly zero-length) final chunk.
//
// The proof sketch: cumulative bytes moved is the only thing Write's commit
// check depends on (not how the caller chose to chunk them), so as long as
// ReadFrom (a) never lets more than `threshold` bytes flow before either
// resolving "no more data" or committing, and (b) commits before any byte
// past that point is delivered, the outcome is identical regardless of the
// exact chunk boundaries used internally. See the phase comments below for
// how each part is achieved.
//
// Encrypted downloads never reach this: they're served through
// idleDeadlineWriter, which deliberately hides ReadFrom from its own method
// set (see that type's doc comment in claim_range.go) so http.ServeContent
// never discovers a ReadFrom-capable writer for that path — content there is
// an *utils.SFSEReader anyway, never an *os.File, so there is no sendfile
// opportunity to gain by not hiding it.
func (sw *sessionWriter) ReadFrom(src io.Reader) (int64, error) {
	if sw.err != nil {
		return 0, sw.err
	}

	var total int64

	// Phase 1/2: resolve the commit-threshold decision exactly as Write
	// would, without yet touching the underlying ResponseWriter's own
	// ReadFrom — going straight to the fast path here would bypass the gate
	// entirely and let unpaid-for bytes out the door.
	if sw.ResponseOK() && !sw.committed {
		remaining := int64(0)
		if !sw.wholeFile {
			remaining = sw.threshold - sw.written.Load()
			if remaining < 0 {
				remaining = 0
			}
		}
		// wholeFile forces remaining to 0 regardless of the threshold value,
		// matching Write's `sw.wholeFile ||` short-circuit: ADR-012 Policy A
		// commits on the very first byte of a whole-file response no matter
		// how large the probe threshold would otherwise allow.

		if remaining > 0 {
			// Free-threshold prefix: deliver up to `remaining` bytes through
			// the ordinary gated Write path. onlyWriter strips ReadFrom from
			// the destination's method set so io.CopyN's own internal
			// io.Copy can't rediscover this very method on sw and recurse.
			// Cumulative written never exceeds threshold while inside this
			// call, so Write's own commit check can't fire mid-prefix.
			n, err := io.CopyN(onlyWriter{sw}, src, remaining)
			total += n
			if err != nil {
				if err == io.EOF {
					// Stream ended at or before the free threshold: a
					// Write-based caller's loop would likewise simply have
					// stopped issuing calls here, with no commit ever
					// attempted. Same outcome, non-sticky (io.EOF here is
					// success, not failure).
					return total, nil
				}
				// A plain read (src) or write (destination) error — not
				// sticky, matching Write's treatment of an ordinary
				// underlying-write failure (only a failed commit poisons
				// sw.err; see commitNow's doc comment).
				return total, err
			}
		}

		// Exactly `remaining` bytes (or nothing, if wholeFile / the
		// threshold was already met) have been delivered without
		// committing, and src's exhaustion is still unknown. Peek exactly
		// one byte — the minimum possible read — to find out: a stream that
		// ends precisely here must still never commit, same as Write's
		// caller never issuing a further call.
		var one [1]byte
		pn, perr := io.ReadFull(src, one[:])
		if pn == 0 {
			if perr != nil && perr != io.EOF {
				return total, perr
			}
			return total, nil
		}

		// There is at least one more byte: this is the call that would have
		// pushed cumulative bytes past threshold (or the very first call at
		// all, for wholeFile / threshold-0) — commit now, before sending any
		// of it, exactly like Write commits before writing the chunk that
		// crosses the boundary.
		if err := sw.commitNow(); err != nil {
			sw.err = err
			return total, err
		}

		n, err := sw.Write(one[:pn])
		total += int64(n)
		if err != nil {
			return total, err
		}
	}

	// Phase 3: committed (or never gated at all — an error response, where
	// Write never applies the threshold check either). Drain the rest
	// through the underlying ResponseWriter's own ReadFrom when it has one,
	// in bounded chunks (see sessionWriterReadFromChunk) so BytesWritten()
	// doesn't go dark for the whole remainder of a large transfer;
	// otherwise fall back to a plain buffered copy through Write — still
	// correct, just without the sendfile fast path.
	rf, ok := sw.ResponseWriter.(io.ReaderFrom)
	if !ok {
		n, err := io.Copy(onlyWriter{sw}, src)
		return total + n, err
	}

	// In production, src is always already an *io.LimitedReader: it arrives
	// here as exactly the one io.LimitReader(content, sendSize) that
	// http.ServeContent's io.CopyN constructs once (net/http/fs.go) and
	// hands straight to ReadFrom via io.Copy's ReaderFrom fast path — never
	// re-wrapped by anything in between. That single layer matters: both
	// net.sendFile (net/sendfile.go) and net/http's own (*response).ReadFrom
	// unwrap only ONE level of *io.LimitedReader before requiring what's
	// left to satisfy syscall.Conn (i.e. be an *os.File) — response.ReadFrom
	// even says so directly ("to avoid ... having to unnest readers
	// repeatedly in net.sendFile, just adjust the existing LimitedReader N").
	// Wrapping src in a second io.LimitReader here — as an earlier version
	// of this method did, to bound each chunk — makes that unwrap land on
	// an *io.LimitedReader instead of an *os.File, so the syscall.Conn
	// assertion fails, sendfile silently declines ("handled=false"), and
	// every capped plaintext download fell back to a buffered copy instead.
	// The fix: reuse the identical *io.LimitedReader object across every
	// chunk, temporarily capping and restoring its own N field instead of
	// allocating a nested wrapper — exactly the pattern response.ReadFrom
	// itself uses.
	//
	// A src that ISN'T already an *io.LimitedReader (never happens via
	// http.ServeContent, but true of this package's own unit tests that
	// call ReadFrom directly) falls back to wrapping once per chunk — safe,
	// since there's no pre-existing LimitedReader layer to double up on.
	if lr, isLimited := src.(*io.LimitedReader); isLimited {
		remaining := lr.N
		for remaining > 0 {
			chunk := remaining
			if chunk > sessionWriterReadFromChunk {
				chunk = sessionWriterReadFromChunk
			}
			lr.N = chunk
			n, err := rf.ReadFrom(lr)
			sw.written.Add(n)
			total += n
			remaining -= n
			if err != nil {
				return total, err
			}
			if n == 0 {
				// The underlying reader gave nothing this call (e.g. the
				// file turned out shorter than the caller's declared
				// length) — fail safe and stop instead of spinning.
				return total, nil
			}
		}
		return total, nil
	}

	for {
		n, err := rf.ReadFrom(io.LimitReader(src, sessionWriterReadFromChunk))
		sw.written.Add(n)
		total += n
		if err != nil {
			return total, err
		}
		if n == 0 {
			// A zero-byte chunk with no error means the limited reader had
			// nothing left to give — src is exhausted. (A full chunk with
			// src also exhausted just costs one extra, cheap iteration that
			// discovers the same thing here.)
			return total, nil
		}
	}
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
