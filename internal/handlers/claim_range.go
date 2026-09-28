package handlers

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/metrics"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
)

// decryptAdmissionWaitTimeout bounds how long a request waits for a slot in
// the global decrypt-memory admission budget (decryptAdmission, sized from
// DOWNLOAD_DECRYPT_MEMORY_BUDGET) before giving up with a 503. Short and
// fixed, not operator-configurable: a request that can't get a slot within
// a few seconds is better told to retry than left queued behind an
// unpredictable number of other downloads.
const decryptAdmissionWaitTimeout = 3 * time.Second

// claimRangeDecision resolves r's Range/If-Range headers against file's
// current size/ETag/Last-Modified, returning both the decision and the ETag
// it was resolved against (callers that also need to set the `ETag`
// response header, or compare it elsewhere, reuse this value instead of
// recomputing it separately). Both claim_session.go (which must know the
// decision before any bytes are written, to size its session/
// reservation-byte accounting) and serveFileWithRangeSupport (which
// rewrites the request and drives http.ServeContent) call this exact
// function so their two independent calls — pure and deterministic given
// identical inputs — can never disagree about what this request will
// actually receive.
func claimRangeDecision(r *http.Request, file *models.File) (utils.RangeDecision, string) {
	etag := utils.ComputeClaimETag(file.StoredFilename, file.FileSize, file.CreatedAt)
	return utils.ResolveRange(r, file.FileSize, etag, file.CreatedAt), etag
}

// claimServeWriter is a thin bookkeeping wrapper installed around whatever
// ResponseWriter serveFileWithRangeSupport was given (a plain
// http.ResponseWriter for an uncapped download, or a *sessionWriter for a
// capped one — see claim_session.go) so this function can determine
// `commitable` uniformly for both without the caller needing to expose its
// own status/byte counters.
//
// It also implements io.ReaderFrom, delegating to the wrapped writer's own
// ReaderFrom when available (T33): http.ServeContent's io.CopyN hands the
// ResponseWriter a bounded io.Reader via that interface when present, and
// net/http's own writer specially recognizes that reader (when it wraps an
// *os.File, as it does for a plaintext download's content) to drive
// sendfile. Without an explicit ReadFrom here, that chain would silently
// break at this wrapper and fall back to a buffered copy loop even though
// everything below it supports the fast path.
type claimServeWriter struct {
	http.ResponseWriter
	status  int
	written int64
	err     error
}

func (cw *claimServeWriter) WriteHeader(code int) {
	if cw.status == 0 {
		cw.status = code
	}
	cw.ResponseWriter.WriteHeader(code)
}

func (cw *claimServeWriter) Write(p []byte) (int, error) {
	if cw.status == 0 {
		cw.status = http.StatusOK
	}
	n, err := cw.ResponseWriter.Write(p)
	cw.written += int64(n)
	if err != nil {
		cw.err = err
	}
	return n, err
}

// ReadFrom delegates to the wrapped writer's own ReadFrom when it has one,
// preserving src's identity (in particular, an *io.LimitedReader wrapping
// an *os.File) so the sendfile fast path can propagate all the way down to
// net/http's real connection writer. See the type doc.
func (cw *claimServeWriter) ReadFrom(src io.Reader) (int64, error) {
	if cw.status == 0 {
		cw.status = http.StatusOK
	}
	rf, ok := cw.ResponseWriter.(io.ReaderFrom)
	if !ok {
		n, err := io.Copy(onlyWriter{cw.ResponseWriter}, src)
		cw.written += n
		if err != nil {
			cw.err = err
		}
		return n, err
	}
	n, err := rf.ReadFrom(src)
	cw.written += n
	if err != nil {
		cw.err = err
	}
	return n, err
}

// Flush implements http.Flusher by delegating, if the wrapped writer
// supports it, so a streamed response still gets early time-to-first-byte
// flushing through this wrapper.
func (cw *claimServeWriter) Flush() {
	if f, ok := cw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the wrapped ResponseWriter for http.ResponseController and
// any other type-assertion-based middleware walking the wrapper chain.
func (cw *claimServeWriter) Unwrap() http.ResponseWriter {
	return cw.ResponseWriter
}

// onlyWriter strips every method except Write from w, so passing it as
// io.Copy's dst can never rediscover a ReadFrom method (on this type or
// whatever it wraps) and recurse back into claimServeWriter.ReadFrom.
type onlyWriter struct{ io.Writer }

// defaultIdleWriteInterval is how often serveFileWithRangeSupport resets
// the write deadline on an encrypted (SFSE/legacy) GET download's response
// while bytes are actively flowing — see idleDeadlineWriter. A package var
// (not a const) so tests can shrink it instead of waiting out a realistic
// idle window.
var defaultIdleWriteInterval = 60 * time.Second

// minDecryptWriteRateBytesPerSecond is the slowest sustained *average*
// write rate an encrypted download's idle-deadline enforcement (see
// idleDeadlineWriter) will tolerate for the rest of a transfer: 16 KiB/s.
// Documents the intended production default; minDecryptWriteRate (below) is
// what's actually consulted at runtime, so tests can shrink it.
const minDecryptWriteRateBytesPerSecond int64 = 16 * 1024

// minDecryptWriteRate is the var idleDeadlineWriter actually reads. A
// package var (not a plain use of the const above) so tests can override it
// without waiting out a realistic multi-KB/multi-second drip.
var minDecryptWriteRate = minDecryptWriteRateBytesPerSecond

// idleDeadlineWriter wraps a ResponseWriter for an encrypted claim
// download so that, instead of holding a single write deadline for up to
// the full transfer deadline (up to 6h — see extendTransferDeadline in
// helpers.go) regardless of whether the client is actually making
// progress, the deadline is continuously recomputed as the *minimum* of
// three bounds — see computeDeadline — so a client that stops reading, or
// one that reads too slowly to matter, has the connection torn down well
// before the full transfer deadline instead of pinning this download's
// decrypt-admission weight (ADR-017 §2, utils.DecryptAdmission) for
// however long that deadline allows.
//
// Security-audit finding (HIGH, round 2): two raw TCP clients that sent a
// GET and never read the response reproduced a server-wide 503 — every
// other encrypted download was starved of admission budget, held by
// connections that were making no progress at all, for up to the full 6h
// transfer deadline. The first fix (re-tightening the deadline after every
// successful Write) closed the case where at least one Write had already
// succeeded — a genuinely stalled connection's *next* Write would then
// block until the by-then-short deadline fires, errors out, and
// serveFileWithRangeSupport's deferred admission Release runs as soon as
// the function returns.
//
// Security-audit finding (HIGH, round 3): that fix still left the *first*
// Write unprotected — the deadline was only ever reset *after* a successful
// Write, so a client that blocks the very first Write (an h2c client that
// advertises a zero initial flow-control window and never sends
// WINDOW_UPDATE, or an HTTP/1.1 client with a small enough receive buffer
// that the first ~32KB write blocks before ever returning) still held
// admission until the full absolute deadline, because the reset that would
// have shortened it never got a chance to run. The deadline is now armed
// (computeDeadline, applied) once at construction — before ServeContent
// ever calls Write — closing that gap for the very first write, not just
// every write after the first.
//
// It deliberately does NOT implement io.ReaderFrom, even though the
// ResponseWriter it wraps (csw) might: http.ServeContent's io.CopyN prefers
// a ReadFrom on its destination when available, which would hand the
// entire copy to a downstream writer in one call and bypass this type's
// Write hook (and therefore the deadline recompute) entirely. This is
// achieved simply by embedding the http.ResponseWriter *interface* (whose
// method set doesn't include ReadFrom) rather than csw's concrete type
// (whose method set does) — Go only promotes the embedded static type's
// methods, so ReadFrom is invisible on idleDeadlineWriter regardless of
// what the dynamic value underneath actually supports. SFSE/legacy content
// is never backed by an *os.File anyway, so hiding ReadFrom here costs no
// sendfile opportunity — see claimServeWriter's doc for the (plaintext-only)
// case where ReadFrom matters.
type idleDeadlineWriter struct {
	http.ResponseWriter
	rc       *http.ResponseController
	idle     time.Duration
	absolute time.Time
	start    time.Time
	written  int64
}

// newIdleDeadlineWriter constructs an idleDeadlineWriter and immediately
// arms its deadline — before returning, i.e. before ServeContent ever calls
// Write on it (round-3 fix, see the type doc). rc must control the same
// underlying connection as w (typically http.NewResponseController(w) —
// the caller builds it once so this function doesn't need w to also
// implement Unwrap).
func newIdleDeadlineWriter(w http.ResponseWriter, rc *http.ResponseController, absolute time.Time) *idleDeadlineWriter {
	idw := &idleDeadlineWriter{
		ResponseWriter: w,
		rc:             rc,
		idle:           defaultIdleWriteInterval,
		absolute:       absolute,
		start:          time.Now(),
	}
	idw.applyDeadline()
	return idw
}

func (idw *idleDeadlineWriter) Write(p []byte) (int, error) {
	n, err := idw.ResponseWriter.Write(p)
	idw.written += int64(n)
	if err == nil {
		idw.applyDeadline()
	}
	return n, err
}

// computeDeadline returns the minimum of three bounds:
//
//   - idw.absolute: extendTransferDeadline's original cap — never loosened
//     past this regardless of the other two.
//   - now + idw.idle: the per-write idle cap (round 2) — a connection that
//     hasn't written anything recently is cut off within idle.
//   - idw.start + idw.idle + written/minDecryptWriteRate: an
//     average-progress floor (round 3, MEDIUM finding: "slow-drip" —
//     writing just enough every idle-1-second to keep resetting the
//     per-write cap above could otherwise stretch a transfer out to the
//     full absolute deadline regardless of how little data actually
//     moved). grace before this floor engages is idw.idle itself, matching
//     the per-write cap's own window, so a slow-starting-but-otherwise-fine
//     transfer isn't penalized in its first idle window.
//
// A client sustaining at least minDecryptWriteRate bytes/sec on average
// never hits the third bound before the connection naturally finishes; one
// sustaining less eventually does, regardless of how diligently it keeps
// each individual per-write gap under idle.
func (idw *idleDeadlineWriter) computeDeadline() time.Time {
	// Security-audit finding (round 4, latent): start from perWrite
	// (now+idle), which is always a well-defined, non-zero bound, rather
	// than from idw.absolute. idw.absolute can be the zero Time (should
	// never happen via the production call path — see
	// serveFileWithRangeSupport's !transferDeadline.IsZero() guard before
	// constructing this type at all — but computeDeadline must fail safe
	// regardless of caller discipline): starting from a zero absolute and
	// never correcting it would return the zero Time as the deadline, and
	// to net.Conn.SetWriteDeadline a zero Time means "no deadline at all,"
	// the exact opposite of what this function exists to enforce. absolute
	// is instead only applied as an optional *tightening* bound, when it's
	// actually set.
	deadline := time.Now().Add(idw.idle)
	if !idw.absolute.IsZero() && idw.absolute.Before(deadline) {
		deadline = idw.absolute
	}

	rate := minDecryptWriteRate
	if rate < 1 {
		rate = 1
	}
	avgFloor := idw.start.Add(idw.idle).Add(time.Duration(idw.written/rate) * time.Second)
	if avgFloor.Before(deadline) {
		deadline = avgFloor
	}

	return deadline
}

// applyDeadline computes and sets the current deadline. Called once at
// construction (arming it before the first Write) and after every
// subsequent successful Write.
func (idw *idleDeadlineWriter) applyDeadline() {
	if err := idw.rc.SetWriteDeadline(idw.computeDeadline()); err != nil {
		slog.Debug("failed to apply idle write deadline", "error", err)
	}
}

// restoreAbsoluteDeadline resets the write deadline back to the plain
// absolute transfer deadline that was already in effect before this writer
// ever tightened it — the same value extendTransferDeadline established at
// the very start of the request, before any encrypted-specific handling.
// Callers must invoke this once after http.ServeContent returns.
//
// Security-audit finding (LOW, round 3): without this, a keep-alive
// connection served by a deployment running with WRITE_TIMEOUT=0 (so
// nothing else ever re-establishes a sane deadline) would carry forward
// whatever short idle/average-rate-derived deadline was in effect at the
// moment the response finished — a deadline computed for a since-completed
// encrypted download, with no relationship to the next request that reuses
// this connection. Restoring to the plain absolute deadline (not clearing
// it to zero, which would mean "no deadline at all" and reopen a different
// hang risk) reproduces exactly what a non-idle-managed request already
// left behind before this feature existed.
func (idw *idleDeadlineWriter) restoreAbsoluteDeadline() {
	if err := idw.rc.SetWriteDeadline(idw.absolute); err != nil {
		slog.Debug("failed to restore absolute write deadline", "error", err)
	}
}

// headOnlySeeker is a minimal io.ReadSeeker that reports a fixed logical
// size, with no backing content at all. It exists for a HEAD request
// against a legacy-encrypted file (see the FormatLegacy case in
// serveFileWithRangeSupport): http.ServeContent needs an io.ReadSeeker to
// call Seek(0, io.SeekEnd) for the size (and, for a ranged HEAD,
// Seek(start, io.SeekStart)), but — once Range has already been resolved to
// zero-or-one ranges by this package's own rule-1 rewrite, so the
// multipart/byteranges branch that reads from content is never reached —
// it never calls Read for a HEAD request. Read is implemented defensively
// (reports EOF) rather than omitted, so a future stdlib behavior change or
// a bug in the Range rewrite fails safe (an empty body) instead of a nil
// pointer or interface panic.
type headOnlySeeker struct {
	size int64
	pos  int64
}

func (s *headOnlySeeker) Read(p []byte) (int, error) {
	return 0, io.EOF
}

func (s *headOnlySeeker) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = s.pos + offset
	case io.SeekEnd:
		newPos = s.size + offset
	default:
		return 0, fmt.Errorf("headOnlySeeker: invalid whence %d", whence)
	}
	if newPos < 0 {
		return 0, fmt.Errorf("headOnlySeeker: negative resulting position %d", newPos)
	}
	s.pos = newPos
	return newPos, nil
}

// sfseAdmissionWeight returns the byte weight to charge the decrypt
// admission budget for an SFSE stream opened from f: one chunk buffer's
// worth (chunk_size + per-chunk nonce/tag overhead), matching what
// OpenSFSEReader actually allocates and holds for the stream's lifetime
// (see sfse_readseeker.go). It re-reads the small fixed-size header
// directly (via ReadAt, so it doesn't disturb any other reader's position
// on f) rather than calling ClassifyStoredFile a second time or requiring
// utils to expose chunk_size from its return value.
//
// Falls back to the default (10MB) chunk size — the overwhelming common
// case — if the header can't be read or parsed here for any reason;
// OpenSFSEReader itself is the authority that will reject a genuinely
// malformed header a moment later, so under-charging here in that edge
// case only risks slightly looser admission control, never an incorrect
// decrypt.
func sfseAdmissionWeight(f *os.File) int64 {
	fallback := utils.DefaultChunkSize + int64(utils.SFSE2OverheadPerChunk)

	var hdr [10]byte
	n, err := f.ReadAt(hdr[:], 0)
	if err != nil && err != io.EOF {
		return fallback
	}
	if n < 10 {
		return fallback
	}
	chunkSize := int64(binary.LittleEndian.Uint32(hdr[6:10]))
	if chunkSize <= 0 || chunkSize > utils.MaxSFSEChunkSize {
		return fallback
	}
	return chunkSize + int64(utils.SFSE2OverheadPerChunk)
}

// perIPShareCap returns the per-client decrypt-memory share cap to enforce
// (see decryptShareTracker's doc), given the currently-installed admission
// budget and per-IP concurrency tracker.
//
// Security-audit finding (MEDIUM, round 3): when ipTracker is nil (the
// operator set MAX_ENCRYPTED_DOWNLOADS_PER_IP=0 to disable the per-IP
// concurrency cap — the documented, intended way to say "no per-client
// limits, only the global budget applies," e.g. for a Tor hidden service
// where every visitor shares one apparent address), the per-client memory
// SHARE must be disabled too. Previously it wasn't: capShare was always
// Capacity()/4 regardless, so setting the concurrency cap to 0 still left
// every visitor behind a shared apparent address splitting a single
// quarter of the budget between them. Returning 0 here (which
// decryptShareTracker.tryReserve already treats as "disabled") when
// ipTracker is nil closes that.
func perIPShareCap(admission *utils.DecryptAdmission, ipTracker *InFlightTracker) int64 {
	if ipTracker == nil {
		return 0
	}
	return admission.Capacity() / 4
}

// acquireDecryptAdmission acquires weight bytes from the global
// decrypt-memory budget, this client's share of it (see perIPShareCap), and
// the per-IP encrypted-range concurrency counter. Order: the per-IP share is
// reserved FIRST (cheapest check, and reserving it before the — potentially
// blocking — global Acquire means a client already at its share cap gets
// rejected immediately instead of occupying a place in the global FIFO
// queue while it waits for a share it could never legally hold), then the
// global budget, then the per-IP concurrency counter.
//
// Security-audit finding (LOW, round 3): decryptAdmission,
// encryptedRangeIPTracker, and decryptShare are captured into locals here,
// at acquire time, rather than read directly from the package-level vars
// inside the returned closure. The closure can run much later — after the
// full download has streamed — by which point a config hot-reload or (in
// tests) another goroutine's SetDecryptAdmission/SetEncryptedRangeIPTracker
// call could have swapped those package vars out from under it; reading
// them again at release time could then release into a completely
// different instance than the one this download actually acquired from.
//
// Returns a release func to defer, or (nil, false) with the response
// already written (503/429, Retry-After) if any of the three is
// unavailable.
func acquireDecryptAdmission(w http.ResponseWriter, r *http.Request, cfg *config.Config, file *models.File, weight int64) (release func(), ok bool) {
	admission := decryptAdmission
	ipTracker := encryptedRangeIPTracker
	share := decryptShare

	clientIP := getClientIP(r)
	ipKey := decryptShareIPKey(clientIP)

	clamped := admission.ClampWeight(weight)
	capShare := perIPShareCap(admission, ipTracker)
	shareAdmitted, shareReserved := share.tryReserve(ipKey, clamped, capShare)
	if !shareAdmitted {
		slog.Warn("per-IP decrypt-memory share exhausted",
			"claim_code", redactClaimCode(file.ClaimCode), "weight", clamped,
			"client_ip", logIP(clientIP, cfg),
		)
		w.Header().Set("Retry-After", "5")
		sendErrorResponse(w, r, "Too Many Concurrent Downloads", "You have too many encrypted downloads in progress. Please wait for them to finish and try again.", "TOO_MANY_INFLIGHT", http.StatusTooManyRequests)
		return nil, false
	}
	// Security-audit finding (round 4): release the share only if
	// tryReserve actually recorded one (shareReserved) — not merely
	// because this request was admitted (shareAdmitted), which is also
	// true when per-client share enforcement is disabled (capShare<=0) and
	// nothing was recorded at all. Releasing an unrecorded reservation
	// could decrement a different, still-active reservation for the same
	// key. See decryptShareTracker.tryReserve's doc.

	admitCtx, cancel := context.WithTimeout(r.Context(), decryptAdmissionWaitTimeout)
	admittedWeight, err := admission.Acquire(admitCtx, weight)
	cancel()
	if err != nil {
		if shareReserved {
			share.release(ipKey, clamped)
		}
		slog.Warn("decrypt admission budget exhausted",
			"claim_code", redactClaimCode(file.ClaimCode), "weight", weight, "error", err,
			"client_ip", logIP(clientIP, cfg),
		)
		w.Header().Set("Retry-After", "2")
		sendErrorResponse(w, r, "Server Busy", "The server is currently handling too many encrypted downloads. Please try again shortly.", "SERVER_BUSY", http.StatusServiceUnavailable)
		return nil, false
	}

	if !ipTracker.TryAcquire(encryptedRangeIPTrackerKey, ipKey) {
		admission.Release(admittedWeight)
		if shareReserved {
			share.release(ipKey, clamped)
		}
		slog.Warn("too many concurrent encrypted downloads for client IP",
			"claim_code", redactClaimCode(file.ClaimCode),
			"client_ip", logIP(clientIP, cfg),
			"max_per_ip", ipTracker.MaxPerIP(),
		)
		w.Header().Set("Retry-After", "5")
		sendErrorResponse(w, r, "Too Many Concurrent Downloads", "You have too many encrypted downloads in progress. Please wait for them to finish and try again.", "TOO_MANY_INFLIGHT", http.StatusTooManyRequests)
		return nil, false
	}

	return func() {
		ipTracker.Release(encryptedRangeIPTrackerKey, ipKey)
		admission.Release(admittedWeight)
		if shareReserved {
			share.release(ipKey, clamped)
		}
	}, true
}

// serveFileWithRangeSupport serves file's content (GET or HEAD) through
// http.ServeContent, handling plaintext, SFSE1/SFSE2, and legacy encrypted
// storage formats. See ADR-017 for the full design; in short:
//
//  1. The file is opened, classified (utils.ClassifyStoredFile — never the
//     old len(header)>=29 heuristic), and — for SFSE — a validating reader
//     is opened and its first chunk primed, ALL before a single response
//     header is written. A missing encryption key, a size that matches no
//     recognized format, or a corrupt/truncated SFSE header all therefore
//     fail closed with a clean 500 and no partial 200/206 ever started
//     (closes T6, T9, T14, T27's "headers written before file open").
//  2. Content-Type, Content-Disposition, ETag, and Cache-Control are set
//     explicitly before ServeContent is ever called — Content-Type so
//     ServeContent never sniffs it (which would decrypt chunk 0 on every
//     request that omits it), ETag so ServeContent's own conditional-
//     request handling (If-None-Match/If-Match/If-Modified-Since/
//     If-Unmodified-Since) has a strong validator to check against.
//  3. This request's Range/If-Range are resolved once via
//     claimRangeDecision (utils.ResolveRange) and the request is rewritten
//     before ServeContent sees it: Range is deleted on a Full decision,
//     rewritten to the single canonical range on Partial, and If-Range is
//     always deleted (our policy already decided it) — otherwise
//     ServeContent's own RFC 9110-compliant-but-different Range parsing
//     (which supports multipart/byteranges) could re-decide differently,
//     including serving a multipart response whose extra parts would each
//     cost their own chunk decrypt. RangeUnsatisfiable is answered directly
//     with a 416 and never reaches ServeContent.
//  4. A conditional-request match (304/412) is entirely handled by
//     ServeContent's own checkPreconditions, which runs before it ever
//     calls Seek/Read on content — so on a 304 nothing downstream of that
//     point (bytes written, download-session commit) ever happens. This
//     does mean an SFSE 304 still pays the step-1 chunk-0-prime cost, since
//     that validation happens unconditionally before headers/preconditions
//     are even evaluated; ADR-017 documents this as a deliberate
//     simplicity/fail-closed tradeoff over a lazy-open scheme that would
//     avoid it.
//
// Returns commitable=true only when this specific request (GET, not HEAD)
// received a 200 or a 206 covering the entire file, and every expected byte
// was actually written with no error — matching the pre-ServeContent
// contract this function's callers (claim.go, claim_session.go) already
// rely on to decide CommitDownload vs CancelDownload/no-op.
//
// transferDeadline is the absolute write-deadline cap the caller already
// applied via extendTransferDeadline (up to 6h for a large file) before
// calling this function; the zero value means no deadline management is
// needed (the HEAD path never streams a body, so it passes one through
// unused). serveFileWithRangeSupport itself never sets it looser than this
// — see idleDeadlineWriter — only tighter, as a security-audit fix for a
// stalled reader otherwise pinning decrypt-admission weight for however
// long transferDeadline allows.
func serveFileWithRangeSupport(
	w http.ResponseWriter,
	r *http.Request,
	file *models.File,
	filePath string,
	cfg *config.Config,
	transferDeadline time.Time,
) (commitable bool) {
	// IsStreamEncrypted/os.Open wrap the underlying error with fmt.Errorf's
	// %w, so this must use errors.Is(err, fs.ErrNotExist) rather than
	// os.IsNotExist(err), which predates error wrapping.
	f, err := os.Open(filePath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			slog.Error("file not found on disk", "path", filePath, "claim_code", redactClaimCode(file.ClaimCode))
			sendErrorResponse(w, r, "File Not Found", "The file could not be found on the server. It may have been deleted. Please contact the administrator.", "NOT_FOUND", http.StatusNotFound)
			return false
		}
		slog.Error("failed to open file", "path", filePath, "error", err)
		sendErrorResponse(w, r, "Server Error", "An error occurred while reading the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
		return false
	}
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		slog.Error("failed to stat file", "path", filePath, "error", err)
		sendErrorResponse(w, r, "Server Error", "An error occurred while reading the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
		return false
	}

	format, err := utils.ClassifyStoredFile(f, fi, file.FileSize, utils.IsEncryptionEnabled(cfg.EncryptionKey))
	if err != nil {
		fields := []any{"path", filePath, "claim_code", redactClaimCode(file.ClaimCode), "error", err}
		switch {
		case errors.Is(err, utils.ErrEncryptionKeyMissing):
			slog.Error("stored file requires an encryption key but none is configured; refusing to stream ciphertext (fail closed)", fields...)
		case errors.Is(err, utils.ErrStoredSizeMismatch):
			slog.Error("stored file size matches no recognized format; refusing to serve", fields...)
		default:
			slog.Error("failed to classify stored file", fields...)
		}
		sendErrorResponse(w, r, "Server Error", "An error occurred while reading the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
		return false
	}

	// sfseReader, when non-nil, is checked for a mid-stream integrity/
	// decrypt failure after http.ServeContent returns (security-audit
	// finding: such a failure — e.g. a chunk's AEAD tag failing to
	// authenticate, or the whole-file SHA-256 mismatching once the last
	// chunk is reached — occurred *after* headers were already sent, so it
	// could only ever surface as a silently truncated response; nothing
	// checked ServeContent's implicit outcome for it). Declared here so
	// it's visible after the switch below.
	var sfseReader *utils.SFSEReader

	var content io.ReadSeeker
	switch format {
	case utils.FormatPlaintext:
		// *os.File served directly: this is what lets the sendfile fast
		// path (T33) reach all the way down for a plaintext download.
		content = f

	case utils.FormatSFSE1, utils.FormatSFSE2:
		weight := sfseAdmissionWeight(f)
		release, ok := acquireDecryptAdmission(w, r, cfg, file, weight)
		if !ok {
			return false
		}
		defer release()

		// SFSE1 and SFSE2 share one reader: OpenSFSEReader dispatches on
		// the header's version byte, and its whole-file SHA-256 check
		// (when sha256Hex is non-empty) is format-agnostic — it only
		// engages for a strictly sequential from-offset-0 read, so passing
		// file.SHA256Hash unconditionally here is what gives SFSE1
		// exact-size + SHA-256 enforcement it never had before (ADR-017
		// rule 5), with no special-casing needed: an empty SHA256Hash (an
		// older row that predates hash tracking) simply leaves the check
		// disabled, same as before.
		reader, err := utils.OpenSFSEReader(f, fi, cfg.EncryptionKey, file.EncFileID, file.FileSize, file.SHA256Hash)
		if err != nil {
			slog.Error("failed to open SFSE reader", "path", filePath, "claim_code", redactClaimCode(file.ClaimCode), "error", err)
			sendErrorResponse(w, r, "Server Error", "An error occurred while decrypting the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
			return false
		}
		defer reader.Close()

		// Prime chunk 0 now — before any header is written — so a wrong
		// key or a corrupt/truncated first chunk surfaces as a clean 500
		// instead of a 200/206 that fails partway through the body.
		if file.FileSize > 0 {
			if err := reader.Prime(0); err != nil {
				slog.Error("SFSE integrity check failed", "path", filePath, "claim_code", redactClaimCode(file.ClaimCode), "error", err)
				sendErrorResponse(w, r, "Server Error", "An error occurred while decrypting the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
				return false
			}
		}
		content = reader
		sfseReader = reader

	case utils.FormatLegacy:
		// master finding #9 / T34: cap the in-RAM decrypt so a large
		// legacy (pre-SFSE) file can't OOM the server. An operator seeing
		// this should run migrate-encryption to upgrade the file to SFSE.
		// Enforced for HEAD too, even though HEAD never actually decrypts
		// below — the cap is also a signal to the operator that this file
		// needs upgrading, and it keeps HEAD's fail-closed behavior
		// identical to GET's for an over-cap file.
		if fi.Size() > cfg.LegacyDecryptMaxBytes {
			slog.Error("legacy encrypted file exceeds LEGACY_DECRYPT_MAX_BYTES; refusing to decrypt into memory — run migrate-encryption to upgrade it to SFSE",
				"path", filePath, "claim_code", redactClaimCode(file.ClaimCode),
				"size", fi.Size(), "limit", cfg.LegacyDecryptMaxBytes,
			)
			sendErrorResponse(w, r, "Server Error", "This file is stored in a legacy format that is too large to serve directly. Please contact the administrator.", "INTERNAL_ERROR", http.StatusInternalServerError)
			return false
		}

		// Code-review finding: a HEAD request only needs the file's size —
		// already established as consistent with the on-disk ciphertext by
		// ClassifyStoredFile's FormatLegacy check (on-disk size ==
		// dbFileSize + nonce/tag overhead) above, before this switch ever
		// ran. Decrypting the entire file into memory just to answer a
		// HEAD would spend exactly the resource LEGACY_DECRYPT_MAX_BYTES
		// and the decrypt-admission budget exist to protect, for no
		// benefit: http.ServeContent never calls Read on `content` for a
		// HEAD request once Range has already been resolved to zero-or-one
		// ranges by this function's own rule-1 rewrite below (see
		// headOnlySeeker's doc) — only Seek, to report size and (for a
		// ranged HEAD) the range's start. No admission weight is acquired
		// either, since nothing is actually decrypted.
		if r.Method == http.MethodHead {
			content = &headOnlySeeker{size: file.FileSize}
			break
		}

		release, ok := acquireDecryptAdmission(w, r, cfg, file, fi.Size())
		if !ok {
			return false
		}
		defer release()

		ciphertext, err := io.ReadAll(f)
		if err != nil {
			slog.Error("failed to read legacy encrypted file", "path", filePath, "error", err)
			sendErrorResponse(w, r, "Server Error", "An error occurred while reading the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
			return false
		}
		decrypted, err := utils.DecryptFile(ciphertext, cfg.EncryptionKey)
		if err != nil {
			slog.Error("failed to decrypt legacy file", "claim_code", redactClaimCode(file.ClaimCode), "error", err)
			sendErrorResponse(w, r, "Decryption Error", "An error occurred while decrypting the file. Please contact the administrator.", "INTERNAL_ERROR", http.StatusInternalServerError)
			return false
		}
		if int64(len(decrypted)) != file.FileSize {
			slog.Error("legacy decrypted size mismatch", "claim_code", redactClaimCode(file.ClaimCode), "got", len(decrypted), "want", file.FileSize)
			sendErrorResponse(w, r, "Server Error", "An error occurred while reading the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
			return false
		}
		content = bytes.NewReader(decrypted)

	default:
		slog.Error("unrecognized stored file format", "path", filePath, "format", format)
		sendErrorResponse(w, r, "Server Error", "An error occurred while reading the file. Please try again later.", "INTERNAL_ERROR", http.StatusInternalServerError)
		return false
	}

	// Nothing above this point wrote any response header: a corrupt/
	// truncated SFSE stream, a missing key, an oversized legacy file, or
	// any I/O error all failed with a clean 500 first (rule 2 / T6, T14,
	// T27).
	mimeType := file.MimeType
	if mimeType == "" {
		mimeType = "application/octet-stream"
	}

	w.Header().Set("Cache-Control", "private, no-store")
	w.Header().Set("Accept-Ranges", "bytes")
	w.Header().Set("Content-Type", mimeType)
	w.Header().Set("Content-Disposition", utils.ContentDisposition(file.OriginalFilename))

	decision, etag := claimRangeDecision(r, file)
	w.Header().Set("ETag", etag)
	// http.ServeContent sets Last-Modified itself when it's actually
	// called (below); the RangeUnsatisfiable branch never reaches it, so
	// it's set unconditionally here to cover that response too — matching
	// what setLastModified would have produced, and needed for the
	// precondition check just below to have a Last-Modified value to
	// compare against and report.
	lastModified := file.CreatedAt.UTC().Format(http.TimeFormat)
	w.Header().Set("Last-Modified", lastModified)

	switch decision.Kind {
	case utils.RangeUnsatisfiable:
		// Security-audit fix: RFC 9110 §13.2.2 evaluates conditional
		// headers (If-Match/If-Unmodified-Since -> 412, then
		// If-None-Match/If-Modified-Since -> 304/412) BEFORE Range is even
		// considered. http.ServeContent gets this right when it's called at
		// all, but this branch bypasses it entirely — so a client that also
		// sent a precondition (e.g. an If-None-Match matching its cached
		// copy) must still get that answer, not a 416, even though the
		// Range it sent happens to be unsatisfiable.
		if pre := utils.EvaluatePreconditions(r, etag, file.CreatedAt); pre.Status != 0 {
			if pre.Status == http.StatusNotModified {
				w.Header().Del("Content-Type")
				w.Header().Del("Content-Length")
				if w.Header().Get("Etag") != "" {
					w.Header().Del("Last-Modified")
				}
			}
			w.WriteHeader(pre.Status)
			slog.Debug("range unsatisfiable but a precondition took precedence",
				"claim_code", redactClaimCode(file.ClaimCode),
				"precondition_status", pre.Status,
			)
			return false
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes */%d", file.FileSize))
		w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
		slog.Warn("range not satisfiable",
			"claim_code", redactClaimCode(file.ClaimCode),
			"range_header", r.Header.Get("Range"),
			"file_size", file.FileSize,
			"client_ip", logIP(getClientIP(r), cfg),
		)
		return false
	case utils.RangeFull:
		// Rule 1: an absent, malformed, or multi-range Range header all
		// resolve to Full — deleting it here (rather than leaving whatever
		// the client sent) stops ServeContent's own Range parsing from
		// re-deciding differently, in particular ever serving a multipart
		// response whose extra parts would each cost their own chunk
		// decrypt.
		r.Header.Del("Range")
	case utils.RangePartial:
		r.Header.Set("Range", utils.CanonicalRangeHeader(decision))
	}
	// Our policy already resolved If-Range (as part of claimRangeDecision);
	// deleting it stops ServeContent from evaluating it a second time
	// against whatever it computes as "current" state.
	r.Header.Del("If-Range")

	wholeFile := decision.Kind == utils.RangeFull ||
		(decision.Kind == utils.RangePartial && decision.Start == 0 && decision.End == file.FileSize-1)

	csw := &claimServeWriter{ResponseWriter: w}

	// Security-audit fix (HIGH): a stalled reader on an encrypted download
	// must not pin this download's decrypt-admission weight for up to the
	// full transferDeadline (up to 6h) — see idleDeadlineWriter. Only
	// engaged for GET on an encrypted format: HEAD never writes a body
	// (nothing to stall on), and the plaintext path is left exactly as
	// before so it keeps the sendfile fast path (T33) — it never holds any
	// decrypt-admission weight in the first place, so there's nothing here
	// to protect.
	var serveWriter http.ResponseWriter = csw
	var idw *idleDeadlineWriter
	encrypted := format != utils.FormatPlaintext
	if encrypted && r.Method != http.MethodHead && !transferDeadline.IsZero() {
		idw = newIdleDeadlineWriter(csw, http.NewResponseController(csw), transferDeadline)
		serveWriter = idw
	}

	http.ServeContent(serveWriter, r, file.OriginalFilename, file.CreatedAt, content)

	// Security-audit fix (LOW, round 3): restore the write deadline to the
	// plain absolute transfer deadline idw tightened away from — not clear
	// it to zero — so a keep-alive connection reused for a following
	// request (in particular under WRITE_TIMEOUT=0, where nothing else
	// would ever re-establish a sane deadline) doesn't inherit a stale,
	// short deadline computed for this now-finished download. See
	// restoreAbsoluteDeadline's doc.
	if idw != nil {
		idw.restoreAbsoluteDeadline()
	}

	var expectedBytes int64
	switch decision.Kind {
	case utils.RangeFull:
		expectedBytes = file.FileSize
	case utils.RangePartial:
		expectedBytes = decision.End - decision.Start + 1
	}

	// Security-audit fix (MEDIUM): a mid-stream SFSE decrypt/integrity
	// failure (a chunk's AEAD tag failing to authenticate, or the
	// whole-file SHA-256 mismatching once the last chunk is decrypted) was
	// previously silent — it happens after headers are already sent, and
	// http.ServeContent's io.CopyN discards its own error return, so the
	// response just ended short with nothing logged or counted. streamErr
	// distinguishes that from an ordinary write failure (a client
	// disconnecting mid-download — Warn, unremarkable, uncounted) and is
	// folded into the "claim download served" line below either way.
	//
	// Security-audit fix (round 3): a plain I/O error reading the stored
	// ciphertext (a failing disk, not tampering or corruption) was being
	// counted under the same `integrity_failed` metric label as a genuine
	// auth-tag/hash failure, conflating two very different failure modes
	// an operator would want to alert on differently. utils.SFSEReader
	// wraps every genuine integrity failure (a chunk's AEAD auth tag, a
	// short/truncated read, or the whole-file hash) in
	// utils.ErrSFSE2IntegrityCheckFailed; a plain ReadAt error is not
	// wrapped in it, so errors.Is distinguishes them here without needing
	// SFSEReader to expose a richer error type.
	var streamErr error
	if sfseReader != nil && sfseReader.Err() != nil {
		streamErr = sfseReader.Err()
		if errors.Is(streamErr, utils.ErrSFSE2IntegrityCheckFailed) {
			metrics.DownloadsTotal.WithLabelValues("integrity_failed").Inc()
			slog.Error("SFSE decrypt/integrity failure after headers were sent",
				"claim_code", redactClaimCode(file.ClaimCode),
				"error", streamErr,
				"bytes_sent", csw.written,
			)
		} else {
			metrics.DownloadsTotal.WithLabelValues("read_error").Inc()
			slog.Error("SFSE read error after headers were sent",
				"claim_code", redactClaimCode(file.ClaimCode),
				"error", streamErr,
				"bytes_sent", csw.written,
			)
		}
	} else if csw.err != nil {
		streamErr = csw.err
		slog.Warn("claim download write failed",
			"claim_code", redactClaimCode(file.ClaimCode),
			"error", streamErr,
			"bytes_sent", csw.written,
		)
	}

	success := streamErr == nil && (csw.status == http.StatusOK || csw.status == http.StatusPartialContent)
	commitable = success && r.Method != http.MethodHead && wholeFile && csw.written == expectedBytes

	// Security-audit fix (LOW): a successful HEAD has no downloaded bytes
	// to count — it must not inflate the success counter or the size
	// histogram the way an actual file transfer does.
	if success && r.Method != http.MethodHead {
		metrics.DownloadsTotal.WithLabelValues("success").Inc()
		metrics.DownloadSizeBytes.Observe(float64(csw.written))
	}

	slog.Info("claim download served",
		"claim_code", redactClaimCode(file.ClaimCode),
		"filename", file.OriginalFilename,
		"method", r.Method,
		"status", csw.status,
		"range_kind", decision.Kind.String(),
		"bytes_sent", csw.written,
		"whole_file", wholeFile,
		"commitable", commitable,
		"error", streamErr,
		"client_ip", logIP(getClientIP(r), cfg),
		"user_agent", getUserAgent(r),
	)
	return commitable
}
