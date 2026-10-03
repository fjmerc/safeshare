package handlers

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fjmerc/safeshare/internal/audit"
	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/privacy"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/scanning"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/fjmerc/safeshare/internal/webhooks"
	"github.com/google/uuid"
)

// integrityMismatchMessage is the uploader-visible message when the
// scanned-vs-assembled content integrity check fails. Deliberately generic
// (L3 bug-hunter finding): it must not describe internal chunk paths or
// mechanics — those go to the server log instead, via logIntegrityMismatch.
const integrityMismatchMessage = "Upload could not be verified and was rejected"

// genericAssemblyFailureMessage is the uploader-visible error_message for
// every other internal assembly failure (claim-code generation, MIME
// detection, disk/encryption I/O, the file-record insert, ...). These used
// to embed the raw Go error (os path fragments, DB driver text, etc.)
// directly via fmt.Sprintf("...: %v", err) — harmless while error_message
// was log-only, but ADR-016's /complete now echoes it back in a 409 body
// and /status always has (bug-hunter finding L5: no internal detail in
// client-facing text). Every call site below still logs the real error via
// slog.Error immediately before calling w.fail/w.failWithAudit.
const genericAssemblyFailureMessage = "An internal error occurred while processing your upload. Please try again."

// scannedContentMatches reports whether assembledHash matches what
// verdict.hash recorded during the scan. verdict.hash is empty when nothing
// meaningful was scanned (scanning disabled, or content skipped for size),
// in which case there is nothing to compare and the content is treated as
// matching.
func scannedContentMatches(verdict scanVerdict, assembledHash string) bool {
	return verdict.hash == "" || verdict.hash == assembledHash
}

// logIntegrityMismatch logs a scanned/assembled content mismatch at ERROR:
// this is a TOCTOU attack signature (bug-hunter finding), not a routine
// failure, and should be alerted on.
func logIntegrityMismatch(uploadID string) {
	slog.Error("scanned content does not match assembled content; rejecting upload (possible TOCTOU tampering)",
		"upload_id", uploadID,
	)
}

// scanRetryBackoff is the chunked-upload malware-scan retry schedule
// (ADR-015): a transient clamd hiccup during assembly gets three retries
// before the upload is failed (or, under MALWARE_SCAN_ALLOW_UNVERIFIED,
// waved through unverified). Assembly runs off the request path, so this
// can afford to wait longer than the simple upload path, which fails
// closed immediately with a client-retryable 503 instead.
var scanRetryBackoff = []time.Duration{5 * time.Second, 15 * time.Second, 45 * time.Second}

// scanRetrySleep sleeps for d, waking early if the server begins shutting
// down, or if the assembly worker's own context is cancelled (lease lost,
// or a shutdown yield request — ADR-016). Overridable in tests to avoid
// real delays.
var scanRetrySleep = func(ctx context.Context, d time.Duration) {
	select {
	case <-time.After(d):
	case <-utils.GetUploadTracker().ShutdownCh():
	case <-ctx.Done():
	}
}

// scanChunkedUploadWithRetry scans a chunked upload's assembled-but-not-yet-
// encrypted content straight off its chunk files (utils.OpenChunksReader),
// retrying scan errors (clamd unreachable, timed out, or an unparsable
// response — never an infected/clean verdict, which are not errors) per
// scanRetryBackoff. Each attempt opens a fresh chunk reader since a failed
// attempt may have partially consumed the previous one.
//
// A missing/unopenable chunk (utils.ErrChunkMissing) is NOT retried: the
// chunks are already frozen for assembly by this point, so a missing one
// means the data itself is gone or corrupted, not that clamd is
// unavailable — retrying three times with backoff would only delay an
// outcome that can't change, and the caller must not treat it as a
// SCAN_UNAVAILABLE/ALLOW_UNVERIFIED case (bug-hunter finding).
func scanChunkedUploadWithRetry(ctx context.Context, cfg *config.Config, uploadDir, uploadID string, totalChunks int, size int64, clientEncrypted bool) (scanVerdict, error) {
	var lastErr error
	for attempt := 0; ; attempt++ {
		reader := utils.OpenChunksReader(uploadDir, uploadID, totalChunks)
		verdict, err := scanUpload(ctx, cfg, reader, size, clientEncrypted)
		if closeErr := reader.Close(); closeErr != nil {
			slog.Warn("failed to close chunk reader after scan", "error", closeErr, "upload_id", uploadID)
		}
		if err == nil {
			return verdict, nil
		}
		if errors.Is(err, utils.ErrChunkMissing) {
			return scanVerdict{}, err
		}
		if !errors.Is(err, scanning.ErrConnect) {
			// Not a connection blip: a scan timeout or a clamd ERROR reply
			// will just recur identically on an immediate retry against the
			// same clamd, so retrying only wastes an assembly-worker slot for
			// up to the full backoff schedule (bug-hunter finding) — and,
			// under MALWARE_SCAN_ALLOW_UNVERIFIED, gives an uploader who can
			// deliberately trigger a clamd-side error (e.g. a crafted stream)
			// a way to reliably wait out "unavailable" faster.
			return scanVerdict{}, err
		}
		lastErr = err
		if attempt >= len(scanRetryBackoff) {
			return scanVerdict{}, lastErr
		}
		backoff := scanRetryBackoff[attempt]
		slog.Warn("malware scan connection failed; retrying",
			"error", err,
			"upload_id", uploadID,
			"attempt", attempt+1,
			"backoff", backoff,
		)
		scanRetrySleep(ctx, backoff)
		if utils.GetUploadTracker().IsShuttingDown() {
			return scanVerdict{}, errScanInterruptedByShutdown
		}
		if ctx.Err() != nil {
			return scanVerdict{}, ctx.Err()
		}
	}
}

// errScanInterruptedByShutdown means the server began shutting down while a
// scan was waiting to retry. The upload is neither failed nor published; the
// worker yields its lease so recovery re-runs it (and rescans) promptly.
var errScanInterruptedByShutdown = errors.New("malware scan interrupted by shutdown")

// assemblyFailure is a machine-readable assembly failure reason paired with
// whether it's worth retrying (ADR-016). Centralizing the taxonomy here
// (rather than scattering ad-hoc code/retryable pairs through the worker)
// keeps /complete's Reopen decision and the SDK/web-client retry behaviour
// consistent with what the worker actually recorded.
type assemblyFailure struct {
	code      string
	retryable bool
}

// beforePublishHook, when non-nil, runs immediately before a worker calls
// w.publish, with the upload_id being published. Test-only seam for
// simulating races around the Publish transition (e.g. a stale worker that
// reaches publish after another attempt has already taken over and
// finished). Never set outside tests.
var beforePublishHook func(uploadID string)

var (
	// errMalwareDetected: terminal — the content is what it is, retrying
	// changes nothing.
	errMalwareDetected = assemblyFailure{code: "MALWARE_DETECTED", retryable: false}
	// errIntegrityMismatch: terminal — a TOCTOU chunk-content mismatch or a
	// size mismatch between scan time and assembly time. Retrying would
	// just re-run the same race; the uploader must re-upload from scratch
	// (a fresh /api/upload/init), not retry /complete.
	errIntegrityMismatch = assemblyFailure{code: "INTEGRITY_ERROR", retryable: false}
	// errScanUnavailable: retryable — clamd was unreachable after retries.
	errScanUnavailable = assemblyFailure{code: "SCAN_UNAVAILABLE", retryable: true}
	// errAssemblyFailed: retryable — the catch-all for IO/DB/encryption/
	// claim-code errors. These are usually transient (disk hiccup,
	// momentary DB contention) and a retry (or a takeover by a healthier
	// worker) commonly succeeds.
	errAssemblyFailed = assemblyFailure{code: "ASSEMBLY_FAILED", retryable: true}
	// errChunkMissing: terminal (bug-hunter follow-up finding) — a chunk
	// file went missing or became unreadable on disk. Same client-facing
	// code as errAssemblyFailed (ASSEMBLY_FAILED, no API contract change)
	// but NOT retryable: recovery cannot re-run this upload to success
	// because the missing bytes are gone, and the client cannot retry
	// either — /api/upload/{id}/complete 400s MISSING_CHUNKS before ever
	// reaching the lock, and chunk PUTs are refused once status is no
	// longer "uploading" (409 UPLOAD_NOT_ACCEPTING). Marking this
	// retryable=true left /status telling the client to keep waiting on
	// an upload that could never recover; the uploader must start over
	// with a fresh /api/upload/init instead.
	errChunkMissing = assemblyFailure{code: "ASSEMBLY_FAILED", retryable: false}
)

// assemblyWorker holds the state for a single assembly attempt: the lease
// it must renew to keep working, and the plumbing to fail/publish through
// the owner-guarded ADR-016 transitions.
type assemblyWorker struct {
	repos  *repository.Repositories
	cfg    *config.Config
	upload *models.PartialUpload
	lease  repository.AssemblyLease

	ctx    context.Context
	cancel context.CancelFunc

	leaseLost atomic.Bool // set by the heartbeat before it cancels ctx because renewal stopped succeeding

	heartbeatDone chan struct{}
}

// assemblyRootCtx is cancelled by CancelAssemblies at shutdown, asking every
// in-flight assembly worker to stop promptly (yielding its lease) instead of
// running to completion. Each worker derives its own child context so a
// single worker's lease loss doesn't cancel its siblings.
var (
	assemblyRootMu     sync.Mutex
	assemblyRootCtx    context.Context
	assemblyRootCancel context.CancelFunc
)

func init() {
	assemblyRootCtx, assemblyRootCancel = context.WithCancel(context.Background())
}

// CancelAssemblies cancels the shared assembly root context, asking every
// in-flight assembly worker to abandon its current step and yield its lease
// rather than run to completion. Called from graceful shutdown after the
// normal WaitForUploads grace period elapses (main.go).
func CancelAssemblies() {
	assemblyRootMu.Lock()
	defer assemblyRootMu.Unlock()
	assemblyRootCancel()
}

// resetAssemblyRootCtx replaces the shared assembly root context. Test-only:
// lets tests run multiple shutdown scenarios without cross-contaminating a
// cancelled root context across cases.
func resetAssemblyRootCtx() {
	assemblyRootMu.Lock()
	defer assemblyRootMu.Unlock()
	assemblyRootCancel()
	assemblyRootCtx, assemblyRootCancel = context.WithCancel(context.Background())
}

// launchAssembly spawns the assembly worker goroutine for upload. It takes
// ownership of the already-acquired semaphore slot (semCh) and upload
// tracker entry: the CALLER must have already sent to semCh and called
// utils.GetUploadTracker().StartAssembly(upload.UploadID) before calling
// this; launchAssembly releases both via defer when assembly finishes
// (success, terminal failure, or a shutdown yield).
func launchAssembly(repos *repository.Repositories, cfg *config.Config, upload *models.PartialUpload, lease repository.AssemblyLease, semCh chan struct{}) {
	tracker := utils.GetUploadTracker()
	go func() {
		defer tracker.FinishAssembly(upload.UploadID)
		defer func() { <-semCh }()
		runAssembly(repos, cfg, upload, lease)
	}()
}

// runAssembly builds an assemblyWorker, starts its heartbeat, and runs the
// assembly pipeline, recovering from panics exactly as the pre-ADR-016
// worker did (a panicking goroutine must never leak the lease or the
// upload's row forever).
func runAssembly(repos *repository.Repositories, cfg *config.Config, upload *models.PartialUpload, lease repository.AssemblyLease) {
	assemblyRootMu.Lock()
	parent := assemblyRootCtx
	assemblyRootMu.Unlock()

	ctx, cancel := context.WithCancel(parent)
	w := &assemblyWorker{
		repos:         repos,
		cfg:           cfg,
		upload:        upload,
		lease:         lease,
		ctx:           ctx,
		cancel:        cancel,
		heartbeatDone: make(chan struct{}),
	}
	defer cancel()
	defer w.stopHeartbeat()

	defer func() {
		if r := recover(); r != nil {
			slog.Error("assembly worker panic recovered", "upload_id", upload.UploadID, "panic", r)
			w.fail(errAssemblyFailed, genericAssemblyFailureMessage)
		}
	}()

	go w.heartbeat()

	w.run()
}

// heartbeat renews the assembly lease on a tick of TTL/4 (per ADR-016),
// cancelling the worker's context if the lease is confirmed lost (a
// takeover won) or if no renewal has succeeded for TTL-15s (the DB may be
// unreachable — better to stop and let recovery decide than keep working
// past the point another attempt could legitimately take over).
func (w *assemblyWorker) heartbeat() {
	defer close(w.heartbeatDone)

	ttl := w.lease.TTL
	if ttl <= 0 {
		ttl = utils.DefaultAssemblyLeaseTTL
	}
	tick := ttl / 4
	if tick < time.Second {
		tick = time.Second
	}
	staleDeadline := ttl - 15*time.Second
	if staleDeadline <= 0 {
		staleDeadline = ttl / 2
	}

	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	lastSuccess := time.Now()
	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			ok, err := w.repos.PartialUploads.RenewAssemblyLease(w.ctx, w.upload.UploadID, w.lease)
			if err != nil {
				slog.Warn("assembly lease renew failed; will retry", "error", err, "upload_id", w.upload.UploadID)
				if time.Since(lastSuccess) >= staleDeadline {
					slog.Error("assembly lease not renewed in time; aborting worker", "upload_id", w.upload.UploadID)
					w.leaseLost.Store(true)
					w.cancel()
					return
				}
				continue
			}
			if !ok {
				slog.Warn("assembly lease lost to another attempt; aborting worker", "upload_id", w.upload.UploadID)
				w.leaseLost.Store(true)
				w.cancel()
				return
			}
			lastSuccess = time.Now()
		}
	}
}

// stopHeartbeat cancels the worker context (idempotent) and waits for the
// heartbeat goroutine to exit, so nothing renews (or double-cancels) after
// the worker itself has finished.
func (w *assemblyWorker) stopHeartbeat() {
	w.cancel()
	<-w.heartbeatDone
}

// aborted checks whether the worker should stop: either its context was
// cancelled (lease lost, or shutdown via CancelAssemblies) or the global
// shutdown flag was raised directly (belt-and-suspenders with the
// assemblyRootCtx cancellation path). Call at each pipeline checkpoint.
func (w *assemblyWorker) aborted() bool {
	return w.ctx.Err() != nil
}

// handleAbort cleans up finalPath (if created) and, when the abort reason is
// shutdown (not a lost lease — no point spending a DB round-trip on a lease
// we no longer hold), explicitly yields the lease so recovery can take over
// immediately instead of waiting out the remainder of the TTL.
func (w *assemblyWorker) handleAbort(finalPath string) {
	if finalPath != "" {
		if err := os.Remove(finalPath); err != nil && !os.IsNotExist(err) {
			slog.Warn("failed to remove partial final file on assembly abort", "error", err, "upload_id", w.upload.UploadID, "path", finalPath)
		}
	}

	if w.leaseLost.Load() {
		slog.Info("assembly aborted: lease lost to another attempt", "upload_id", w.upload.UploadID)
		return
	}

	// Bug-hunter follow-up finding: on the errScanInterruptedByShutdown
	// path (IsShuttingDown fires before CancelAssemblies/assemblyRootCtx
	// cancellation), w.ctx is still live here, so the heartbeat goroutine
	// may still be ticking. Stop it — and wait for it to actually exit —
	// before yielding below; otherwise an in-flight renew racing with this
	// Yield could land afterward and extend the lease a full TTL, undoing
	// the whole point of yielding early. stopHeartbeat is idempotent (a
	// later deferred call in runAssembly is a no-op once this has run).
	w.stopHeartbeat()

	slog.Info("assembly aborted: shutting down, yielding lease for recovery", "upload_id", w.upload.UploadID)
	yieldCtx, yieldCancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
	defer yieldCancel()
	if err := w.repos.PartialUploads.YieldAssemblyLease(yieldCtx, w.upload.UploadID, w.lease.Owner); err != nil {
		slog.Warn("failed to yield assembly lease on shutdown", "error", err, "upload_id", w.upload.UploadID)
	}
}

// fail records a terminal or retryable assembly failure via the owner-
// guarded FailAssembly transition. A lost lease (another attempt already
// resolved this upload) is expected under concurrent takeover and logged at
// debug rather than error.
func (w *assemblyWorker) fail(reason assemblyFailure, message string) {
	w.failWithAudit(reason, message, nil)
}

// failWithAudit returns true only if FailAssembly actually committed the
// failure (and, when auditFile is set, the audit row). Callers that follow
// up with something destructive/irreversible — e.g. deleting chunks — must
// check this: if the CAS was lost (ErrLeaseLost) or the audit insert hit a
// belt-and-suspenders duplicate (ErrDuplicateKey), a DIFFERENT attempt now
// owns this upload, quite possibly reading those same chunk files right
// now, and deleting them out from under it would corrupt its assembly
// (bug-hunter finding L1).
func (w *assemblyWorker) failWithAudit(reason assemblyFailure, message string, auditFile *models.File) bool {
	err := w.repos.PartialUploads.FailAssembly(context.WithoutCancel(w.ctx), w.upload.UploadID, w.lease.Owner, message, reason.code, reason.retryable, auditFile)
	if err == nil {
		if auditFile != nil {
			scanStatus := auditFile.ScanStatus
			scanResult := auditFile.ScanResult
			EmitWebhookEvent(&webhooks.Event{
				Type:      webhooks.EventFileInfected,
				Timestamp: time.Now(),
				File: webhooks.FileData{
					ID:         auditFile.ID,
					ClaimCode:  auditFile.ClaimCode,
					Filename:   w.upload.Filename,
					Size:       w.upload.TotalSize,
					ExpiresAt:  auditFile.ExpiresAt,
					ScanStatus: &scanStatus,
					ScanResult: &scanResult,
				},
			})
		}
		return true
	}
	if errors.Is(err, repository.ErrLeaseLost) {
		slog.Debug("assembly fail superseded: lease already lost", "upload_id", w.upload.UploadID, "code", reason.code)
		return false
	}
	slog.Error("failed to record assembly failure", "error", err, "upload_id", w.upload.UploadID, "code", reason.code)
	return false
}

// publish records successful assembly via the owner-guarded PublishAssembly
// transition, which atomically flips partial_uploads to completed and
// inserts the file record in one transaction.
func (w *assemblyWorker) publish(file *models.File) error {
	return w.repos.PartialUploads.PublishAssembly(context.WithoutCancel(w.ctx), w.upload.UploadID, w.lease.Owner, file)
}

// rereadPartialUploadWithRetry re-reads a partial_uploads row with a short
// bounded retry. It exists for the ambiguous-publish-error path in run():
// the most likely reason THIS read itself fails is the same transient DB
// unavailability that made the original publish error ambiguous, so a
// single attempt would almost always just reproduce "still can't tell" —
// worth a few short retries before giving up and treating the outcome as
// genuinely unknown.
func rereadPartialUploadWithRetry(ctx context.Context, repos *repository.Repositories, uploadID string) (*models.PartialUpload, error) {
	const maxAttempts = 3
	delay := 200 * time.Millisecond
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		recheck, err := repos.PartialUploads.GetByUploadID(ctx, uploadID)
		if err == nil {
			return recheck, nil
		}
		lastErr = err
		if attempt < maxAttempts-1 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
			delay *= 2
		}
	}
	return nil, lastErr
}

// recordInfectedChunkedUpload builds the best-effort audit row for a
// rejected, infected chunked upload: no assembled file is ever written and
// claimCode is never surfaced through the status endpoint (a failed upload's
// claim_code stays unset). The row is inserted inside FailAssembly's
// transaction by the caller (w.failWithAudit), not here.
//
// Bug-hunter finding (post-ADR-015 review): FileSize is 0, and the audit
// row's expiry is bounded to the server's default regardless of what the
// uploader requested (including expires_in_hours=0, "never expire") —
// avoids quota/storage-inflation from an audit row nobody can ever claim.
func recordInfectedChunkedUpload(cfg *config.Config, partialUpload *models.PartialUpload, claimCode string, verdict scanVerdict) *models.File {
	auditExpiresAt := time.Now().Add(time.Duration(cfg.GetDefaultExpirationHours()) * time.Hour)
	now := time.Now()
	return &models.File{
		ClaimCode:        claimCode,
		OriginalFilename: partialUpload.Filename,
		// Placeholder to satisfy the NOT NULL column; no file is ever
		// assembled for an infected upload, and claim.go's scanGate blocks
		// download by scan_status before this path would ever be opened.
		StoredFilename:  "quarantined-" + uuid.New().String(),
		FileSize:        0,
		MimeType:        "application/octet-stream",
		ExpiresAt:       auditExpiresAt,
		MaxDownloads:    &partialUpload.MaxDownloads,
		UploaderIP:      partialUpload.UploaderIP,
		PasswordHash:    partialUpload.PasswordHash,
		UserID:          partialUpload.UserID,
		ClientEncrypted: partialUpload.ClientEncrypted,
		ScanStatus:      verdict.status,
		ScanResult:      verdict.result,
		ScannedAt:       &now,
	}
}

// run performs the actual file assembly for w.upload. This is the direct
// descendant of the pre-ADR-016 AssembleUploadAsync; the main structural
// change is that every failure/success point now goes through w.fail /
// w.publish (owner-guarded, so a superseded attempt can never clobber a
// winner) instead of unconditional SetAssemblyFailed/SetAssemblyCompleted
// calls, and every step is preceded by an abort checkpoint.
func (w *assemblyWorker) run() {
	uploadID := w.upload.UploadID
	cfg := w.cfg
	partialUpload := w.upload
	clientIP := partialUpload.UploaderIP

	slog.Info("starting async assembly",
		"upload_id", uploadID,
		"filename", partialUpload.Filename,
		"total_chunks", partialUpload.TotalChunks,
		"total_size", partialUpload.TotalSize,
		"attempt", partialUpload.AssemblyAttempts,
	)

	// Generate unique claim code
	var claimCode string
	var err error
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		claimCode, err = utils.GenerateClaimCode()
		if err != nil {
			slog.Error("failed to generate claim code", "error", err, "upload_id", uploadID)
			w.fail(errAssemblyFailed, genericAssemblyFailureMessage)
			return
		}

		existing, err := w.repos.Files.GetByClaimCode(context.Background(), claimCode)
		if err != nil {
			slog.Error("failed to check claim code", "error", err, "upload_id", uploadID)
			w.fail(errAssemblyFailed, genericAssemblyFailureMessage)
			return
		}

		if existing == nil {
			break // Code is unique
		}

		if i == maxRetries-1 {
			slog.Error("failed to generate unique claim code after retries", "upload_id", uploadID)
			w.fail(errAssemblyFailed, "Failed to generate unique claim code")
			return
		}
	}

	if w.aborted() {
		w.handleAbort("")
		return
	}

	// Generate unique filename for storage
	storedFilename := uuid.New().String() + filepath.Ext(partialUpload.Filename)
	finalPath := filepath.Join(cfg.UploadDir, storedFilename)

	// Detect MIME type from the first chunk BEFORE assembly. The first 512
	// bytes of chunk 0 are identical to the assembled file's first 512 bytes,
	// and detecting up front lets the encrypted path below skip writing a
	// plaintext copy of the file entirely.
	mimeType := "application/octet-stream"
	{
		chunkFile, err := os.Open(utils.GetChunkPath(cfg.UploadDir, uploadID, 0))
		if err != nil {
			slog.Error("failed to open first chunk for MIME detection", "error", err, "upload_id", uploadID)
			w.fail(errAssemblyFailed, genericAssemblyFailureMessage)
			return
		}

		buffer := make([]byte, 512)
		n, err := chunkFile.Read(buffer)
		chunkFile.Close()

		if err != nil && err != io.EOF {
			slog.Error("failed to read first chunk for MIME detection", "error", err, "upload_id", uploadID)
			w.fail(errAssemblyFailed, genericAssemblyFailureMessage)
			return
		}

		detected := utils.DetectMimeType(buffer[:n])
		if detected != "" {
			mimeType = detected
		}
	}

	if w.aborted() {
		w.handleAbort("")
		return
	}

	// ADR-015: scan the chunk content synchronously, straight off the chunk
	// files, before any encryption/strip/storage work below — a rejected
	// upload must never reach the assemble/encrypt branch or produce a
	// stored file.
	verdict, scanErr := scanChunkedUploadWithRetry(w.ctx, cfg, cfg.UploadDir, uploadID, partialUpload.TotalChunks, partialUpload.TotalSize, partialUpload.ClientEncrypted)
	if scanErr != nil {
		// Check abort FIRST, regardless of what error the scan actually
		// surfaced. Closing the clamd socket on ctx.Done() (scanner.go)
		// typically produces a generic "use of closed network connection"
		// net.OpError, not context.Canceled — matching on the scan error's
		// type/text is unreliable (bug-hunter finding: a shutdown or a lost
		// lease mid-scan was being recorded as SCAN_UNAVAILABLE, burning an
		// attempt and leaving a healthy upload "failed" instead of
		// recoverable). w.aborted() is authoritative: it's true exactly when
		// this worker's own ctx was cancelled, independent of how that
		// surfaced downstream.
		if w.aborted() || errors.Is(scanErr, errScanInterruptedByShutdown) {
			// Leave the upload for recovery: the assembly recovery worker
			// re-runs it (and rescans) rather than discarding a good
			// upload or publishing it unverified.
			slog.Warn("malware scan interrupted; leaving upload for recovery", "upload_id", uploadID, "reason", scanErr)
			w.handleAbort("")
			return
		}
		if errors.Is(scanErr, utils.ErrChunkMissing) {
			// Full error (which includes the internal chunk file path) goes
			// to the log only — the uploader-visible error_message must stay
			// generic (L3 bug-hunter finding: no internal filesystem layout
			// in client-facing text).
			slog.Error("failed to read uploaded chunks for malware scan; failing assembly",
				"error", scanErr,
				"upload_id", uploadID,
			)
			w.fail(errChunkMissing, "Failed to read uploaded file data")
			return
		}
		if !cfg.ClamAV.AllowUnverified {
			slog.Error("malware scan failed after retries; failing assembly (fail closed)",
				"error", scanErr,
				"upload_id", uploadID,
			)
			w.fail(errScanUnavailable, "Malware scanning is temporarily unavailable")
			return
		}
		slog.Warn("malware scan failed after retries; proceeding unverified (MALWARE_SCAN_ALLOW_UNVERIFIED)",
			"error", scanErr,
			"upload_id", uploadID,
		)
		verdict = scanVerdict{status: scanning.ScanStatusError, result: scanErr.Error()}
	}

	if verdict.status == scanning.ScanStatusInfected {
		slog.Warn("malware detected in chunked upload; rejecting before assembly",
			"virus_name", verdict.result,
			"upload_id", uploadID,
		)
		auditFile := recordInfectedChunkedUpload(cfg, partialUpload, claimCode, verdict)
		if w.failWithAudit(errMalwareDetected, fmt.Sprintf("Upload rejected: malware detected (%s)", verdict.result), auditFile) {
			recordAssemblyEvent(context.WithoutCancel(w.ctx), cfg, w.repos, partialUpload, audit.Event{
				Type: models.AuditEventSecurity, Action: "malware_detected", Outcome: models.AuditOutcomeDenied,
				ResourceType: "file", ResourceID: idStr(auditFile.ID),
				Details: map[string]any{"virus_name": verdict.result, "filename": partialUpload.Filename, "chunked": true},
			})
			// Only delete chunks once the MALWARE_DETECTED verdict (and its
			// audit row) actually committed under OUR lease. If it didn't
			// (another attempt already took over, or a belt-and-suspenders
			// duplicate-key backstop fired), that other attempt may be
			// reading these same chunk files right now — deleting them
			// would corrupt its assembly and could make it record a
			// retryable ASSEMBLY_FAILED instead of MALWARE_DETECTED,
			// losing the audit row and the file.infected webhook
			// (bug-hunter finding L1).
			if err := utils.DeleteChunks(cfg.UploadDir, uploadID); err != nil {
				slog.Error("failed to delete chunks for infected upload", "error", err, "upload_id", uploadID)
			}
		}
		return
	}

	if w.aborted() {
		w.handleAbort("")
		return
	}

	encryptionEnabled := utils.IsEncryptionEnabled(cfg.EncryptionKey)
	needsStrip := cfg.IsStripMetadata() && privacy.SupportsMetadataStripping(mimeType)

	var totalBytesWritten int64
	var sha256Hash string
	var encFileID []byte

	if encryptionEnabled && !needsStrip {
		// Fast path: stream chunks through SHA-256 + SFSE2 encryption directly
		// into the final file. One read of the chunks, one write of the
		// ciphertext — no intermediate plaintext file (2 disk passes instead
		// of 4, and plaintext never touches the disk unchunked).
		var err error
		encFileID, err = utils.GenerateEncFileID()
		if err != nil {
			slog.Error("failed to generate enc_file_id", "error", err, "upload_id", uploadID)
			w.fail(errAssemblyFailed, genericAssemblyFailureMessage)
			return
		}

		totalBytesWritten, sha256Hash, err = utils.AssembleChunksEncrypted(
			cfg.UploadDir, uploadID, partialUpload.TotalChunks, partialUpload.TotalSize,
			finalPath, cfg.EncryptionKey, encFileID,
		)
		if err != nil {
			slog.Error("failed to assemble+encrypt chunks", "error", err, "upload_id", uploadID)
			os.Remove(finalPath) // defensive: AssembleChunksEncrypted removes on error, but be safe
			if errors.Is(err, utils.ErrPlaintextLengthMismatch) {
				// A chunk shrank/vanished on disk between /complete's
				// preflight checks and this reopen — content integrity
				// problem, not a transient IO/DB hiccup (code-reviewer
				// finding: this was falling through to the generic,
				// retryable ASSEMBLY_FAILED).
				w.fail(errIntegrityMismatch, integrityMismatchMessage)
				return
			}
			w.fail(errAssemblyFailed, genericAssemblyFailureMessage)
			return
		}

		// Verify the plaintext byte count matches what was expected (mirrors
		// the multi-pass path's check below). AssembleChunksEncrypted already
		// verified no chunk is missing, but a chunk truncated/shrunk on disk
		// between /complete's integrity check and this reopen would otherwise
		// surface only as a hash mismatch — code-reviewer finding: a size
		// mismatch here was falling through as a generic, retryable
		// ASSEMBLY_FAILED (from AssembleChunksEncrypted's own missing-chunks
		// error) or, if chunk count matched but bytes didn't, silently passing
		// through to the hash check. Checking size explicitly makes this
		// terminal (INTEGRITY_ERROR), consistent with the multi-pass path.
		if totalBytesWritten != partialUpload.TotalSize {
			slog.Error("assembled file size mismatch (encrypted fast path)",
				"upload_id", uploadID,
				"expected", partialUpload.TotalSize,
				"actual", totalBytesWritten,
			)
			os.Remove(finalPath)
			w.fail(errIntegrityMismatch, integrityMismatchMessage)
			return
		}

		if !scannedContentMatches(verdict, sha256Hash) {
			logIntegrityMismatch(uploadID)
			os.Remove(finalPath)
			w.fail(errIntegrityMismatch, integrityMismatchMessage)
			return
		}
	} else {
		// Multi-pass path: metadata stripping needs a plaintext file on disk,
		// and unencrypted deployments store the assembled file as-is.
		slog.Info("assembling chunks into final file",
			"upload_id", uploadID,
			"total_chunks", partialUpload.TotalChunks,
			"filename", partialUpload.Filename,
		)

		var err error
		totalBytesWritten, sha256Hash, err = utils.AssembleChunks(cfg.UploadDir, uploadID, partialUpload.TotalChunks, finalPath)
		if err != nil {
			slog.Error("failed to assemble chunks", "error", err, "upload_id", uploadID)
			os.Remove(finalPath)
			w.fail(errAssemblyFailed, genericAssemblyFailureMessage)
			return
		}

		// Verify assembled file size matches expected
		if totalBytesWritten != partialUpload.TotalSize {
			slog.Error("assembled file size mismatch",
				"upload_id", uploadID,
				"expected", partialUpload.TotalSize,
				"actual", totalBytesWritten,
			)
			os.Remove(finalPath)
			w.fail(errIntegrityMismatch, integrityMismatchMessage)
			return
		}

		// TOCTOU integrity check (bug-hunter finding): a chunk on disk can be
		// rewritten between the synchronous scan (which read the chunk files
		// once, sequentially) and this assembly step (which reopens them from
		// the same paths) — e.g. re-uploading chunk 0 with different, same-
		// size content while racing /complete. Compared BEFORE metadata
		// stripping, which intentionally changes the bytes; see verdict.hash's
		// doc comment for what's covered.
		if !scannedContentMatches(verdict, sha256Hash) {
			logIntegrityMismatch(uploadID)
			os.Remove(finalPath)
			w.fail(errIntegrityMismatch, integrityMismatchMessage)
			return
		}

		slog.Info("chunk assembly complete",
			"upload_id", uploadID,
			"total_bytes", totalBytesWritten,
		)

		// Strip metadata from assembled plaintext file (before encryption)
		if needsStrip {
			if err := privacy.StripFileMetadata(finalPath, mimeType); err != nil {
				slog.Warn("failed to strip metadata in chunked upload",
					"error", err,
					"upload_id", uploadID,
					"mime_type", mimeType,
				)
				// Non-fatal: continue with original file
			} else {
				// Recompute hash and size after stripping
				newHash, err := computeFileHash(finalPath)
				if err != nil {
					slog.Warn("failed to recompute hash after stripping", "error", err, "upload_id", uploadID)
				} else {
					sha256Hash = newHash
				}
				info, err := os.Stat(finalPath)
				if err != nil {
					slog.Warn("failed to stat file after stripping", "error", err, "upload_id", uploadID)
				} else {
					totalBytesWritten = info.Size()
				}
				slog.Info("metadata stripped from chunked upload",
					"upload_id", uploadID,
					"mime_type", mimeType,
					"file_size", totalBytesWritten,
				)
			}
		}

		// Encrypt if encryption is enabled (SFSE2)
		if encryptionEnabled {
			slog.Debug("encrypting assembled file using SFSE2 streaming encryption", "upload_id", uploadID)

			var err error
			encFileID, err = utils.GenerateEncFileID()
			if err != nil {
				slog.Error("failed to generate enc_file_id", "error", err, "upload_id", uploadID)
				os.Remove(finalPath)
				w.fail(errAssemblyFailed, genericAssemblyFailureMessage)
				return
			}

			// Encrypt to temporary file, then replace original.
			tempEncryptedPath := finalPath + ".encrypted.tmp"

			if err := utils.EncryptFileStreamingV2(finalPath, tempEncryptedPath, cfg.EncryptionKey, encFileID); err != nil {
				slog.Error("failed to encrypt file (SFSE2)", "error", err, "upload_id", uploadID)
				os.Remove(finalPath)
				os.Remove(tempEncryptedPath)
				w.fail(errAssemblyFailed, genericAssemblyFailureMessage)
				return
			}

			// Get file sizes for logging
			originalInfo, _ := os.Stat(finalPath)
			encryptedInfo, _ := os.Stat(tempEncryptedPath)

			// Replace original with encrypted version
			if err := os.Remove(finalPath); err != nil {
				slog.Error("failed to remove original file", "error", err, "upload_id", uploadID)
				os.Remove(tempEncryptedPath)
				w.fail(errAssemblyFailed, genericAssemblyFailureMessage)
				return
			}
			if err := os.Rename(tempEncryptedPath, finalPath); err != nil {
				slog.Error("failed to rename encrypted file", "error", err, "upload_id", uploadID)
				os.Remove(tempEncryptedPath)
				w.fail(errAssemblyFailed, genericAssemblyFailureMessage)
				return
			}

			slog.Debug("file encrypted with SFSE2 streaming encryption",
				"upload_id", uploadID,
				"original_size", originalInfo.Size(),
				"encrypted_size", encryptedInfo.Size())
		}
	}

	if w.aborted() {
		w.handleAbort(finalPath)
		return
	}

	// Calculate expiration time
	var expiresAt time.Time
	if partialUpload.ExpiresInHours == 0 {
		// Never expire - set to 100 years in the future
		expiresAt = partialUpload.CreatedAt.Add(time.Duration(100*365*24) * time.Hour)
	} else {
		expiresAt = partialUpload.CreatedAt.Add(time.Duration(partialUpload.ExpiresInHours) * time.Hour)
	}

	// Always set maxDownloads (0 = unlimited, not "unset")
	maxDownloads := &partialUpload.MaxDownloads

	fileRecord := &models.File{
		ClaimCode:        claimCode,
		OriginalFilename: partialUpload.Filename,
		StoredFilename:   storedFilename,
		FileSize:         totalBytesWritten,
		MimeType:         mimeType,
		ExpiresAt:        expiresAt,
		MaxDownloads:     maxDownloads,
		UploaderIP:       storeIP(clientIP, cfg),
		PasswordHash:     partialUpload.PasswordHash,
		UserID:           partialUpload.UserID,
		SHA256Hash:       sha256Hash,
		ClientEncrypted:  partialUpload.ClientEncrypted,
		EncFileID:        encFileID,
	}
	if verdict.status != "" {
		scannedAt := time.Now()
		fileRecord.ScanStatus = verdict.status
		fileRecord.ScanResult = verdict.result
		fileRecord.ScannedAt = &scannedAt
	}

	if beforePublishHook != nil {
		beforePublishHook(uploadID)
	}

	skipWebhook := false
	if err := w.publish(fileRecord); err != nil {
		if errors.Is(err, repository.ErrLeaseLost) {
			slog.Info("assembly publish superseded: another attempt already resolved this upload", "upload_id", uploadID)
			os.Remove(finalPath)
			return
		}

		// Bug-hunter finding M3: a Commit that actually succeeded on the
		// server but whose acknowledgement was lost (e.g. the connection
		// dropped between COMMIT and the client receiving the reply)
		// surfaces here as an ordinary error, not ErrLeaseLost — even
		// though the row really did transition to "completed" under our
		// own claim code. Blindly deleting finalPath and failing below
		// would destroy the only copy of a file whose (already-published,
		// already-unique-checked) claim code is now permanently valid.
		// Before treating this as a real failure, check whether it
		// actually went through: re-read the row (retried — the most
		// likely reason THIS read itself fails is the same transient DB
		// unavailability that made the publish error ambiguous) and see if
		// it's "completed" with THIS attempt's own claim code — a
		// cryptographically random value we already checked was unique
		// before ever calling publish(), so nothing else could ever have
		// set it.
		// Not cancelled immediately: the success branch below reuses
		// recheckCtx for the file-row refetch (GetByClaimCode). The 5s
		// timeout already bounds its lifetime; deferring the cancel here
		// (rather than calling it right after the reread) avoids handing
		// that refetch an already-cancelled context, which would make it
		// fail every time and permanently disable the webhook on this path.
		recheckCtx, recheckCancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer recheckCancel()
		recheck, recheckErr := rereadPartialUploadWithRetry(recheckCtx, w.repos, uploadID)

		switch {
		case recheckErr != nil:
			// M3 edge case (follow-up bug-hunter finding): the re-read
			// itself failed after retries — most likely the DB is still
			// unreachable, so we genuinely cannot tell whether the
			// original commit went through. Guessing either way is wrong
			// half the time: deleting finalPath risks destroying a
			// published file's only copy; calling w.fail risks recording
			// ASSEMBLY_FAILED over a row that's actually completed (a
			// no-op via ErrLeaseLost, but still misleading in intent).
			// Do neither — leave finalPath and the row exactly as they
			// are. If the commit truly failed, the lease eventually
			// expires and recovery re-evaluates from scratch (worst case:
			// this finalPath becomes an orphan for CleanupOrphanedFiles
			// to reap, never a published row silently missing its bytes).
			slog.Error("could not determine whether an ambiguous publish actually committed (DB still unreachable after retries); leaving upload and finalPath untouched for lease-expiry recovery",
				"publish_error", err, "recheck_error", recheckErr, "upload_id", uploadID)
			return

		case recheck != nil && recheck.Status == "completed" && recheck.ClaimCode != nil && *recheck.ClaimCode == claimCode:
			slog.Warn("assembly publish returned an error but the commit actually succeeded; treating as success",
				"error", err, "upload_id", uploadID)
			if publishedFile, fileErr := w.repos.Files.GetByClaimCode(recheckCtx, claimCode); fileErr == nil && publishedFile != nil {
				fileRecord = publishedFile
			} else {
				// Don't emit a webhook carrying a fake ID=0 (bug-hunter
				// finding): skip it entirely rather than guess. Chunk
				// cleanup and the success log below are still correct —
				// the row IS completed, we just couldn't fetch the file
				// row's real ID this time.
				slog.Error("failed to re-fetch published file row after ambiguous commit; skipping file.uploaded webhook", "error", fileErr, "upload_id", uploadID)
				skipWebhook = true
			}
			// Fall through: do NOT remove finalPath (it's the published
			// file) and do NOT call w.fail (the row is no longer
			// "processing", so that CAS wouldn't match anyway).

		case errors.Is(err, repository.ErrDuplicateKey):
			// A file row for this upload_id already exists — the winning
			// side of a race we lost despite passing the owner check (should
			// be effectively impossible given the CAS, but the unique index
			// is the belt-and-suspenders backstop). Don't leave a second
			// copy of the bytes on disk.
			slog.Warn("assembly publish found existing file row for this upload; discarding our copy", "upload_id", uploadID)
			os.Remove(finalPath)
			return

		default:
			slog.Error("failed to publish assembled file", "error", err, "upload_id", uploadID)
			os.Remove(finalPath)
			w.fail(errAssemblyFailed, genericAssemblyFailureMessage)
			return
		}
	}

	// Delete chunks (cleanup)
	if err := utils.DeleteChunks(cfg.UploadDir, uploadID); err != nil {
		slog.Error("failed to delete chunks", "error", err, "upload_id", uploadID)
		// Don't fail - chunks will be cleaned up later by cleanup worker
	}

	// The row is published (directly or confirmed by the re-read above), so
	// the upload is complete - recorded even when the published row couldn't
	// be re-fetched (fileRecord.ID 0, no id to name).
	fileID := ""
	if fileRecord.ID != 0 {
		fileID = idStr(fileRecord.ID)
	}
	recordAssemblyEvent(context.WithoutCancel(w.ctx), cfg, w.repos, partialUpload, audit.Event{
		Type: models.AuditEventFile, Action: "file_upload", Outcome: models.AuditOutcomeSuccess,
		ResourceType: "file", ResourceID: fileID,
		Details: map[string]any{"filename": partialUpload.Filename, "size": totalBytesWritten,
			"password_protected": partialUpload.PasswordHash != "", "chunked": true},
	})

	// Emit webhook event for file upload completion (only after the commit
	// above — a webhook for a file that turned out to be superseded/rolled
	// back would be a lie).
	if !skipWebhook {
		EmitWebhookEvent(&webhooks.Event{
			Type:      webhooks.EventFileUploaded,
			Timestamp: time.Now(),
			File: webhooks.FileData{
				ID:        fileRecord.ID,
				ClaimCode: claimCode,
				Filename:  partialUpload.Filename,
				Size:      totalBytesWritten,
				MimeType:  mimeType,
				ExpiresAt: expiresAt,
			},
		})
	}

	slog.Info("async assembly completed successfully",
		"upload_id", uploadID,
		"claim_code", redactClaimCode(claimCode),
		"filename", partialUpload.Filename,
		"size", totalBytesWritten,
		"total_chunks", partialUpload.TotalChunks,
		"password_protected", partialUpload.PasswordHash != "",
		"scan_status", fileRecord.ScanStatus,
		"client_ip", logIP(clientIP, cfg),
	)
}
