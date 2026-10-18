package handlers

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"math/bits"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"filippo.io/age"
	"github.com/gabriel-vasile/mimetype"
	"github.com/google/uuid"

	"github.com/fjmerc/safeshare/internal/config"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/privacy"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/scanning"
	"github.com/fjmerc/safeshare/internal/static"
	"github.com/fjmerc/safeshare/internal/utils"
)

// The no-JavaScript drop page (docs/DROP_PAGE.md). GET /drop is the static
// form in internal/static/web/drop.html; POST /drop is DropHandler. The
// browser doesn't encrypt anything, so the server does: it holds the upload
// in memory only, strips its metadata, packs it with the sender's message
// into a tar archive padded to a PADME size bucket, and encrypts that with
// age to the operator's DROP_RECIPIENT key. Only the ciphertext is stored.

const (
	// DropStoredFilename is the name every drop is stored and downloaded
	// under. The sender's file name is inside the encrypted archive.
	DropStoredFilename = "safeshare-drop.tar.age"
	// dropMessageName is the archive entry holding the sender's message.
	dropMessageName = "message.txt"
	// dropMaxMessage caps the message field (the form's textarea allows
	// 32768 characters, which is up to four times as many bytes).
	dropMaxMessage = 128 * 1024
	// dropMaxParts caps the form's parts; the form has two.
	dropMaxParts = 8
	// dropFormSlack is room above the file size limit for the multipart
	// framing and the message.
	dropFormSlack = dropMaxMessage + 64*1024
	// dropPadMin is the smallest padded archive, as for browser uploads
	// (PAD_MIN_BYTES in crypto.js): all small drops look the same size.
	dropPadMin = 4096
	// dropSlotWait is how long a received drop waits for a processing slot
	// before the sender is told the server is busy.
	dropSlotWait = 30 * time.Second
	// dropReadChunk is how much of the body is read (and charged to the
	// memory budget) at a time.
	dropReadChunk = 32 * 1024
)

var (
	errDropTooLarge     = errors.New("drop: file too large")
	errDropMessageBig   = errors.New("drop: message too long")
	errDropTooManyParts = errors.New("drop: too many form parts")
	errDropBusy         = errors.New("drop: memory budget for drops in progress is used up")
)

// dropResultTemplate renders both the success page and error pages.
var dropResultTemplate = template.Must(template.ParseFS(static.Templates(), "drop-result.html"))

type dropPage struct {
	// Error is set on an error page, with an optional Detail.
	Error, Detail string

	ClaimCode, Link, Expires, Recipient string
	HasFile, Cleaned                    bool
}

// cleanableType is a file type the server can clean, as named by a file's
// extension: the content types that count as it, and the type to clean it
// as.
type cleanableType struct {
	stripAs string
	accept  []string
}

// dropExtensionTypes maps the extensions of the file types the server can
// clean. A file named like one of them whose content isn't detected as one
// of the accepted types would otherwise be sent uncleaned; it is refused
// instead. The aliases cover what mimetype reports for some genuine files
// (MP4 variants; Office files it only recognises as ZIP, which the Office
// cleaner validates itself).
var dropExtensionTypes = func() map[string]cleanableType {
	const (
		docx = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
		xlsx = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
		pptx = "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	)
	return map[string]cleanableType{
		".jpg":  {"image/jpeg", []string{"image/jpeg"}},
		".jpeg": {"image/jpeg", []string{"image/jpeg"}},
		".png":  {"image/png", []string{"image/png"}},
		".pdf":  {"application/pdf", []string{"application/pdf"}},
		".docx": {docx, []string{docx, "application/zip"}},
		".xlsx": {xlsx, []string{xlsx, "application/zip"}},
		".pptx": {pptx, []string{pptx, "application/zip"}},
		".mp4":  {"video/mp4", []string{"video/mp4", "video/x-m4v", "audio/mp4"}},
		".mov":  {"video/quicktime", []string{"video/quicktime"}},
		".mp3":  {"audio/mpeg", []string{"audio/mpeg"}},
	}
}()

// dropError is a refusal to show the sender: an HTTP status, a headline and
// a detail line, all plain text.
type dropError struct {
	status          int
	message, detail string
}

func (e *dropError) Error() string { return e.message }

// DropPageHandler serves the drop form (GET/HEAD /drop), or a 404 page when
// the drop page is off.
func DropPageHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !cfg.Drop.Enabled() {
			sendHTMLError(w, "Not available", "This server doesn't have a drop page.", "NOT_FOUND", http.StatusNotFound)
			return
		}
		f, err := static.FileSystem().Open("drop.html")
		if err != nil {
			slog.Error("drop page missing from embedded files", "error", err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		defer f.Close()
		stat, err := f.Stat()
		if err != nil {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		rs, ok := f.(io.ReadSeeker)
		if !ok {
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, "drop.html", stat.ModTime(), rs)
	}
}

// DropHandler handles a drop (POST /drop). See the comment at the top of
// this file. It answers with an HTML page, since the sender has no script to
// read JSON.
//
// The plaintext must never reach the disk: the body is read with
// r.MultipartReader only (r.FormValue and ParseMultipartForm spool files to
// the temp dir), and only the age ciphertext is written.
//
// Memory is bounded in two stages, so that slow senders can't lock others
// out. While bodies arrive, every drop in progress charges the bytes it has
// actually received to one shared budget (DROP_MAX_CONCURRENT full-size
// drops): a slow or stalled sender holds only what it has sent, and the idle
// deadline cuts it off if it stops. Once a body is in, the memory-heavy work
// (scan, strip, encrypt: up to about three copies) needs one of
// DROP_MAX_CONCURRENT slots, which no client can hold for long because that
// work doesn't wait on the client.
func DropHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	concurrent := int64(max(cfg.Drop.MaxConcurrent, 1))
	slots := make(chan struct{}, concurrent)
	received := &byteBudget{limit: concurrent * (cfg.Drop.MaxSize + dropMaxMessage)}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")

		if !cfg.Drop.Enabled() {
			sendDropError(w, http.StatusNotFound, "This server doesn't have a drop page.", "")
			return
		}

		tracker := utils.GetUploadTracker()
		if tracker.IsShuttingDown() {
			sendDropError(w, http.StatusServiceUnavailable, "The server is restarting.", "Nothing was sent. Please try again in a minute.")
			return
		}

		maxSize := cfg.Drop.MaxSize
		if limit := cfg.GetMaxFileSize(); limit < maxSize {
			maxSize = limit
		}
		// Time for stripping after the body is in: the PDF stripper's own
		// limit, with room to spare.
		extra := privacy.StripTimeout() + 30*time.Second
		if cfg.Features.IsMalwareScanEnabled() {
			extra += time.Duration(cfg.ClamAV.ScanTimeout)*time.Second + 30*time.Second
		}
		deadline := extendTransferDeadlineWithExtra(w, cfg, maxSize+dropFormSlack, extra)
		body := newIdleDeadlineReader(w, http.MaxBytesReader(w, r.Body, maxSize+dropFormSlack), deadline)
		r.Body = body

		hold := &budgetHold{budget: received}
		defer hold.release()
		form, err := readDropForm(r, maxSize, hold)
		if err == nil {
			err = body.drainRest()
		}
		body.finish(err)
		if err != nil {
			sendDropFormError(w, r, err, maxSize)
			return
		}

		// The memory-heavy part: wait briefly for a slot.
		wait := time.NewTimer(dropSlotWait)
		defer wait.Stop()
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		case <-wait.C:
			sendDropBusy(w)
			return
		case <-r.Context().Done():
			return
		}

		uploadID := uuid.New().String()
		if !tracker.StartUpload(uploadID, DropStoredFilename, int64(len(form.data))) {
			sendDropError(w, http.StatusServiceUnavailable, "The server is restarting.", "Nothing was sent. Please try again in a minute.")
			return
		}
		defer tracker.FinishUpload(uploadID)

		handleDrop(w, r, repos, cfg, form)
	}
}

// dropForm is a parsed drop. data and message are plaintext held only in
// memory.
type dropForm struct {
	filename string // as sent by the browser; "" when no file was chosen
	data     []byte
	message  string
}

// readDropForm reads the multipart body into memory: the first "file" part
// (at most maxSize bytes) and the "message" field, charging the memory they
// take to hold. Other parts are read and discarded. r.Body must already be
// size-limited.
func readDropForm(r *http.Request, maxSize int64, hold *budgetHold) (*dropForm, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, err
	}
	form := &dropForm{}
	gotFile, gotMessage := false, false
	for parts := 0; ; parts++ {
		part, err := mr.NextPart()
		if err == io.EOF {
			return form, nil
		}
		if err != nil {
			return nil, err
		}
		if parts >= dropMaxParts {
			_ = part.Close()
			return nil, errDropTooManyParts
		}

		switch {
		case part.FormName() == "file" && !gotFile:
			gotFile = true
			form.filename = part.FileName()
			form.data, err = readAllCapped(part, maxSize, errDropTooLarge, hold)
		case part.FormName() == "message" && part.FileName() == "" && !gotMessage:
			gotMessage = true
			var msg []byte
			msg, err = readAllCapped(part, dropMaxMessage, errDropMessageBig, hold)
			form.message = string(msg)
		default:
			_, err = io.Copy(io.Discard, part)
		}
		_ = part.Close()
		if err != nil {
			return nil, err
		}
	}
}

// readAllCapped reads r into memory, failing with tooLarge past limit bytes,
// and with errDropBusy when hold can't get budget for the memory it grows
// into.
func readAllCapped(r io.Reader, limit int64, tooLarge error, hold *budgetHold) ([]byte, error) {
	var out []byte
	chunk := make([]byte, dropReadChunk)
	for {
		n, err := r.Read(chunk)
		if n > 0 {
			if int64(len(out)+n) > limit {
				return nil, tooLarge
			}
			before := cap(out)
			out = append(out, chunk[:n]...)
			if grown := cap(out) - before; grown > 0 && !hold.take(int64(grown)) {
				return nil, errDropBusy
			}
		}
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// byteBudget is a memory budget shared by the drops in progress.
type byteBudget struct {
	mu    sync.Mutex
	used  int64
	limit int64
}

// budgetHold is one drop's share of a byteBudget.
type budgetHold struct {
	budget *byteBudget
	held   int64
}

// take charges n more bytes to the hold, or reports false (charging
// nothing) if the budget can't cover them.
func (h *budgetHold) take(n int64) bool {
	b := h.budget
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.used+n > b.limit {
		return false
	}
	b.used += n
	h.held += n
	return true
}

// release gives everything the hold took back to the budget.
func (h *budgetHold) release() {
	b := h.budget
	b.mu.Lock()
	b.used -= h.held
	b.mu.Unlock()
	h.held = 0
}

func sendDropBusy(w http.ResponseWriter) {
	w.Header().Set("Retry-After", "30")
	sendDropError(w, http.StatusServiceUnavailable, "The server is busy.", "Nothing was sent. Please try again in a minute.")
}

// sendDropFormError answers a body that couldn't be read.
func sendDropFormError(w http.ResponseWriter, r *http.Request, err error, maxSize int64) {
	var maxBytes *http.MaxBytesError
	switch {
	case isUploadTimeout(err):
		if r.ProtoMajor == 1 {
			w.Header().Set("Connection", "close")
		}
		sendDropError(w, http.StatusRequestTimeout, "The upload stalled.", "Nothing was sent. Check your connection and try again.")
	case errors.Is(err, errDropTooLarge), errors.As(err, &maxBytes):
		sendDropError(w, http.StatusRequestEntityTooLarge, "The file is too large.",
			fmt.Sprintf("Nothing was sent. This server accepts files up to %s here.", formatDropSize(maxSize)))
	case errors.Is(err, errDropBusy):
		sendDropBusy(w)
	case errors.Is(err, errDropMessageBig):
		sendDropError(w, http.StatusRequestEntityTooLarge, "The message is too long.", "Nothing was sent. Shorten the message, or put it in a file.")
	default:
		sendDropError(w, http.StatusBadRequest, "The upload couldn't be read.", "Nothing was sent. Please try again.")
	}
}

// handleDrop checks, cleans, encrypts and stores a parsed drop, then sends
// the result page.
func handleDrop(w http.ResponseWriter, r *http.Request, repos *repository.Repositories, cfg *config.Config, form *dropForm) {
	sealed, info, derr := prepareDrop(r, cfg, form)
	if derr != nil {
		if derr.status == http.StatusServiceUnavailable {
			w.Header().Set("Retry-After", "30")
		}
		sendDropError(w, derr.status, derr.message, derr.detail)
		return
	}

	record, derr := storeDrop(r.Context(), repos, cfg, sealed, info.verdict, getClientIP(r))
	if derr != nil {
		sendDropError(w, derr.status, derr.message, derr.detail)
		return
	}

	slog.Info("drop received",
		"claim_code", redactClaimCode(record.ClaimCode),
		"stored_size", record.FileSize,
		"has_file", info.hasFile,
		"cleaned", info.cleaned,
		"client_ip", logIP(getClientIP(r), cfg),
	)
	renderDropPage(w, http.StatusOK, dropPage{
		ClaimCode: record.ClaimCode,
		Link:      buildShareURL(r, cfg, record.ClaimCode),
		Expires:   record.ExpiresAt.UTC().Format("2 January 2006, 15:04 UTC"),
		Recipient: shortRecipientKey(cfg.Drop.RecipientKey),
		HasFile:   info.hasFile,
		Cleaned:   info.cleaned,
	})
}

// dropInfo describes a prepared drop for the record and the result page.
type dropInfo struct {
	hasFile, cleaned bool
	verdict          scanVerdict
}

var (
	errDropServer = &dropError{http.StatusInternalServerError, "Something went wrong on the server.", "Nothing was sent."}
	errDropFull   = &dropError{http.StatusInsufficientStorage, "The server is out of space.", "Nothing was sent."}
)

// prepareDrop validates, scans and cleans the drop in form, then seals it:
// it returns the age ciphertext to store. The plaintext in form is released.
func prepareDrop(r *http.Request, cfg *config.Config, form *dropForm) ([]byte, dropInfo, *dropError) {
	// A message-only drop has nothing to scan.
	info := dropInfo{verdict: scanVerdict{status: scanning.ScanStatusNotScanned}}
	info.hasFile = form.filename != "" || len(form.data) > 0
	if !info.hasFile && strings.TrimSpace(form.message) == "" {
		return nil, info, &dropError{http.StatusBadRequest, "Nothing to send.", "Choose a file or write a message."}
	}

	name := ""
	if info.hasFile {
		var derr *dropError
		if name, derr = checkDropFile(cfg, form); derr != nil {
			return nil, info, derr
		}
		if info.verdict, derr = scanDrop(r, cfg, form.data); derr != nil {
			return nil, info, derr
		}
		if form.data, info.cleaned, derr = stripDrop(name, form.data); derr != nil {
			return nil, info, derr
		}
	}
	if name == dropMessageName {
		name = "file-" + dropMessageName
	}

	sealed, err := sealDrop(name, form.data, form.message, cfg.Drop.Recipient)
	// The plaintext isn't needed any more.
	form.data, form.message = nil, ""
	if err != nil {
		slog.Error("failed to encrypt drop", "error", err)
		return nil, info, errDropServer
	}
	return sealed, info, nil
}

// checkDropFile checks the file's name and size and returns the name it is
// stored under in the archive.
func checkDropFile(cfg *config.Config, form *dropForm) (string, *dropError) {
	if len(form.data) == 0 {
		return "", &dropError{http.StatusBadRequest, "The file is empty.", "Nothing was sent."}
	}
	badName := &dropError{http.StatusBadRequest, "The file name isn't allowed.", "Rename the file and try again."}
	if err := utils.ValidateUploadFilename(form.filename); err != nil {
		return "", badName
	}
	name := utils.SanitizeFilename(form.filename)
	if name == "" || name == "." || name == ".." {
		name = "file"
	}
	allowed, blockedExt, err := utils.IsFileAllowed(name, cfg.GetBlockedExtensions())
	if err != nil {
		return "", badName
	}
	if !allowed {
		return "", &dropError{http.StatusBadRequest, "This kind of file isn't accepted.", fmt.Sprintf("This server doesn't accept %s files.", blockedExt)}
	}
	return name, nil
}

// storeDrop writes the sealed drop and its record. The record follows the
// server's mode (rounded times and no IP or hash in Ghost mode).
func storeDrop(ctx context.Context, repos *repository.Repositories, cfg *config.Config, sealed []byte, verdict scanVerdict, clientIP string) (*models.File, *dropError) {
	quotaConfigured := cfg.GetQuotaLimitGB() > 0
	if hasSpace, _, err := utils.CheckDiskSpace(cfg.UploadDir, int64(len(sealed)), quotaConfigured); err != nil || !hasSpace {
		if err != nil {
			slog.Error("failed to check disk space", "error", err)
		}
		return nil, errDropFull
	}

	claimCode, err := newUniqueClaimCode(ctx, repos)
	if err != nil {
		return nil, errDropServer
	}
	if err := os.MkdirAll(cfg.UploadDir, 0755); err != nil {
		slog.Error("failed to create upload directory", "error", err)
		return nil, errDropServer
	}
	storedFilename := uuid.New().String() + ".age"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	written, hash, encFileID, err := writeStoredFile(bytes.NewReader(sealed), int64(len(sealed)), filePath, cfg)
	if err != nil {
		return nil, errDropServer
	}

	hours := min(cfg.Drop.ExpirationHours, cfg.GetMaxExpirationHours())
	record := &models.File{
		ClaimCode:        claimCode,
		CreatedAt:        storeCreatedAt(cfg),
		OriginalFilename: DropStoredFilename,
		StoredFilename:   storedFilename,
		FileSize:         written,
		MimeType:         "application/octet-stream",
		ExpiresAt:        storeExpiry(time.Now().Add(time.Duration(hours)*time.Hour), cfg),
		UploaderIP:       storeIP(clientIP, cfg),
		SHA256Hash:       storeSHA256(hash, cfg),
		EncFileID:        encFileID,
	}
	if cfg.Features.IsMalwareScanEnabled() {
		// The plaintext was scanned (scanDrop); what's stored is age
		// ciphertext, which a download-time scan can't read.
		now := storeScannedAt(time.Now(), cfg)
		record.ScanStatus = verdict.status
		record.ScanResult = verdict.result
		record.ScannedAt = &now
	}
	if err := createDropRecord(ctx, repos, cfg, record, quotaConfigured); err != nil {
		if rmErr := os.Remove(filePath); rmErr != nil {
			slog.Error("failed to remove drop after its record failed", "error", rmErr)
		}
		if errors.Is(err, repository.ErrQuotaExceeded) {
			return nil, errDropFull
		}
		slog.Error("failed to create drop record", "error", err)
		return nil, errDropServer
	}
	return record, nil
}

// scanDrop runs the malware scan on the plaintext, with the same rules as
// direct uploads, and returns its verdict for the record (as UploadHandler
// stores it: a scan that failed but was let through is "error").
func scanDrop(r *http.Request, cfg *config.Config, data []byte) (scanVerdict, *dropError) {
	if !cfg.Features.IsMalwareScanEnabled() {
		return scanVerdict{}, nil
	}
	if cfg.ClamAV.RejectUnscannable && isUnscannable(cfg, int64(len(data)), false) {
		return scanVerdict{}, &dropError{http.StatusUnprocessableEntity, "This file is too large to be checked for viruses, and this server refuses files it can't check.", "Nothing was sent."}
	}
	verdict, err := scanUpload(r.Context(), cfg, bytes.NewReader(data), int64(len(data)), false)
	if err != nil {
		if !cfg.ClamAV.AllowUnverified {
			slog.Error("malware scan failed; rejecting drop (fail closed)", "error", err)
			return scanVerdict{}, &dropError{http.StatusServiceUnavailable, "The virus check isn't working right now.", "Nothing was sent. Please try again shortly."}
		}
		slog.Warn("malware scan failed; accepting drop unverified (MALWARE_SCAN_ALLOW_UNVERIFIED)", "error", err)
		return scanVerdict{status: scanning.ScanStatusError, result: err.Error()}, nil
	}
	if verdict.status == scanning.ScanStatusInfected {
		slog.Warn("malware detected in drop; rejected", "virus", verdict.result, "client_ip", logIP(getClientIP(r), cfg))
		return scanVerdict{}, &dropError{http.StatusUnprocessableEntity, "The virus check flagged this file.", "Nothing was sent."}
	}
	return verdict, nil
}

// stripDrop removes the file's metadata in memory. It fails closed, in
// every mode: a file of a type the server can clean is refused if cleaning
// fails, and so is one named like such a type whose content isn't
// recognised as it. It returns the cleaned file and whether anything was
// cleaned.
func stripDrop(name string, data []byte) ([]byte, bool, *dropError) {
	mimeType := mimetype.Detect(data).String()
	if i := strings.IndexByte(mimeType, ';'); i >= 0 {
		mimeType = mimeType[:i]
	}
	stripAs := mimeType
	ext := strings.ToLower(filepath.Ext(name))
	if ct, ok := dropExtensionTypes[ext]; ok {
		if !slices.Contains(ct.accept, mimeType) {
			return nil, false, &dropError{http.StatusUnprocessableEntity, "The file couldn't be recognised.",
				fmt.Sprintf("It is named like a %s file, but its content couldn't be recognised as one, so its hidden information couldn't be removed. Nothing was sent.", strings.ToUpper(strings.TrimPrefix(ext, ".")))}
		}
		stripAs = ct.stripAs
	}
	if !privacy.SupportsMetadataStripping(stripAs) {
		return data, false, nil
	}

	out, err := stripMetadataBytesSafe(data, stripAs)
	if err != nil {
		slog.Warn("drop rejected: metadata stripping failed", "mime_type", stripAs, "error", err)
		detail := "Its hidden information couldn't be removed, so nothing was sent."
		switch {
		case errors.Is(err, privacy.ErrEncryptedDocument):
			detail = "It is password-protected, so its hidden information couldn't be removed. Nothing was sent. Remove the password and try again."
		case errors.Is(err, privacy.ErrFileTooLarge):
			detail = "It is too large to have its hidden information removed. Nothing was sent."
		}
		return nil, false, &dropError{http.StatusUnprocessableEntity, "The file couldn't be cleaned.", detail}
	}
	return out, true, nil
}

// stripMetadataBytes is privacy.StripMetadataBytes; a variable so tests can
// make it panic.
var stripMetadataBytes = privacy.StripMetadataBytes

// stripMetadataBytesSafe is stripMetadataBytes with a recover: the
// strippers parse untrusted input (pdfcpu has panicked on crafted files),
// and a panic must reject the drop, not send it uncleaned.
func stripMetadataBytesSafe(data []byte, mimeType string) (out []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			out, err = nil, fmt.Errorf("metadata stripping panicked: %v", p)
		}
	}()
	return stripMetadataBytes(data, mimeType)
}

// sealDrop packs the file (as name) and the message into a tar archive,
// pads it with zero bytes to a PADME bucket, and encrypts it to recipient.
// Zero bytes after the end of a tar archive are ignored by tar readers, so
// "age -d -i key.txt safeshare-drop.tar.age | tar -x" unpacks it.
func sealDrop(name string, data []byte, message string, recipient age.Recipient) ([]byte, error) {
	// Room for the padded archive (tar headers and block rounding, plus up
	// to ~12% padding) and age's overhead (a header, and 16 bytes per 64 KiB
	// chunk), so the buffer isn't copied as it grows.
	archive := dropPaddedLength(int64(len(data)+len(message)) + 8*1024)
	var out bytes.Buffer
	out.Grow(int(archive + archive/4096 + 8*1024))
	enc, err := age.Encrypt(&out, recipient)
	if err != nil {
		return nil, err
	}
	counter := &countingWriter{w: enc}
	tw := tar.NewWriter(counter)
	if name != "" {
		if err := writeDropEntry(tw, name, data); err != nil {
			return nil, err
		}
	}
	if message != "" {
		if err := writeDropEntry(tw, dropMessageName, []byte(message)); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if pad := dropPaddedLength(counter.n) - counter.n; pad > 0 {
		if _, err := io.CopyN(counter, zeroReader{}, pad); err != nil {
			return nil, err
		}
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// writeDropEntry adds one regular file to the archive, with no owner, a
// fixed mode and a fixed time, so the archive says nothing about the
// sender's computer or when they made the file.
func writeDropEntry(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Typeflag: tar.TypeReg,
		Name:     name,
		Mode:     0o644,
		Size:     int64(len(data)),
		ModTime:  time.Unix(0, 0),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
}

// dropPaddedLength is the padded archive size for an n-byte archive: the
// PADME bucket (as for browser uploads, padmeLength in crypto.js), at least
// dropPadMin.
func dropPaddedLength(n int64) int64 {
	return max(padmeLength(n), dropPadMin)
}

// padmeLength rounds n up so that only its top bits are significant (PADME,
// Nikitin et al., PETS 2019): at most ~12% larger.
func padmeLength(n int64) int64 {
	if n < 2 {
		return n
	}
	e := int64(bits.Len64(uint64(n))) - 1 // floor(log2 n)
	s := int64(bits.Len64(uint64(e)))     // floor(log2 e) + 1
	lastBits := e - s
	if lastBits <= 0 {
		return n
	}
	mask := int64(1)<<lastBits - 1
	return (n + mask) &^ mask
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// createDropRecord stores the file row, under the quota when one is set.
func createDropRecord(ctx context.Context, repos *repository.Repositories, cfg *config.Config, record *models.File, quotaConfigured bool) error {
	if quotaConfigured {
		quotaBytes := cfg.GetQuotaLimitGB() * 1024 * 1024 * 1024
		err := repos.Files.CreateWithQuotaCheck(ctx, record, quotaBytes)
		// Same check as createFileRecord: some backends wrap the error.
		if err != nil && !errors.Is(err, repository.ErrQuotaExceeded) && strings.Contains(err.Error(), "quota exceeded") {
			return repository.ErrQuotaExceeded
		}
		return err
	}
	return repos.Files.Create(ctx, record)
}

// sendDropError sends an error page. message and detail must be plain text
// (the template escapes them).
func sendDropError(w http.ResponseWriter, status int, message, detail string) {
	w.Header().Set("Cache-Control", "no-store")
	renderDropPage(w, status, dropPage{Error: message, Detail: detail})
}

func renderDropPage(w http.ResponseWriter, status int, page dropPage) {
	var buf bytes.Buffer
	if err := dropResultTemplate.Execute(&buf, page); err != nil {
		slog.Error("failed to render drop page", "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

// shortRecipientKey shortens a post-quantum key (about 2,000 characters)
// to its start and end for the result page, which is enough to compare it
// with a copy the recipient published. Normal keys are shown whole.
func shortRecipientKey(key string) string {
	const keep = 24
	if len(key) <= 3*keep {
		return key
	}
	return key[:keep] + "…" + key[len(key)-keep:]
}

// formatDropSize formats a byte count for the error page.
func formatDropSize(n int64) string {
	const mb = 1024 * 1024
	if n >= mb {
		return fmt.Sprintf("%d MB", n/mb)
	}
	return fmt.Sprintf("%d KB", max(n/1024, 1))
}
