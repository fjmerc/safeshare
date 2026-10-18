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
	"strings"
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
	// dropStripBudget is the extra request time allowed for stripping (the
	// PDF stripper's own limit is 60s).
	dropStripBudget = 90 * time.Second
)

var (
	errDropTooLarge     = errors.New("drop: file too large")
	errDropMessageBig   = errors.New("drop: message too long")
	errDropTooManyParts = errors.New("drop: too many form parts")
)

// dropResultTemplate renders both the success page and error pages.
var dropResultTemplate = template.Must(template.ParseFS(static.Templates(), "drop-result.html"))

type dropPage struct {
	// Error is set on an error page, with an optional Detail.
	Error, Detail string

	ClaimCode, Link, Expires, Recipient string
	HasFile, Cleaned                    bool
}

// dropExtensionTypes maps the extensions of the file types the server can
// clean to the type their content must have. A file named like one of them
// whose content isn't that type would otherwise be sent uncleaned; it is
// refused instead.
var dropExtensionTypes = map[string]string{
	".jpg":  "image/jpeg",
	".jpeg": "image/jpeg",
	".png":  "image/png",
	".pdf":  "application/pdf",
	".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
	".mp4":  "video/mp4",
	".mov":  "video/quicktime",
	".mp3":  "audio/mpeg",
}

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
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, "drop.html", stat.ModTime(), f.(io.ReadSeeker))
	}
}

// DropHandler handles a drop (POST /drop). See the comment at the top of
// this file. It answers with an HTML page, since the sender has no script to
// read JSON.
//
// The plaintext must never reach the disk: the body is read with
// r.MultipartReader only (r.FormValue and ParseMultipartForm spool files to
// the temp dir), and only the age ciphertext is written.
func DropHandler(repos *repository.Repositories, cfg *config.Config) http.HandlerFunc {
	slots := make(chan struct{}, max(cfg.Drop.MaxConcurrent, 1))

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

		// Each drop is held in memory: bound how many run at once.
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			w.Header().Set("Retry-After", "30")
			sendDropError(w, http.StatusServiceUnavailable, "The server is busy.", "Nothing was sent. Please try again in a minute.")
			return
		}

		maxSize := cfg.Drop.MaxSize
		if limit := cfg.GetMaxFileSize(); limit < maxSize {
			maxSize = limit
		}
		extra := dropStripBudget
		if cfg.Features.IsMalwareScanEnabled() {
			extra += time.Duration(cfg.ClamAV.ScanTimeout)*time.Second + 30*time.Second
		}
		deadline := extendTransferDeadlineWithExtra(w, cfg, maxSize+dropFormSlack, extra)
		body := newIdleDeadlineReader(w, http.MaxBytesReader(w, r.Body, maxSize+dropFormSlack), deadline)
		r.Body = body

		form, err := readDropForm(r, maxSize)
		if err == nil {
			err = body.drainRest()
		}
		body.finish(err)
		if err != nil {
			sendDropFormError(w, r, err, maxSize)
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
// (at most maxSize bytes) and the "message" field. Other parts are read
// and discarded. r.Body must already be size-limited.
func readDropForm(r *http.Request, maxSize int64) (*dropForm, error) {
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
			form.data, err = readAllCapped(part, maxSize, errDropTooLarge)
		case part.FormName() == "message" && part.FileName() == "" && !gotMessage:
			gotMessage = true
			var msg []byte
			msg, err = readAllCapped(part, dropMaxMessage, errDropMessageBig)
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

// readAllCapped reads r into memory, failing with tooLarge past limit bytes.
func readAllCapped(r io.Reader, limit int64, tooLarge error) ([]byte, error) {
	var buf bytes.Buffer
	n, err := buf.ReadFrom(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if n > limit {
		return nil, tooLarge
	}
	return buf.Bytes(), nil
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
	case errors.Is(err, errDropMessageBig):
		sendDropError(w, http.StatusRequestEntityTooLarge, "The message is too long.", "Nothing was sent. Shorten the message, or put it in a file.")
	default:
		sendDropError(w, http.StatusBadRequest, "The upload couldn't be read.", "Nothing was sent. Please try again.")
	}
}

// handleDrop checks, cleans, encrypts and stores a parsed drop, then sends
// the result page.
func handleDrop(w http.ResponseWriter, r *http.Request, repos *repository.Repositories, cfg *config.Config, form *dropForm) {
	ctx := r.Context()
	clientIP := getClientIP(r)
	hasFile := form.filename != "" || len(form.data) > 0
	if !hasFile && strings.TrimSpace(form.message) == "" {
		sendDropError(w, http.StatusBadRequest, "Nothing to send.", "Choose a file or write a message.")
		return
	}
	if hasFile && len(form.data) == 0 {
		sendDropError(w, http.StatusBadRequest, "The file is empty.", "Nothing was sent.")
		return
	}

	name := ""
	cleaned := false
	if hasFile {
		if err := utils.ValidateUploadFilename(form.filename); err != nil {
			sendDropError(w, http.StatusBadRequest, "The file name isn't allowed.", "Rename the file and try again.")
			return
		}
		name = utils.SanitizeFilename(form.filename)
		if name == "" || name == "." || name == ".." {
			name = "file"
		}
		allowed, blockedExt, err := utils.IsFileAllowed(name, cfg.GetBlockedExtensions())
		if err != nil {
			sendDropError(w, http.StatusBadRequest, "The file name isn't allowed.", "Rename the file and try again.")
			return
		}
		if !allowed {
			sendDropError(w, http.StatusBadRequest, "This kind of file isn't accepted.",
				fmt.Sprintf("This server doesn't accept %s files.", blockedExt))
			return
		}

		if !scanDrop(w, r, cfg, form.data) {
			return
		}

		var ok bool
		form.data, cleaned, ok = stripDrop(w, cfg, name, form.data)
		if !ok {
			return
		}
	}
	if name == dropMessageName {
		name = "file-" + dropMessageName
	}

	recipient := cfg.Drop.Recipient
	sealed, err := sealDrop(name, form.data, form.message, recipient)
	// The plaintext isn't needed any more.
	form.data, form.message = nil, ""
	if err != nil {
		slog.Error("failed to encrypt drop", "error", err)
		sendDropError(w, http.StatusInternalServerError, "Something went wrong on the server.", "Nothing was sent.")
		return
	}

	quotaConfigured := cfg.GetQuotaLimitGB() > 0
	if hasSpace, _, err := utils.CheckDiskSpace(cfg.UploadDir, int64(len(sealed)), quotaConfigured); err != nil || !hasSpace {
		if err != nil {
			slog.Error("failed to check disk space", "error", err)
		}
		sendDropError(w, http.StatusInsufficientStorage, "The server is out of space.", "Nothing was sent.")
		return
	}

	claimCode, err := newUniqueClaimCode(ctx, repos)
	if err != nil {
		sendDropError(w, http.StatusInternalServerError, "Something went wrong on the server.", "Nothing was sent.")
		return
	}

	if err := os.MkdirAll(cfg.UploadDir, 0755); err != nil {
		slog.Error("failed to create upload directory", "error", err)
		sendDropError(w, http.StatusInternalServerError, "Something went wrong on the server.", "Nothing was sent.")
		return
	}
	storedFilename := uuid.New().String() + ".age"
	filePath := filepath.Join(cfg.UploadDir, storedFilename)
	written, hash, encFileID, err := writeStoredFile(bytes.NewReader(sealed), int64(len(sealed)), filePath, cfg)
	if err != nil {
		sendDropError(w, http.StatusInternalServerError, "Something went wrong on the server.", "Nothing was sent.")
		return
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
		// The plaintext was scanned above (scanDrop); what's stored is age
		// ciphertext, which a download-time scan can't read.
		now := storeScannedAt(time.Now(), cfg)
		record.ScanStatus = dropScanStatus(hasFile)
		record.ScannedAt = &now
	}
	if err := createDropRecord(ctx, repos, cfg, record, quotaConfigured); err != nil {
		os.Remove(filePath)
		if errors.Is(err, repository.ErrQuotaExceeded) {
			sendDropError(w, http.StatusInsufficientStorage, "The server is out of space.", "Nothing was sent.")
			return
		}
		slog.Error("failed to create drop record", "error", err)
		sendDropError(w, http.StatusInternalServerError, "Something went wrong on the server.", "Nothing was sent.")
		return
	}

	slog.Info("drop received",
		"claim_code", redactClaimCode(claimCode),
		"stored_size", written,
		"has_file", hasFile,
		"cleaned", cleaned,
		"client_ip", logIP(clientIP, cfg),
	)

	renderDropPage(w, http.StatusOK, dropPage{
		ClaimCode: claimCode,
		Link:      buildShareURL(r, cfg, claimCode),
		Expires:   record.ExpiresAt.UTC().Format("2 January 2006, 15:04 UTC"),
		Recipient: shortRecipientKey(cfg.Drop.RecipientKey),
		HasFile:   hasFile,
		Cleaned:   cleaned,
	})
}

// dropScanStatus is the scan status recorded for a drop that passed
// scanDrop: a message-only drop has nothing to scan.
func dropScanStatus(hasFile bool) string {
	if hasFile {
		return scanning.ScanStatusClean
	}
	return scanning.ScanStatusNotScanned
}

// scanDrop runs the malware scan on the plaintext, with the same rules as
// direct uploads. It answers and returns false when the drop must stop.
func scanDrop(w http.ResponseWriter, r *http.Request, cfg *config.Config, data []byte) bool {
	if !cfg.Features.IsMalwareScanEnabled() {
		return true
	}
	if cfg.ClamAV.RejectUnscannable && isUnscannable(cfg, int64(len(data)), false) {
		sendDropError(w, http.StatusUnprocessableEntity, "This file is too large to be checked for viruses, and this server refuses files it can't check.", "Nothing was sent.")
		return false
	}
	verdict, err := scanUpload(r.Context(), cfg, bytes.NewReader(data), int64(len(data)), false)
	if err != nil {
		if !cfg.ClamAV.AllowUnverified {
			slog.Error("malware scan failed; rejecting drop (fail closed)", "error", err)
			w.Header().Set("Retry-After", "30")
			sendDropError(w, http.StatusServiceUnavailable, "The virus check isn't working right now.", "Nothing was sent. Please try again shortly.")
			return false
		}
		slog.Warn("malware scan failed; accepting drop unverified (MALWARE_SCAN_ALLOW_UNVERIFIED)", "error", err)
		return true
	}
	if verdict.status == scanning.ScanStatusInfected {
		slog.Warn("malware detected in drop; rejected", "virus", verdict.result, "client_ip", logIP(getClientIP(r), cfg))
		sendDropError(w, http.StatusUnprocessableEntity, "The virus check flagged this file.", "Nothing was sent.")
		return false
	}
	return true
}

// stripDrop removes the file's metadata in memory. It fails closed, in
// every mode: a file of a type the server can clean is refused if cleaning
// fails, and so is one whose name says it is such a type when its content
// isn't. It returns the cleaned file, whether anything was cleaned, and
// false after answering when the drop must stop.
func stripDrop(w http.ResponseWriter, cfg *config.Config, name string, data []byte) ([]byte, bool, bool) {
	mimeType := mimetype.Detect(data).String()
	if i := strings.IndexByte(mimeType, ';'); i >= 0 {
		mimeType = mimeType[:i]
	}
	ext := strings.ToLower(filepath.Ext(name))
	if want, ok := dropExtensionTypes[ext]; ok && want != mimeType {
		sendDropError(w, http.StatusUnprocessableEntity, "The file's name doesn't match its content.",
			fmt.Sprintf("It is named like a %s file but isn't one, so its hidden information couldn't be removed. Nothing was sent.", strings.ToUpper(strings.TrimPrefix(ext, "."))))
		return nil, false, false
	}
	if !privacy.SupportsMetadataStripping(mimeType) {
		return data, false, true
	}

	out, err := stripMetadataBytesSafe(data, mimeType)
	if err != nil {
		slog.Warn("drop rejected: metadata stripping failed", "mime_type", mimeType, "error", err)
		detail := "Its hidden information couldn't be removed, so nothing was sent."
		switch {
		case errors.Is(err, privacy.ErrEncryptedDocument):
			detail = "It is password-protected, so its hidden information couldn't be removed. Nothing was sent. Remove the password and try again."
		case errors.Is(err, privacy.ErrFileTooLarge):
			detail = "It is too large to have its hidden information removed. Nothing was sent."
		}
		sendDropError(w, http.StatusUnprocessableEntity, "The file couldn't be cleaned.", detail)
		return nil, false, false
	}
	return out, true, true
}

// stripMetadataBytesSafe is privacy.StripMetadataBytes with a recover: the
// strippers parse untrusted input (pdfcpu has panicked on crafted files),
// and a panic must reject the drop, not send it uncleaned.
func stripMetadataBytesSafe(data []byte, mimeType string) (out []byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			out, err = nil, fmt.Errorf("metadata stripping panicked: %v", p)
		}
	}()
	return privacy.StripMetadataBytes(data, mimeType)
}

// sealDrop packs the file (as name) and the message into a tar archive,
// pads it with zero bytes to a PADME bucket, and encrypts it to recipient.
// Zero bytes after the end of a tar archive are ignored by tar readers, so
// "age -d -i key.txt safeshare-drop.tar.age | tar -x" unpacks it.
func sealDrop(name string, data []byte, message string, recipient age.Recipient) ([]byte, error) {
	var out bytes.Buffer
	out.Grow(len(data) + len(message) + 16*1024)
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
