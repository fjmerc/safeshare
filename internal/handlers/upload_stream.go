package handlers

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/fjmerc/safeshare/internal/utils"
)

// Limits for streamed multipart upload bodies. http.Request.ParseMultipartForm
// enforced equivalents implicitly; the streaming parsers below read the body
// part by part themselves, so they enforce their own.
const (
	// maxUploadFormParts caps how many parts one upload body may contain.
	maxUploadFormParts = 32
	// maxUploadFormValueSize caps each non-file form field.
	maxUploadFormValueSize = 64 << 10
	// uploadSpoolDirName is where simple uploads are spooled while being
	// processed, under the upload directory (see spoolUploadForm).
	uploadSpoolDirName = ".spool"
)

var (
	// errNoFormFile means the body had no file part with the wanted name.
	errNoFormFile = errors.New("no file part in form")
	// errTooManyFormParts means the body exceeded maxUploadFormParts.
	errTooManyFormParts = errors.New("too many form parts")
	// errFormValueTooLarge means a non-file field exceeded
	// maxUploadFormValueSize.
	errFormValueTooLarge = errors.New("form field too large")
)

// spoolError marks a local failure writing the spool file (as opposed to a
// malformed or oversized request body), so callers can answer 500.
type spoolError struct{ err error }

func (e *spoolError) Error() string { return "failed to spool upload: " + e.err.Error() }
func (e *spoolError) Unwrap() error { return e.err }

// errRecordingWriter remembers the last error its writer returned, so a
// failed io.Copy can be attributed to the write side or the read side.
type errRecordingWriter struct {
	w   io.Writer
	err error
}

func (e *errRecordingWriter) Write(p []byte) (int, error) {
	n, err := e.w.Write(p)
	if err != nil {
		e.err = err
	}
	return n, err
}

// spoolDiskCheckInterval is how many spooled bytes pass between free-space
// checks in diskGuardWriter.
const spoolDiskCheckInterval = 64 << 20

// diskGuardWriter fails a spool write with ENOSPC once free space on dir
// drops below utils.MinimumFreeSpace, checked every spoolDiskCheckInterval
// bytes. The up-front disk checks only see the space free before a spool
// starts (and nothing at all for a body without Content-Length), so
// concurrent large uploads could otherwise drain the volume past the
// reserve every other write relies on.
type diskGuardWriter struct {
	w       io.Writer
	dir     string
	pending int64
}

func (d *diskGuardWriter) Write(p []byte) (int, error) {
	d.pending += int64(len(p))
	if d.pending >= spoolDiskCheckInterval {
		d.pending = 0
		info, err := utils.GetDiskSpace(d.dir)
		if err != nil {
			return 0, err
		}
		if info.AvailableBytes < utils.MinimumFreeSpace {
			return 0, fmt.Errorf("free space below reserve: %w", syscall.ENOSPC)
		}
	}
	return d.w.Write(p)
}

// spoolUploadForm streams a multipart upload body (T29): the first file part
// named fileField is copied to a temp file under
// <uploadDir>/uploadSpoolDirName instead of being buffered in memory, and
// every other non-file field is collected into r.Form/r.PostForm, so
// r.FormValue keeps working for them afterwards. Additional file parts are
// read and discarded, matching r.FormFile's first-one-wins behavior.
//
// The spool file is unlinked as soon as it's created; the returned open
// handle keeps its data readable (POSIX semantics - SafeShare runs on
// Linux), and nothing is left on disk once it's closed, even if the process
// dies mid-upload. Spooling under the upload directory (rather than the
// system temp dir, as ParseMultipartForm would) keeps the bytes on the
// volume the disk-space checks measure, and works with a read-only root
// filesystem. The caller must Close the returned file.
//
// r.Body must already be wrapped in http.MaxBytesReader. Errors: a
// *spoolError for a local write failure, errNoFormFile when there's no
// such file part, anything else for a malformed or oversized body.
func spoolUploadForm(r *http.Request, fileField, uploadDir string) (_ *os.File, _ *multipart.FileHeader, err error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, nil, err
	}

	// The spooled file lives in a local, not a named result: error returns
	// below write nil into the results before deferred calls run, so a
	// deferred close of a named result would never see the open file.
	var file *os.File
	var header *multipart.FileHeader
	defer func() {
		if err != nil && file != nil {
			file.Close()
		}
	}()

	values := url.Values{}
	for parts := 0; ; parts++ {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		if parts >= maxUploadFormParts {
			_ = part.Close()
			return nil, nil, errTooManyFormParts
		}

		if part.FileName() != "" {
			if part.FormName() == fileField && file == nil {
				file, header, err = spoolFilePart(part, filepath.Join(uploadDir, uploadSpoolDirName))
			} else {
				_, err = io.Copy(io.Discard, part)
			}
			_ = part.Close()
			if err != nil {
				return nil, nil, err
			}
			continue
		}

		value, err := io.ReadAll(io.LimitReader(part, maxUploadFormValueSize+1))
		_ = part.Close()
		if err != nil {
			return nil, nil, err
		}
		if len(value) > maxUploadFormValueSize {
			return nil, nil, errFormValueTooLarge
		}
		if name := part.FormName(); name != "" {
			values.Add(name, string(value))
		}
	}

	if file == nil {
		return nil, nil, errNoFormFile
	}

	// Populate the form the way ParseMultipartForm would have: URL query
	// values first, then body values, so FormValue keeps returning a query
	// value when both are present. Both fields must be non-nil, or
	// FormValue/PostFormValue would try to parse the already-consumed body.
	r.PostForm = values
	form := r.URL.Query()
	for k, v := range values {
		form[k] = append(form[k], v...)
	}
	r.Form = form
	return file, header, nil
}

// spoolFilePart copies part into a new, immediately unlinked temp file in
// spoolDir and returns it rewound to the start, with a FileHeader carrying
// the part's filename, headers and size.
func spoolFilePart(part *multipart.Part, spoolDir string) (*os.File, *multipart.FileHeader, error) {
	if err := os.MkdirAll(spoolDir, 0700); err != nil {
		return nil, nil, &spoolError{err}
	}
	f, err := os.CreateTemp(spoolDir, "upload-*")
	if err != nil {
		return nil, nil, &spoolError{err}
	}
	if err := os.Remove(f.Name()); err != nil {
		f.Close()
		return nil, nil, &spoolError{err}
	}

	writer := &errRecordingWriter{w: &diskGuardWriter{w: f, dir: spoolDir}}
	size, err := io.Copy(writer, part)
	if err != nil {
		f.Close()
		if writer.err != nil {
			return nil, nil, &spoolError{writer.err}
		}
		return nil, nil, err // reading the body failed
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, nil, &spoolError{err}
	}

	return f, &multipart.FileHeader{
		Filename: part.FileName(),
		Header:   part.Header,
		Size:     size,
	}, nil
}

// nextFormFilePart advances a streamed multipart body to the first file part
// named fileField, reading and discarding any parts before it, and returns
// it for the caller to read directly (#19: chunk uploads stream straight to
// disk instead of being buffered). Parts after it are left unread. Returns
// errNoFormFile when there's no such part.
func nextFormFilePart(r *http.Request, fileField string) (*multipart.Part, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, err
	}
	for parts := 0; parts < maxUploadFormParts; parts++ {
		part, err := mr.NextPart()
		if err == io.EOF {
			return nil, errNoFormFile
		}
		if err != nil {
			return nil, err
		}
		if part.FormName() == fileField && part.FileName() != "" {
			return part, nil
		}
		// Bounded by the caller's MaxBytesReader.
		_, err = io.Copy(io.Discard, part)
		_ = part.Close()
		if err != nil {
			return nil, fmt.Errorf("failed to skip form part: %w", err)
		}
	}
	return nil, errTooManyFormParts
}

// defaultIdleReadInterval is how long an upload body may go without
// delivering any bytes before its read deadline fires - see
// idleDeadlineReader. A package var (not a const) so tests can shrink it.
var defaultIdleReadInterval = 60 * time.Second

// minUploadReadRate is the slowest sustained average rate, in bytes per
// second, idleDeadlineReader tolerates for an upload body: 4 KiB/s. Lower
// than the download floor (minDecryptWriteRate) on purpose: uploads had no
// rate floor at all before, and slow uplinks (mobile, Tor) must keep
// working. A package var so tests can change it.
var minUploadReadRate int64 = 4 * 1024

// idleDeadlineReader wraps an upload request body so that a client that
// stops sending - or drips bytes too slowly to matter - is cut off within
// about a minute, instead of holding the connection and everything already
// received (a spool file, a chunk temp file) until the request's full
// transfer deadline, up to 6h (T50). It's the read-side counterpart of
// idleDeadlineWriter (claim_range.go) and uses the same three bounds: the
// absolute transfer deadline, now + idle after every successful read, and
// an average-rate floor of start + idle + read/minUploadReadRate.
//
// The deadline is armed at construction, before the first Read, so a client
// that never sends a byte of body is covered too. Once the body has been
// consumed, the caller must call drainRest and then finish: the request carries on (malware
// scan, encryption, database writes) and the short idle deadline would
// otherwise fire mid-way - net/http cancels a request's context when its
// connection's read deadline passes.
type idleDeadlineReader struct {
	io.ReadCloser
	rc       *http.ResponseController
	idle     time.Duration
	minRate  int64
	absolute time.Time
	start    time.Time
	read     int64
	lastSet  time.Time // deadline most recently applied
	done     bool      // finish restored the absolute deadline; stop re-arming
}

// newIdleDeadlineReader wraps body and arms its read deadline. absolute is
// the transfer deadline already set for the request (see
// extendTransferDeadline) and is never loosened.
func newIdleDeadlineReader(w http.ResponseWriter, body io.ReadCloser, absolute time.Time) *idleDeadlineReader {
	idr := &idleDeadlineReader{
		ReadCloser: body,
		rc:         http.NewResponseController(w),
		idle:       defaultIdleReadInterval,
		minRate:    minUploadReadRate,
		absolute:   absolute,
		start:      time.Now(),
	}
	idr.applyDeadline()
	return idr
}

// Read re-arms the deadline before each read, so the idle window measures
// only time spent waiting on the client - not time the handler spent
// between reads (e.g. a slow disk write).
func (idr *idleDeadlineReader) Read(p []byte) (int, error) {
	if !idr.done {
		idr.applyDeadline()
	}
	n, err := idr.ReadCloser.Read(p)
	idr.read += int64(n)
	return n, err
}

// computeDeadline returns the earliest of the three bounds described on the
// type. It starts from now + idle, which is never zero, and only tightens
// with absolute when that's set (a zero deadline would mean "none at all").
func (idr *idleDeadlineReader) computeDeadline() time.Time {
	deadline := time.Now().Add(idr.idle)
	if !idr.absolute.IsZero() && idr.absolute.Before(deadline) {
		deadline = idr.absolute
	}
	rate := max(idr.minRate, 1)
	if avgFloor := idr.start.Add(idr.idle).Add(time.Duration(idr.read/rate) * time.Second); avgFloor.Before(deadline) {
		deadline = avgFloor
	}
	return deadline
}

// applyDeadline sets the computed deadline, skipping it when it would only
// push the current one later by under a second: reads arrive in small
// pieces (multipart reads at most 4 KiB at a time), and on HTTP/2 every
// SetReadDeadline is a round trip to the connection's serve loop.
func (idr *idleDeadlineReader) applyDeadline() {
	deadline := idr.computeDeadline()
	if !idr.lastSet.IsZero() && !deadline.Before(idr.lastSet) && deadline.Sub(idr.lastSet) < time.Second {
		return
	}
	idr.lastSet = deadline
	if err := idr.rc.SetReadDeadline(deadline); err != nil {
		slog.Debug("failed to apply idle read deadline", "error", err)
	}
}

// finish is called once the handler has stopped reading the body, with the
// error (if any) reading it ended with. Normally it puts the read deadline
// back to the absolute transfer deadline (see the type doc). After a
// timeout it leaves the short, already-expired deadline in place instead:
// net/http may still read the rest of the body before writing the
// response (it does for a small remainder), and with the long deadline
// restored that read would block on the stalled client for hours - the
// 408 would never even be sent. See sendUploadTimeout.
//
// After any other error the short deadline is kept too: the handler only
// sends an error response, and net/http may first read the unread rest of
// the body (always for a chunked-encoding body), which must not wait on the
// client for the full transfer deadline. Only a successfully read body -
// read to its end, see drainRest - gets the absolute deadline back, which
// protects the processing that follows (net/http cancels the request's
// context if the read deadline passes once the body has hit EOF).
func (idr *idleDeadlineReader) finish(err error) {
	if err != nil {
		return
	}
	idr.done = true
	idr.lastSet = idr.absolute
	if err := idr.rc.SetReadDeadline(idr.absolute); err != nil {
		slog.Debug("failed to restore absolute read deadline", "error", err)
	}
}

// drainRest reads and discards whatever is left of the body (a multipart
// epilogue, or parts after the one the handler needed), still under the
// idle deadline and the body's size limit, so the body is fully consumed
// before finish restores the long deadline.
func (idr *idleDeadlineReader) drainRest() error {
	_, err := io.Copy(io.Discard, idr)
	return err
}

// isUploadTimeout reports whether err comes from an upload body's read
// deadline firing (see idleDeadlineReader).
func isUploadTimeout(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// sendUploadTimeout answers an upload whose body stalled with 408 and closes
// the connection: the rest of the body was never read, so the connection
// can't be reused, and Connection: close also stops net/http from trying to
// read that remainder before sending the response.
//
// Only on HTTP/1.x: on HTTP/2 the unread body is handled by resetting the
// stream, and Connection: close would instead shut down the whole
// connection, which (behind a reverse proxy) carries other users' requests.
func sendUploadTimeout(w http.ResponseWriter, r *http.Request) {
	if r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
	}
	sendError(w, "Upload stalled and timed out", "UPLOAD_TIMEOUT", http.StatusRequestTimeout)
}
