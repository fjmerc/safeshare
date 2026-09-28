package scanning

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
)

// errReadSource marks a streamChunks failure as coming from reading the
// LOCAL source (e.g. a missing chunk file) rather than from writing to
// clamd. The distinction matters to scanReader: clamd is healthy in this
// case and simply waiting for input that will never arrive, so attempting
// the mid-stream-failure best-effort read of "clamd's reply" would only
// waste up to a full idle timeout waiting for a reply that provably isn't
// coming (bug-hunter finding — this used to hang indefinitely before a
// deadline was added; see scanReader).
var errReadSource = errors.New("failed to read local source")

// ErrConnect marks a scan failure as a clamd connection/dial failure —
// clamd unreachable, connection refused, DNS failure, or the dial itself
// timing out. Distinct from a timeout waiting for a scan verdict, or a
// response clamd (or this client) couldn't parse: callers use this to
// decide what's worth retrying (bug-hunter finding — see
// internal/handlers/assembly_worker.go's scanChunkedUploadWithRetry, which
// retries only this case: a connection blip is plausibly transient, but a
// scan timeout or a clamd ERROR reply will just recur identically on retry,
// wasting an assembly-worker slot for up to the full backoff schedule).
var ErrConnect = errors.New("clamd connection failed")

// Scan status constants represent the possible outcomes of a file scan.
// These values are persisted to the files.scan_status column — do not
// change them without a migration (see ADR-015).
const (
	ScanStatusPending    = "pending"
	ScanStatusClean      = "clean"
	ScanStatusInfected   = "infected"
	ScanStatusError      = "error"
	ScanStatusSkipped    = "skipped"
	ScanStatusNotScanned = "not_scanned" // content was untrustworthy to scan (E2E ciphertext) or too large (see ADR-015)
)

// chunkSize is the size of each chunk sent to clamd via INSTREAM.
// 32KB balances memory usage and network efficiency.
const chunkSize = 32 * 1024

// Scanner defines the interface for file scanning implementations.
type Scanner interface {
	ScanFile(filePath string) (*ScanResult, error)
}

// ScanResult holds the outcome of a single file scan.
type ScanResult struct {
	// Clean is true when clamd confirmed no threats were found.
	Clean bool
	// Infected is true when clamd identified a known threat.
	Infected bool
	// VirusName is the threat name reported by clamd, empty if not infected.
	VirusName string
	// Skipped is true when the content was never sent to clamd because it
	// exceeded the configured size limit. Distinct from Clean: the caller
	// must not report a Skipped result as "clean" (ADR-015 — a prior
	// version did, which silently let oversized malware through).
	Skipped bool
	// Duration is the wall-clock time taken for the scan.
	Duration time.Duration
}

// ClamAVScanner connects to a running clamd instance via TCP and scans files
// using the INSTREAM protocol, which streams file data without writing to a
// shared socket directory.
type ClamAVScanner struct {
	host        string
	port        int
	timeout     time.Duration
	scanTimeout time.Duration
	maxFileSize int64
}

// NewClamAVScanner creates a ClamAVScanner that connects to clamd at host:port.
//
// timeout is an IDLE bound: the TCP dial, and each individual write while
// streaming chunks (see streamChunks) — it must never be exceeded by a
// healthy, still-progressing connection, however long the transfer takes
// overall.
//
// scanTimeout separately bounds the wait for clamd's verdict AFTER the
// entire stream (including its terminator) has been sent (bug-hunter
// finding: clamd buffers the whole INSTREAM before scanning it, so zero
// reply bytes flow while a large file is being scanned — conflating this
// with the idle timeout meant CLAMAV_TIMEOUT's sensible default for "is the
// connection stalled" was also, incorrectly, a hard cap on total scan time,
// well under clamd's own default MaxScanTime). Give this one plenty of
// headroom relative to clamd's MaxScanTime.
//
// Files larger than maxFileSize are skipped and reported as clean.
func NewClamAVScanner(host string, port int, timeout, scanTimeout time.Duration, maxFileSize int64) *ClamAVScanner {
	return &ClamAVScanner{
		host:        host,
		port:        port,
		timeout:     timeout,
		scanTimeout: scanTimeout,
		maxFileSize: maxFileSize,
	}
}

// ScanFile scans the file at filePath using clamd's INSTREAM protocol.
// It returns an error only for unrecoverable I/O or protocol failures;
// a detected virus is reported through ScanResult.Infected, not as an error.
//
// ScanFile is a thin wrapper around ScanReader kept for the Scanner
// interface and callers that only have a path on disk; new code that
// already has a reader (e.g. the synchronous upload path, ADR-015) should
// call ScanReader directly to avoid a redundant os.Open.
func (s *ClamAVScanner) ScanFile(filePath string) (*ScanResult, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("scanning: stat file: %w", err)
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("scanning: open file: %w", err)
	}
	defer f.Close()

	return s.ScanReader(context.Background(), f, info.Size())
}

// ScanReader scans r using clamd's INSTREAM protocol. size is the number of
// bytes r will yield; it is compared against the configured MaxFileSize
// before any data is sent to clamd, and content over the limit is reported
// as ScanResult.Skipped (never as clean — see ADR-015 finding 1e).
//
// It returns an error only for unrecoverable I/O, protocol, or clamd-side
// failures (including a clamd response clamd itself flags as ERROR, or any
// response this client doesn't recognize — ADR-015 finding 1c: an earlier
// version defaulted an unrecognized response to "clean", which silently
// waved through anything clamd couldn't parse). A detected virus is
// reported through ScanResult.Infected, not as an error.
func (s *ClamAVScanner) ScanReader(ctx context.Context, r io.Reader, size int64) (*ScanResult, error) {
	start := time.Now()

	if s.maxFileSize > 0 && size > s.maxFileSize {
		slog.Info("clamav: skipping oversized content",
			"size_bytes", size,
			"max_bytes", s.maxFileSize,
		)
		return &ScanResult{
			Skipped:  true,
			Duration: time.Since(start),
		}, nil
	}

	result, err := s.scanReader(ctx, r, "<stream>")
	if err != nil {
		return nil, err
	}
	result.Duration = time.Since(start)
	return result, nil
}

// scanReader performs the actual INSTREAM exchange with clamd.
// filePath is used only for log messages.
func (s *ClamAVScanner) scanReader(ctx context.Context, r io.Reader, filePath string) (*ScanResult, error) {
	addr := net.JoinHostPort(s.host, fmt.Sprintf("%d", s.port))

	dialer := net.Dialer{Timeout: s.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("scanning: connect to clamd at %s: %w: %w", addr, ErrConnect, err)
	}
	defer func() { _ = conn.Close() }()

	// Tie the connection lifetime to ctx: if the caller's context is
	// cancelled (request aborted, shutdown) while a scan is in flight, close
	// the socket so the blocked Read/Write returns immediately instead of
	// riding out the full idle timeout.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	// The zINSTREAM\0 command prefix uses the null-terminated command format
	// (the 'z' prefix) which clamd requires for the streaming protocol.
	if err := conn.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, fmt.Errorf("scanning: set write deadline: %w", err)
	}
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return nil, fmt.Errorf("scanning: send INSTREAM command: %w", err)
	}

	if err := s.streamChunks(conn, r); err != nil {
		// clamd may have already closed the stream with a diagnostic reply
		// (e.g. a size-limit or protocol error) before this write failed;
		// best-effort read it so the log shows clamd's side of the story too.
		// Skipped entirely when the failure was reading the LOCAL source
		// (errReadSource) — clamd is healthy and just waiting for input that
		// will never come, so there's no reply to wait for, and even the
		// bounded wait below would just waste up to a full idle timeout.
		if !errors.Is(err, errReadSource) {
			// Bounded deadline even so: without one, a write failure whose
			// cause left clamd equally silent would otherwise hang this read
			// forever instead of returning the original error.
			if dErr := conn.SetReadDeadline(time.Now().Add(s.timeout)); dErr == nil {
				if resp, rErr := s.readResponse(conn); rErr == nil && resp != "" {
					slog.Warn("clamav: mid-stream write failure; clamd replied before closing",
						"path", filePath,
						"response", resp,
					)
				}
			}
		}
		return nil, fmt.Errorf("scanning: stream file %q: %w", filePath, err)
	}

	// scanTimeout, not the idle timeout: clamd sends nothing at all until it
	// has fully received AND scanned the stream, so this has to accommodate
	// a large-but-legitimate scan, not just network idleness.
	if err := conn.SetReadDeadline(time.Now().Add(s.scanTimeout)); err != nil {
		return nil, fmt.Errorf("scanning: set read deadline: %w", err)
	}
	response, err := s.readResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("scanning: read clamd response: %w", err)
	}

	slog.Debug("clamav: scan response",
		"path", filePath,
		"response", response,
	)

	result, err := parseResponse(response)
	if err != nil {
		return nil, fmt.Errorf("scanning: %w", err)
	}
	return result, nil
}

// streamChunks writes the file content to conn using the INSTREAM framing:
// each chunk is preceded by its 4-byte big-endian length, and a zero-length
// chunk signals end-of-stream.
//
// The write deadline is reset before every chunk rather than set once for
// the whole transfer: s.timeout is an IDLE timeout (clamd or the network
// stalling), not a total-scan budget, so a large-but-healthy stream that
// takes longer than s.timeout end-to-end must not be aborted as long as
// each individual write keeps making progress.
func (s *ClamAVScanner) streamChunks(conn net.Conn, r io.Reader) error {
	buf := make([]byte, chunkSize)
	lenBuf := make([]byte, 4)

	for {
		n, readErr := r.Read(buf)
		if n > 0 {
			if err := conn.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
				return fmt.Errorf("set write deadline: %w", err)
			}
			binary.BigEndian.PutUint32(lenBuf, uint32(n))
			if _, err := conn.Write(lenBuf); err != nil {
				return fmt.Errorf("write chunk length: %w", err)
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return fmt.Errorf("write chunk data: %w", err)
			}
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("read source: %w: %w", errReadSource, readErr)
		}
	}

	// Zero-length chunk terminates the stream.
	if err := conn.SetWriteDeadline(time.Now().Add(s.timeout)); err != nil {
		return fmt.Errorf("set write deadline: %w", err)
	}
	binary.BigEndian.PutUint32(lenBuf, 0)
	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("write stream terminator: %w", err)
	}

	return nil
}

// maxResponseSize bounds how much of clamd's response readResponse will
// buffer (L3 bug-hunter finding). Real clamd replies are a short line
// ("stream: OK", "stream: <name> FOUND", or an ERROR message); this is
// purely a guard against a misbehaving or malicious peer on the clamd
// connection sending an unterminated stream and growing the buffer
// unbounded.
const maxResponseSize = 4096

// readResponse reads clamd's null-terminated response line.
// clamd always responds with a single null-terminated string for INSTREAM.
func (s *ClamAVScanner) readResponse(conn net.Conn) (string, error) {
	var sb strings.Builder
	oneByte := make([]byte, 1)

	for sb.Len() < maxResponseSize {
		_, err := conn.Read(oneByte)
		if err != nil {
			// io.EOF mid-response is unexpected but treat the accumulated
			// bytes as the complete response to be tolerant of clamd
			// implementations that omit the trailing null.
			if err == io.EOF {
				break
			}
			return "", fmt.Errorf("read response byte: %w", err)
		}
		if oneByte[0] == 0x00 {
			break
		}
		sb.WriteByte(oneByte[0])
	}

	return sb.String(), nil
}

// parseResponse converts a raw clamd response string to a ScanResult.
// Expected formats:
//
//	"stream: OK"                   - file is clean
//	"stream: <VirusName> FOUND"    - file is infected
//
// Anything else — clamd's own "... ERROR" replies (e.g. a malformed stream,
// or a size limit clamd itself enforced) as well as any response this client
// doesn't recognize — is treated as a scan error, never as clean. ADR-015
// finding 1c: a prior version defaulted the unrecognized case to Clean=true,
// which meant a clamd misconfiguration or protocol hiccup silently passed
// every upload. FOUND is checked first since a virus name could
// coincidentally contain the substring "OK".
func parseResponse(response string) (*ScanResult, error) {
	switch {
	case strings.HasSuffix(response, "FOUND"):
		// Extract virus name: response is "stream: <VirusName> FOUND"
		trimmed := strings.TrimPrefix(response, "stream: ")
		trimmed = strings.TrimSuffix(trimmed, " FOUND")
		return &ScanResult{Infected: true, VirusName: trimmed}, nil

	case response == "stream: OK":
		return &ScanResult{Clean: true}, nil

	default:
		return nil, fmt.Errorf("unexpected clamd response: %q", response)
	}
}
