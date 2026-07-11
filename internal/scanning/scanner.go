package scanning

import (
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"
)

// Scan status constants represent the possible outcomes of a file scan.
const (
	ScanStatusPending  = "pending"
	ScanStatusClean    = "clean"
	ScanStatusInfected = "infected"
	ScanStatusError    = "error"
	ScanStatusSkipped  = "skipped"
)

// chunkSize is the size of each chunk sent to clamd via INSTREAM.
// 32KB balances memory usage and network efficiency.
const chunkSize = 32 * 1024

// Scanner defines the interface for file scanning implementations.
type Scanner interface {
	ScanFile(filePath string) (*ScanResult, error)
}

// ScanResult holds the outcome of a single file scan.
//
// Exactly one of Clean/Infected is true for a definitive verdict. When clamd
// returns an unrecognised reply (e.g. "INSTREAM size limit exceeded. ERROR"),
// BOTH are false: the scan is inconclusive and MUST be treated as not-clean by
// callers. Never infer "clean" from the absence of Infected.
type ScanResult struct {
	// Clean is true only when clamd affirmatively confirmed no threats.
	Clean bool
	// Infected is true when clamd identified a known threat.
	Infected bool
	// VirusName is the threat name reported by clamd, empty if not infected.
	VirusName string
	// Unknown is true when clamd returned an unrecognised/error reply and no
	// verdict could be determined. Callers must fail closed on this.
	Unknown bool
	// RawResponse is the raw clamd reply, retained for diagnostics on Unknown.
	RawResponse string
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
	maxFileSize int64
}

// NewClamAVScanner creates a ClamAVScanner that connects to clamd at host:port.
// timeout applies to both the TCP dial and the full scan operation.
// Files larger than maxFileSize are skipped and reported as clean.
func NewClamAVScanner(host string, port int, timeout time.Duration, maxFileSize int64) *ClamAVScanner {
	return &ClamAVScanner{
		host:        host,
		port:        port,
		timeout:     timeout,
		maxFileSize: maxFileSize,
	}
}

// ScanFile scans the file at filePath using clamd's INSTREAM protocol.
// It returns an error only for unrecoverable I/O or protocol failures;
// a detected virus is reported through ScanResult.Infected, not as an error.
func (s *ClamAVScanner) ScanFile(filePath string) (*ScanResult, error) {
	start := time.Now()

	// Stat the file before opening it so we can enforce the size limit without
	// streaming any data to clamd.
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("scanning: stat file: %w", err)
	}

	if s.maxFileSize > 0 && info.Size() > s.maxFileSize {
		slog.Info("clamav: skipping oversized file",
			"path", filePath,
			"size_bytes", info.Size(),
			"max_bytes", s.maxFileSize,
		)
		return &ScanResult{
			Clean:    true,
			Duration: time.Since(start),
		}, nil
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("scanning: open file: %w", err)
	}
	defer f.Close()

	result, err := s.scanReader(f, filePath)
	if err != nil {
		return nil, err
	}
	result.Duration = time.Since(start)
	return result, nil
}

// scanReader performs the actual INSTREAM exchange with clamd.
// filePath is used only for log messages.
func (s *ClamAVScanner) scanReader(r io.Reader, filePath string) (*ScanResult, error) {
	addr := net.JoinHostPort(s.host, fmt.Sprintf("%d", s.port))

	conn, err := net.DialTimeout("tcp", addr, s.timeout)
	if err != nil {
		return nil, fmt.Errorf("scanning: connect to clamd at %s: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	// Apply a single deadline that covers the entire scan so a slow or
	// unresponsive clamd cannot block the caller indefinitely.
	if err := conn.SetDeadline(time.Now().Add(s.timeout)); err != nil {
		return nil, fmt.Errorf("scanning: set deadline: %w", err)
	}

	// The zINSTREAM\0 command prefix uses the null-terminated command format
	// (the 'z' prefix) which clamd requires for the streaming protocol.
	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return nil, fmt.Errorf("scanning: send INSTREAM command: %w", err)
	}

	if err := s.streamChunks(conn, r); err != nil {
		return nil, fmt.Errorf("scanning: stream file %q: %w", filePath, err)
	}

	response, err := s.readResponse(conn)
	if err != nil {
		return nil, fmt.Errorf("scanning: read clamd response: %w", err)
	}

	slog.Debug("clamav: scan response",
		"path", filePath,
		"response", response,
	)

	return parseResponse(response), nil
}

// streamChunks writes the file content to conn using the INSTREAM framing:
// each chunk is preceded by its 4-byte big-endian length, and a zero-length
// chunk signals end-of-stream.
func (s *ClamAVScanner) streamChunks(conn net.Conn, r io.Reader) error {
	buf := make([]byte, chunkSize)
	lenBuf := make([]byte, 4)

	for {
		n, readErr := r.Read(buf)
		if n > 0 {
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
			return fmt.Errorf("read source: %w", readErr)
		}
	}

	// Zero-length chunk terminates the stream.
	binary.BigEndian.PutUint32(lenBuf, 0)
	if _, err := conn.Write(lenBuf); err != nil {
		return fmt.Errorf("write stream terminator: %w", err)
	}

	return nil
}

// readResponse reads clamd's null-terminated response line.
// clamd always responds with a single null-terminated string for INSTREAM.
func (s *ClamAVScanner) readResponse(conn net.Conn) (string, error) {
	var sb strings.Builder
	oneByte := make([]byte, 1)

	for {
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
// Any other reply is inconclusive and reported as Unknown (fail closed).
// Historically the default branch reported Clean=true, which silently passed
// genuinely-failed scans (e.g. "INSTREAM size limit exceeded. ERROR") as safe.
func parseResponse(response string) *ScanResult {
	result := &ScanResult{RawResponse: response}

	switch {
	case strings.HasSuffix(response, "FOUND"):
		result.Infected = true
		// Extract virus name: response is "stream: <VirusName> FOUND"
		trimmed := strings.TrimPrefix(response, "stream: ")
		trimmed = strings.TrimSuffix(trimmed, " FOUND")
		result.VirusName = trimmed

	case strings.HasSuffix(response, " OK") || response == "OK":
		result.Clean = true

	default:
		// Unrecognised reply: fail closed. Do NOT mark clean.
		slog.Warn("clamav: unexpected response format, treating as inconclusive",
			"response", response,
		)
		result.Unknown = true
	}

	return result
}
