package scanning

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/scanning/scanningtest"
)

func TestScanResultStruct(t *testing.T) {
	tests := []struct {
		name      string
		result    ScanResult
		wantClean bool
		wantInf   bool
		wantVirus string
	}{
		{
			name:      "clean result",
			result:    ScanResult{Clean: true},
			wantClean: true,
			wantInf:   false,
			wantVirus: "",
		},
		{
			name:      "infected result",
			result:    ScanResult{Infected: true, VirusName: "Eicar-Test-Signature"},
			wantClean: false,
			wantInf:   true,
			wantVirus: "Eicar-Test-Signature",
		},
		{
			name:      "result with duration",
			result:    ScanResult{Clean: true, Duration: 42 * time.Millisecond},
			wantClean: true,
			wantInf:   false,
			wantVirus: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.result.Clean != tt.wantClean {
				t.Errorf("Clean = %v, want %v", tt.result.Clean, tt.wantClean)
			}
			if tt.result.Infected != tt.wantInf {
				t.Errorf("Infected = %v, want %v", tt.result.Infected, tt.wantInf)
			}
			if tt.result.VirusName != tt.wantVirus {
				t.Errorf("VirusName = %q, want %q", tt.result.VirusName, tt.wantVirus)
			}
		})
	}
}

func TestNewClamAVScanner(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		port        int
		timeout     time.Duration
		scanTimeout time.Duration
		maxFileSize int64
	}{
		{
			name:        "default configuration",
			host:        "localhost",
			port:        3310,
			timeout:     30 * time.Second,
			scanTimeout: 180 * time.Second,
			maxFileSize: 25 * 1024 * 1024,
		},
		{
			name:        "custom host and port",
			host:        "clamav.internal",
			port:        9999,
			timeout:     10 * time.Second,
			scanTimeout: 60 * time.Second,
			maxFileSize: 100 * 1024 * 1024,
		},
		{
			name:        "zero maxFileSize disables size limit",
			host:        "127.0.0.1",
			port:        3310,
			timeout:     5 * time.Second,
			scanTimeout: 5 * time.Second,
			maxFileSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewClamAVScanner(tt.host, tt.port, tt.timeout, tt.scanTimeout, tt.maxFileSize)

			if s == nil {
				t.Fatal("NewClamAVScanner() returned nil")
			}
			if s.host != tt.host {
				t.Errorf("host = %q, want %q", s.host, tt.host)
			}
			if s.port != tt.port {
				t.Errorf("port = %d, want %d", s.port, tt.port)
			}
			if s.timeout != tt.timeout {
				t.Errorf("timeout = %v, want %v", s.timeout, tt.timeout)
			}
			if s.scanTimeout != tt.scanTimeout {
				t.Errorf("scanTimeout = %v, want %v", s.scanTimeout, tt.scanTimeout)
			}
			if s.maxFileSize != tt.maxFileSize {
				t.Errorf("maxFileSize = %d, want %d", s.maxFileSize, tt.maxFileSize)
			}
		})
	}
}

// TestScanFile_OversizedFileSkipped verifies that files exceeding maxFileSize
// are not sent to clamd and are reported as clean without opening a connection.
func TestScanFile_OversizedFileSkipped(t *testing.T) {
	// Write a small temporary file; the scanner is configured with a maxFileSize
	// of 1 byte so any real file content will trigger the skip path.
	f, err := os.CreateTemp(t.TempDir(), "safeshare-scan-test-*.bin")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer f.Close()

	content := []byte("hello safeshare")
	if _, err := f.Write(content); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()

	// maxFileSize of 1 byte ensures the 15-byte file is always over the limit.
	// The host is deliberately set to an unreachable address so the test fails
	// loudly if the scanner incorrectly attempts a connection.
	s := NewClamAVScanner("192.0.2.1", 3310, 1*time.Second, 1*time.Second, 1)

	result, err := s.ScanFile(f.Name())
	if err != nil {
		t.Fatalf("ScanFile() returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("ScanFile() returned nil result")
	}
	// ADR-015: an oversized file is Skipped, never reported as Clean — a
	// caller that treated Skipped the same as Clean would silently let
	// oversized malware through.
	if !result.Skipped {
		t.Errorf("Skipped = false, want true for oversized file skip")
	}
	if result.Clean {
		t.Errorf("Clean = true, want false for oversized file skip")
	}
	if result.Infected {
		t.Errorf("Infected = true, want false for oversized file skip")
	}
	if result.VirusName != "" {
		t.Errorf("VirusName = %q, want empty for oversized file skip", result.VirusName)
	}
}

// TestScanFile_MissingFile verifies that a non-existent file path returns an
// error rather than a result.
func TestScanFile_MissingFile(t *testing.T) {
	s := NewClamAVScanner("localhost", 3310, 5*time.Second, 5*time.Second, 0)

	_, err := s.ScanFile("/does/not/exist/safeshare-test-file.bin")
	if err == nil {
		t.Error("ScanFile() expected error for missing file, got nil")
	}
}

// TestParseResponse covers the clean/infected/error clamd response variants.
//
// ADR-015 deviation from the pre-existing test: unrecognized and "... ERROR"
// responses used to default to Clean=true; they now return an error and no
// result, since a clamd protocol hiccup silently reporting "clean" is exactly
// the fail-open bug ADR-015 closes (finding 1c).
func TestParseResponse(t *testing.T) {
	t.Run("clean response", func(t *testing.T) {
		result, err := parseResponse("stream: OK")
		if err != nil {
			t.Fatalf("parseResponse() unexpected error: %v", err)
		}
		if !result.Clean || result.Infected {
			t.Errorf("got Clean=%v Infected=%v, want Clean=true Infected=false", result.Clean, result.Infected)
		}
	})

	t.Run("infected response", func(t *testing.T) {
		result, err := parseResponse("stream: Eicar-Test-Signature FOUND")
		if err != nil {
			t.Fatalf("parseResponse() unexpected error: %v", err)
		}
		if !result.Infected || result.VirusName != "Eicar-Test-Signature" {
			t.Errorf("got Infected=%v VirusName=%q, want Infected=true VirusName=%q", result.Infected, result.VirusName, "Eicar-Test-Signature")
		}
	})

	t.Run("infected response with compound virus name", func(t *testing.T) {
		result, err := parseResponse("stream: Win.Trojan.Agent-12345 FOUND")
		if err != nil {
			t.Fatalf("parseResponse() unexpected error: %v", err)
		}
		if !result.Infected || result.VirusName != "Win.Trojan.Agent-12345" {
			t.Errorf("got Infected=%v VirusName=%q, want Infected=true VirusName=%q", result.Infected, result.VirusName, "Win.Trojan.Agent-12345")
		}
	})

	t.Run("clamd ERROR response fails closed", func(t *testing.T) {
		if _, err := parseResponse("stream: some.file: Parse ERROR"); err == nil {
			t.Error("parseResponse() expected error for a clamd ERROR reply, got nil")
		}
	})

	t.Run("unrecognized response fails closed", func(t *testing.T) {
		if _, err := parseResponse("garbage"); err == nil {
			t.Error("parseResponse() expected error for an unrecognized reply, got nil")
		}
	})

	t.Run("empty response fails closed", func(t *testing.T) {
		if _, err := parseResponse(""); err == nil {
			t.Error("parseResponse() expected error for an empty reply, got nil")
		}
	})
}

// TestScanStatusConstants verifies the string values of scan status constants
// are stable, since they are persisted to the database.
func TestScanStatusConstants(t *testing.T) {
	tests := []struct {
		constant string
		want     string
	}{
		{ScanStatusPending, "pending"},
		{ScanStatusClean, "clean"},
		{ScanStatusInfected, "infected"},
		{ScanStatusError, "error"},
		{ScanStatusSkipped, "skipped"},
		{ScanStatusNotScanned, "not_scanned"},
	}

	for _, tt := range tests {
		if tt.constant != tt.want {
			t.Errorf("constant value = %q, want %q", tt.constant, tt.want)
		}
	}
}

// TestScanReader_EICARFound verifies a stream containing the EICAR test
// string is reported as infected against a fake clamd.
func TestScanReader_EICARFound(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeNormal)
	s := NewClamAVScanner(srv.Host, srv.Port, 5*time.Second, 5*time.Second, 0)

	content := scanningtest.EICARString
	result, err := s.ScanReader(context.Background(), strings.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("ScanReader() unexpected error: %v", err)
	}
	if !result.Infected || result.VirusName != "Eicar-Test-Signature" {
		t.Errorf("got Infected=%v VirusName=%q, want Infected=true VirusName=%q", result.Infected, result.VirusName, "Eicar-Test-Signature")
	}
}

// TestScanReader_Clean verifies a stream without the EICAR string is clean.
func TestScanReader_Clean(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeNormal)
	s := NewClamAVScanner(srv.Host, srv.Port, 5*time.Second, 5*time.Second, 0)

	content := "just an ordinary harmless file"
	result, err := s.ScanReader(context.Background(), strings.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("ScanReader() unexpected error: %v", err)
	}
	if !result.Clean || result.Infected {
		t.Errorf("got Clean=%v Infected=%v, want Clean=true Infected=false", result.Clean, result.Infected)
	}
}

// TestScanReader_UnknownResponseIsError verifies clamd replying with an
// unrecognized line surfaces as an error (ADR-015 fail-closed behaviour),
// not a clean result.
func TestScanReader_UnknownResponseIsError(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeUnknown)
	s := NewClamAVScanner(srv.Host, srv.Port, 5*time.Second, 5*time.Second, 0)

	content := "hello"
	_, err := s.ScanReader(context.Background(), strings.NewReader(content), int64(len(content)))
	if err == nil {
		t.Fatal("ScanReader() expected error for unrecognized clamd response, got nil")
	}
}

// TestScanReader_ClamdErrorIsError verifies a clamd "... ERROR" reply
// surfaces as an error rather than being silently treated as clean.
func TestScanReader_ClamdErrorIsError(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeError)
	s := NewClamAVScanner(srv.Host, srv.Port, 5*time.Second, 5*time.Second, 0)

	content := "hello"
	_, err := s.ScanReader(context.Background(), strings.NewReader(content), int64(len(content)))
	if err == nil {
		t.Fatal("ScanReader() expected error for clamd ERROR response, got nil")
	}
}

// TestScanReader_OversizedIsSkippedNotClean verifies size-limited content
// never reaches clamd and is reported Skipped, not Clean.
func TestScanReader_OversizedIsSkippedNotClean(t *testing.T) {
	// Unreachable host: the test fails loudly if the scanner tries to dial
	// despite the size limit being exceeded.
	s := NewClamAVScanner("192.0.2.1", 3310, 1*time.Second, 1*time.Second, 1)

	content := "more than one byte"
	result, err := s.ScanReader(context.Background(), strings.NewReader(content), int64(len(content)))
	if err != nil {
		t.Fatalf("ScanReader() unexpected error: %v", err)
	}
	if !result.Skipped || result.Clean {
		t.Errorf("got Skipped=%v Clean=%v, want Skipped=true Clean=false", result.Skipped, result.Clean)
	}
}

// TestScanReader_IdleTimeout verifies a clamd that accepts the stream but
// never replies (a wedged daemon) fails with an error once scanTimeout
// elapses, rather than hanging indefinitely. This exercises scanTimeout, not
// the idle timeout: the stream itself (tiny content) sends immediately, and
// the wedge happens entirely in the post-stream wait for a verdict.
func TestScanReader_IdleTimeout(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeHang)
	s := NewClamAVScanner(srv.Host, srv.Port, 5*time.Second, 200*time.Millisecond, 0)

	content := "hello"
	start := time.Now()
	_, err := s.ScanReader(context.Background(), strings.NewReader(content), int64(len(content)))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("ScanReader() expected error for scan timeout, got nil")
	}
	if elapsed > 5*time.Second {
		t.Errorf("ScanReader() took %v to time out, want well under 5s", elapsed)
	}
}

// TestScanReader_ContextCancellation verifies a cancelled context aborts an
// in-flight scan promptly instead of waiting for the idle timeout.
func TestScanReader_ContextCancellation(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeHang)
	s := NewClamAVScanner(srv.Host, srv.Port, 5*time.Second, 30*time.Second, 0)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	content := "hello"
	start := time.Now()
	_, err := s.ScanReader(ctx, strings.NewReader(content), int64(len(content)))
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("ScanReader() expected error for context cancellation, got nil")
	}
	if elapsed > 5*time.Second {
		t.Errorf("ScanReader() took %v after context cancellation, want well under 5s", elapsed)
	}
}

// TestScanReader_CloseMidStream verifies clamd dropping the connection
// mid-transfer surfaces as an error, and that the mid-stream failure path
// (which attempts a best-effort read of clamd's reply for logging) doesn't
// itself hang or panic when there is no reply to read.
func TestScanReader_CloseMidStream(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeCloseMidStream)
	s := NewClamAVScanner(srv.Host, srv.Port, 2*time.Second, 2*time.Second, 0)

	// Content larger than one chunk write so the first Write() has already
	// happened by the time the fake server closes the connection.
	content := strings.Repeat("a", 128*1024)
	_, err := s.ScanReader(context.Background(), strings.NewReader(content), int64(len(content)))
	if err == nil {
		t.Fatal("ScanReader() expected error when clamd closes mid-stream, got nil")
	}
}

// failAfterReader returns n bytes of data and then a permanent read error —
// simulating a local source failure (e.g. ADR-015's missing-chunk case)
// partway through a stream, as opposed to clamd closing the connection.
type failAfterReader struct {
	data []byte
	err  error
}

func (r *failAfterReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	return 0, r.err
}

// TestScanReader_LocalSourceFailure_DoesNotHang is a regression test for a
// bug found while testing the ADR-015 missing-chunk fail-fast fix: when
// streamChunks fails because reading the LOCAL source errored (clamd itself
// is healthy and simply never received a terminator), the mid-stream
// best-effort "read clamd's reply" used to block forever, since clamd has
// nothing to say and no deadline was set. It must now return promptly.
func TestScanReader_LocalSourceFailure_DoesNotHang(t *testing.T) {
	srv := scanningtest.New(t, scanningtest.ModeNormal)
	// A long timeout: if the fix regresses, this test would hang for the
	// full timeout instead of merely being slow, so keep it large relative
	// to the elapsed-time assertion below to make the failure mode obvious.
	s := NewClamAVScanner(srv.Host, srv.Port, 20*time.Second, 20*time.Second, 0)

	src := &failAfterReader{
		data: []byte("some data, then a permanent read error"),
		err:  errors.New("simulated local read failure (e.g. missing chunk file)"),
	}

	start := time.Now()
	_, err := s.ScanReader(context.Background(), src, 1024)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("ScanReader() expected error for a failing local source, got nil")
	}
	if elapsed > 3*time.Second {
		t.Errorf("ScanReader() took %v for a local source failure, want near-instant (no wait for a clamd reply that will never come)", elapsed)
	}
}
