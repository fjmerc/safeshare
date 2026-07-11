package scanning

import (
	"os"
	"testing"
	"time"
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
		maxFileSize int64
	}{
		{
			name:        "default configuration",
			host:        "localhost",
			port:        3310,
			timeout:     30 * time.Second,
			maxFileSize: 25 * 1024 * 1024,
		},
		{
			name:        "custom host and port",
			host:        "clamav.internal",
			port:        9999,
			timeout:     10 * time.Second,
			maxFileSize: 100 * 1024 * 1024,
		},
		{
			name:        "zero maxFileSize disables size limit",
			host:        "127.0.0.1",
			port:        3310,
			timeout:     5 * time.Second,
			maxFileSize: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewClamAVScanner(tt.host, tt.port, tt.timeout, tt.maxFileSize)

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
	s := NewClamAVScanner("192.0.2.1", 3310, 1*time.Second, 1)

	result, err := s.ScanFile(f.Name())
	if err != nil {
		t.Fatalf("ScanFile() returned unexpected error: %v", err)
	}
	if result == nil {
		t.Fatal("ScanFile() returned nil result")
	}
	if !result.Clean {
		t.Errorf("Clean = false, want true for oversized file skip")
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
	s := NewClamAVScanner("localhost", 3310, 5*time.Second, 0)

	_, err := s.ScanFile("/does/not/exist/safeshare-test-file.bin")
	if err == nil {
		t.Error("ScanFile() expected error for missing file, got nil")
	}
}

// TestParseResponse covers all three clamd response variants.
func TestParseResponse(t *testing.T) {
	tests := []struct {
		name        string
		response    string
		wantClean   bool
		wantInf     bool
		wantUnknown bool
		wantVirus   string
	}{
		{
			name:      "clean response",
			response:  "stream: OK",
			wantClean: true,
		},
		{
			name:      "infected response",
			response:  "stream: Eicar-Test-Signature FOUND",
			wantInf:   true,
			wantVirus: "Eicar-Test-Signature",
		},
		{
			name:      "infected response with compound virus name",
			response:  "stream: Win.Trojan.Agent-12345 FOUND",
			wantInf:   true,
			wantVirus: "Win.Trojan.Agent-12345",
		},
		{
			name:        "clamd error reply fails closed (not clean)",
			response:    "stream: INSTREAM size limit exceeded. ERROR",
			wantUnknown: true,
		},
		{
			name:        "bare ERROR fails closed",
			response:    "stream: ERROR",
			wantUnknown: true,
		},
		{
			name:        "empty response fails closed",
			response:    "",
			wantUnknown: true,
		},
		{
			name:        "substring OK without boundary fails closed",
			response:    "stream: SOMETHINGOK",
			wantUnknown: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseResponse(tt.response)

			if result.Clean != tt.wantClean {
				t.Errorf("Clean = %v, want %v", result.Clean, tt.wantClean)
			}
			if result.Infected != tt.wantInf {
				t.Errorf("Infected = %v, want %v", result.Infected, tt.wantInf)
			}
			if result.Unknown != tt.wantUnknown {
				t.Errorf("Unknown = %v, want %v", result.Unknown, tt.wantUnknown)
			}
			if result.VirusName != tt.wantVirus {
				t.Errorf("VirusName = %q, want %q", result.VirusName, tt.wantVirus)
			}
		})
	}
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
	}

	for _, tt := range tests {
		if tt.constant != tt.want {
			t.Errorf("constant value = %q, want %q", tt.constant, tt.want)
		}
	}
}
