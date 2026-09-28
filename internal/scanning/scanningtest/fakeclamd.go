// Package scanningtest provides a fake clamd INSTREAM server for testing
// internal/scanning and any handler that scans uploads. It speaks just
// enough of the real clamd wire protocol (zINSTREAM\0 command, length-prefixed
// chunks, null-terminated reply) to exercise ClamAVScanner without a real
// ClamAV daemon.
package scanningtest

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"testing"
)

// EICARString is the standard EICAR antivirus test string. A scan whose
// input contains it is reported FOUND by Server in ModeNormal, mirroring
// real antivirus engines (this is the industry-standard harmless test
// signature, not real malware).
const EICARString = `X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`

// Mode selects how Server responds to a scan.
type Mode int

const (
	// ModeNormal replies FOUND when the streamed content contains
	// EICARString, otherwise OK — like a real, working clamd.
	ModeNormal Mode = iota
	// ModeError always replies with a clamd-style "... ERROR" line, as clamd
	// itself sends for a malformed stream or an internal failure.
	ModeError
	// ModeUnknown always replies with a line that doesn't match any known
	// clamd response format, simulating a protocol mismatch.
	ModeUnknown
	// ModeHang accepts the connection and reads the full stream but never
	// replies, simulating a wedged or overloaded clamd. The connection is
	// closed when the test cleans up the server.
	ModeHang
	// ModeCloseMidStream closes the connection as soon as the first chunk is
	// read, before the stream terminator or any reply — simulating clamd
	// crashing or the connection dropping mid-transfer.
	ModeCloseMidStream
)

// Server is a fake clamd INSTREAM listener bound to an ephemeral local port.
type Server struct {
	Host string
	Port int

	ln   net.Listener
	mode Mode
	stop chan struct{}
}

// New starts a fake clamd server in the given mode. The listener and any
// in-flight connections are closed automatically via t.Cleanup.
func New(t *testing.T, mode Mode) *Server {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("scanningtest: failed to listen: %v", err)
	}

	addr := ln.Addr().(*net.TCPAddr)
	s := &Server{
		Host: addr.IP.String(),
		Port: addr.Port,
		ln:   ln,
		mode: mode,
		stop: make(chan struct{}),
	}

	go s.serve()

	t.Cleanup(func() {
		close(s.stop)
		_ = ln.Close()
	})

	return s
}

func (s *Server) serve() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return // listener closed
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	// Read the zINSTREAM\0 command.
	cmd := make([]byte, len("zINSTREAM\x00"))
	if _, err := io.ReadFull(conn, cmd); err != nil {
		return
	}

	var received bytes.Buffer
	lenBuf := make([]byte, 4)
	first := true

	for {
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(lenBuf)
		if n == 0 {
			break // zero-length chunk: end of stream
		}

		if s.mode == ModeCloseMidStream && first {
			return // drop the connection without reading the chunk body
		}
		first = false

		chunk := make([]byte, n)
		if _, err := io.ReadFull(conn, chunk); err != nil {
			return
		}
		received.Write(chunk)
	}

	switch s.mode {
	case ModeHang:
		<-s.stop // block until the test tears the server down
		return
	case ModeError:
		s.reply(conn, "stream: some.file: Parse ERROR")
	case ModeUnknown:
		s.reply(conn, "this is not a clamd response")
	default: // ModeNormal
		if bytes.Contains(received.Bytes(), []byte(EICARString)) {
			s.reply(conn, "stream: Eicar-Test-Signature FOUND")
		} else {
			s.reply(conn, "stream: OK")
		}
	}
}

// reply writes a null-terminated clamd response line.
func (s *Server) reply(conn net.Conn, msg string) {
	_, _ = conn.Write(append([]byte(msg), 0x00))
}
