package utils

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// This file holds the reader-agnostic SFSE decrypt entry points used by
// non-os.File-backed storage backends (S3, in-memory, etc.). The file-based
// dispatchers (DecryptFileStreamingV2 / DecryptFileStreamingRangeV2) and
// path-based dispatchers (DecryptFileStreamingAny / RangeAny) live in
// encryption.go; the chunk decrypt core (decryptSFSE2Core) is shared.
//
// Why a separate API: S3 returns io.ReadCloser, not *os.File. The file path
// can Stat() + Seek(), so it pre-positions the underlying reader before
// calling the core; the S3 path achieves the same effect by issuing a ranged
// GetObject whose Range header maps the requested plaintext slice to the
// covering ciphertext slice (see ComputeSFSE2CiphertextRange).
//
// V1 (no AAD) and V2 (per-chunk AAD) are both supported. Use
// DecryptSFSEFromReader to auto-dispatch on the version byte; use the V2-
// specific entry points when the caller already knows the format and wants
// to skip a small initial peek.

// DecryptSFSEFromReader streams the full decrypted plaintext of an SFSE blob
// from r to w. r must be positioned at the start of the SFSE magic header.
// The function reads the version byte, dispatches to the V1 or V2 reader,
// and runs the full-file decrypt to EOF.
//
// V2-only parameters (encFileID, expectedSHA256Hex, expectedPlaintextLen) are
// ignored when the blob is V1. encryptedSize, when >= 0, lets the V2 reader
// fail fast on size mismatches (use HeadObject.ContentLength or equivalent);
// pass -1 to skip.
//
// Use this from non-os.File backends. For file-backed callers, prefer
// DecryptFileStreamingAny (path-based) so the V2 path can also do its
// stat-based file-size sanity check.
func DecryptSFSEFromReader(r io.Reader, w io.Writer, keyHex string, encFileID []byte, expectedSHA256Hex string, expectedPlaintextLen, encryptedSize int64) (int64, error) {
	var hdr [6]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, fmt.Errorf("failed to peek SFSE header: %w", err)
	}
	if string(hdr[:5]) != StreamEncryptionMagic {
		return 0, fmt.Errorf("invalid SFSE magic")
	}
	switch hdr[5] {
	case StreamEncryptionVersion:
		// V1: re-prepend the magic+version bytes we already consumed so the
		// V1 reader sees a complete header from byte 0. V1 has no header
		// trailer, no AAD, and no integrity plumbing to honor.
		full := io.MultiReader(prependReader(hdr[:6]), r)
		written, err := decryptSFSE1FullFromReader(full, w, keyHex)
		return written, err
	case StreamEncryptionVersionV2:
		// V2: parse the remaining 12 bytes of the header (chunk_size +
		// total_plaintext_len) and dispatch to the reader-based decrypt.
		return decryptSFSE2FullFromReaderPostMagic(r, w, keyHex, encFileID, expectedSHA256Hex, expectedPlaintextLen, encryptedSize)
	default:
		return 0, fmt.Errorf("%w: %d", ErrUnsupportedSFSEVersion, hdr[5])
	}
}

// DecryptSFSE2FromReader streams the full decrypted plaintext of an SFSE2
// blob from r to w. r must be positioned at the start of the SFSE2 magic
// header. The 18-byte header is parsed from r itself.
//
// encryptedSize, when >= 0, is verified against the size implied by the
// header (typically supplied via HeadObject.ContentLength for S3). Pass -1
// to skip the check; the per-chunk AAD still catches all tampering classes
// SFSE2 is designed to defeat, but a header-size cross-check catches blunt
// truncation faster.
//
// expectedSHA256Hex / expectedPlaintextLen behave as for the file-based
// DecryptFileStreamingV2: pass file.SHA256Hash and file.Size when invoking
// from production; pass "" / -1 from admin tools without DB context.
func DecryptSFSE2FromReader(r io.Reader, w io.Writer, keyHex string, encFileID []byte, expectedSHA256Hex string, expectedPlaintextLen, encryptedSize int64) (int64, error) {
	if len(encFileID) != SFSE2EncFileIDSize {
		return 0, fmt.Errorf("enc_file_id must be %d bytes, got %d", SFSE2EncFileIDSize, len(encFileID))
	}
	gcm, err := newGCMFromKeyHex(keyHex)
	if err != nil {
		return 0, err
	}
	chunkSize, totalPlaintextLen, err := readSFSE2Header(r)
	if err != nil {
		return 0, err
	}
	if expectedPlaintextLen >= 0 && totalPlaintextLen != expectedPlaintextLen {
		return 0, fmt.Errorf("%w: header total_plaintext_len=%d, caller expected=%d", ErrSFSE2IntegrityCheckFailed, totalPlaintextLen, expectedPlaintextLen)
	}
	p, empty, err := newSFSE2RangeParams(encFileID, chunkSize, totalPlaintextLen, 0, -1, expectedSHA256Hex, gcm)
	if err != nil {
		return 0, err
	}
	if empty {
		return 0, nil
	}
	if encryptedSize >= 0 && encryptedSize != p.expectedCiphertextSize {
		return 0, fmt.Errorf("%w: ciphertext size %d, header expects %d", ErrSFSE2IntegrityCheckFailed, encryptedSize, p.expectedCiphertextSize)
	}
	return decryptSFSE2Core(r, w, gcm, p)
}

// DecryptSFSE2RangeFromReader streams a plaintext byte range from a reader
// that has been pre-positioned at the start of the ciphertext for startChunk
// (i.e., at the byte offset returned in ctStart by ComputeSFSE2CiphertextRange).
//
// The caller is responsible for: (a) fetching the 18-byte SFSE2 header
// separately (e.g., S3 GetObject Range=bytes=0-17) and parsing chunkSize +
// totalPlaintextLen from it, (b) computing the covering ciphertext range via
// ComputeSFSE2CiphertextRange, and (c) issuing a second ranged fetch of that
// ciphertext range from the backing storage, passing the body here as r.
//
// startByte / endByte are inclusive plaintext-byte offsets. endByte < 0 is
// rejected — for a full read, call DecryptSFSE2FromReader.
//
// expectedSHA256Hex is honored only when (startByte=0 && endByte=totalPlaintextLen-1)
// — otherwise the running hash cannot reasonably be verified against a
// whole-file digest.
func DecryptSFSE2RangeFromReader(r io.Reader, w io.Writer, keyHex string, encFileID []byte, expectedSHA256Hex string, chunkSize, totalPlaintextLen, startByte, endByte int64) (int64, error) {
	if len(encFileID) != SFSE2EncFileIDSize {
		return 0, fmt.Errorf("enc_file_id must be %d bytes, got %d", SFSE2EncFileIDSize, len(encFileID))
	}
	if chunkSize <= 0 {
		return 0, fmt.Errorf("chunk_size must be > 0, got %d", chunkSize)
	}
	if totalPlaintextLen < 0 {
		return 0, fmt.Errorf("total_plaintext_len must be >= 0, got %d", totalPlaintextLen)
	}
	if startByte < 0 || endByte < 0 || endByte < startByte {
		return 0, fmt.Errorf("invalid range: start=%d, end=%d", startByte, endByte)
	}
	gcm, err := newGCMFromKeyHex(keyHex)
	if err != nil {
		return 0, err
	}
	p, empty, err := newSFSE2RangeParams(encFileID, chunkSize, totalPlaintextLen, startByte, endByte, expectedSHA256Hex, gcm)
	if err != nil {
		return 0, err
	}
	if empty {
		return 0, nil
	}
	return decryptSFSE2Core(r, w, gcm, p)
}

// ComputeSFSE2CiphertextRange maps a plaintext byte range to the inclusive
// ciphertext byte range that must be fetched from the backing storage to
// satisfy the request. Result byte offsets are absolute (include the SFSE2
// header offset) so callers can pass them directly to e.g. an HTTP
// Range: bytes=ctStart-ctEnd header.
//
// plaintextEnd is clamped to totalPlaintextLen-1; out-of-range plaintextStart
// returns an error.
//
// Empty-file (totalPlaintextLen=0) callers get ctStart == ctEnd-1 (an empty
// range) — they should short-circuit before issuing the fetch.
//
// chunkSize is the per-file value from the SFSE2 header (currently always
// DefaultChunkSize=10MB in practice, but parsed per-file).
func ComputeSFSE2CiphertextRange(plaintextStart, plaintextEnd, chunkSize, totalPlaintextLen int64) (ctStart, ctEnd int64, err error) {
	if chunkSize <= 0 {
		return 0, 0, fmt.Errorf("chunk_size must be > 0, got %d", chunkSize)
	}
	if totalPlaintextLen < 0 {
		return 0, 0, fmt.Errorf("total_plaintext_len must be >= 0, got %d", totalPlaintextLen)
	}
	if plaintextStart < 0 || plaintextEnd < plaintextStart {
		return 0, 0, fmt.Errorf("invalid plaintext range [%d, %d]", plaintextStart, plaintextEnd)
	}
	if totalPlaintextLen == 0 {
		// Empty file: caller should not be issuing a Range fetch; signal an
		// empty range. SFSE2HeaderSize-1 < SFSE2HeaderSize so this is an
		// invalid HTTP range, which is correct behavior.
		return int64(SFSE2HeaderSize), int64(SFSE2HeaderSize) - 1, nil
	}
	if plaintextStart >= totalPlaintextLen {
		return 0, 0, fmt.Errorf("plaintext start %d beyond total %d", plaintextStart, totalPlaintextLen)
	}
	if plaintextEnd >= totalPlaintextLen {
		plaintextEnd = totalPlaintextLen - 1
	}

	startChunk := plaintextStart / chunkSize
	endChunk := plaintextEnd / chunkSize
	totalChunks := chunkCountFromPlaintextLen(totalPlaintextLen, chunkSize)
	finalChunkPlainBytes := totalPlaintextLen - (totalChunks-1)*chunkSize

	encChunkSize := chunkSize + int64(SFSE2OverheadPerChunk)
	ctStart = int64(SFSE2HeaderSize) + startChunk*encChunkSize

	if endChunk == totalChunks-1 {
		// Last chunk's ciphertext is shorter than a full encChunkSize.
		ctEnd = int64(SFSE2HeaderSize) + (totalChunks-1)*encChunkSize + finalChunkPlainBytes + int64(SFSE2OverheadPerChunk) - 1
	} else {
		ctEnd = int64(SFSE2HeaderSize) + (endChunk+1)*encChunkSize - 1
	}
	return ctStart, ctEnd, nil
}

// prependReader returns an io.Reader that yields the supplied bytes once,
// then returns io.EOF. Used by DecryptSFSEFromReader to re-prepend the
// version-peek bytes when dispatching to a V1 reader that expects to read
// the header from byte 0.
func prependReader(p []byte) io.Reader {
	b := make([]byte, len(p))
	copy(b, p)
	return &sliceReader{buf: b}
}

type sliceReader struct {
	buf []byte
	off int
}

func (s *sliceReader) Read(p []byte) (int, error) {
	if s.off >= len(s.buf) {
		return 0, io.EOF
	}
	n := copy(p, s.buf[s.off:])
	s.off += n
	return n, nil
}

// DecryptSFSE1RangeFromReader runs a V1 (no-AAD) Range decrypt from a reader
// pre-positioned at the start of startChunk's ciphertext. Caller is
// responsible for: (a) parsing the V1 header separately and supplying its
// chunkSize, (b) issuing the ranged fetch from the backing storage.
//
// startByte / endByte are inclusive plaintext-byte offsets. V1 has no AAD
// and no length trailer; per-chunk GCM tag validation is the only
// integrity check.
//
// Returns the number of bytes written to w.
func DecryptSFSE1RangeFromReader(r io.Reader, w io.Writer, keyHex string, chunkSize, startByte, endByte int64) (int64, error) {
	if startByte < 0 || endByte < startByte {
		return 0, fmt.Errorf("invalid range: start=%d, end=%d", startByte, endByte)
	}
	if chunkSize <= 0 {
		return 0, fmt.Errorf("chunk_size must be > 0, got %d", chunkSize)
	}
	gcm, err := newGCMFromKeyHex(keyHex)
	if err != nil {
		return 0, err
	}
	startChunk := startByte / chunkSize
	endChunk := endByte / chunkSize
	offsetInFirstChunk := startByte % chunkSize
	encChunkSize := int(chunkSize) + gcm.NonceSize() + gcm.Overhead()
	buffer := make([]byte, encChunkSize)
	var totalWritten int64

	// V1 range loop — mirrors the canonical loop in DecryptFileStreamingRange.
	// Keep io.ReadFull semantics in sync (SH-1.2). ErrUnexpectedEOF is the
	// legitimate short final chunk; EOF is clean termination.
	for currentChunk := startChunk; currentChunk <= endChunk; currentChunk++ {
		n, readErr := io.ReadFull(r, buffer)
		if readErr == io.EOF {
			break
		}
		if readErr != nil && readErr != io.ErrUnexpectedEOF {
			return totalWritten, fmt.Errorf("failed to read encrypted chunk %d: %w", currentChunk, readErr)
		}
		if n == 0 {
			break
		}
		if n < gcm.NonceSize() {
			return totalWritten, fmt.Errorf("chunk too small: %d bytes", n)
		}
		nonce := buffer[:gcm.NonceSize()]
		ciphertext := buffer[gcm.NonceSize():n]
		plaintext, decErr := gcm.Open(nil, nonce, ciphertext, nil)
		if decErr != nil {
			return totalWritten, fmt.Errorf("failed to decrypt chunk %d: %w", currentChunk, decErr)
		}

		var chunkStart, chunkEnd int64
		if currentChunk == startChunk {
			chunkStart = offsetInFirstChunk
		}
		if currentChunk == endChunk {
			chunkEnd = (endByte % chunkSize) + 1
			if chunkEnd > int64(len(plaintext)) {
				chunkEnd = int64(len(plaintext))
			}
		} else {
			chunkEnd = int64(len(plaintext))
		}

		if chunkStart < chunkEnd {
			written, writeErr := w.Write(plaintext[chunkStart:chunkEnd])
			if writeErr != nil {
				return totalWritten, fmt.Errorf("failed to write decrypted data: %w", writeErr)
			}
			totalWritten += int64(written)
		}
		if readErr == io.ErrUnexpectedEOF {
			break
		}
	}
	return totalWritten, nil
}

// decryptSFSE1FullFromReader runs a V1 (no-AAD) full decrypt from a reader
// positioned at the start of an SFSE1 file. Returns the number of plaintext
// bytes written (so the V2 dispatcher can return a consistent (int64, error)).
// Internal helper for the DecryptSFSEFromReader dispatcher.
func decryptSFSE1FullFromReader(r io.Reader, w io.Writer, keyHex string) (int64, error) {
	gcm, err := newGCMFromKeyHex(keyHex)
	if err != nil {
		return 0, err
	}
	// Header: magic(5) + version(1) + chunk_size(4 LE). Magic+version
	// already consumed and re-prepended by caller via prependReader, so we
	// read the full 10-byte header from r.
	var hdr [SFSE1HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, fmt.Errorf("failed to read SFSE1 header: %w", err)
	}
	if string(hdr[:5]) != StreamEncryptionMagic {
		return 0, fmt.Errorf("invalid SFSE1 magic")
	}
	if hdr[5] != StreamEncryptionVersion {
		return 0, fmt.Errorf("unexpected SFSE version in V1 reader: %d", hdr[5])
	}
	chunkSize := int64(binary.LittleEndian.Uint32(hdr[6:10]))
	encryptedChunkSize := int(chunkSize) + gcm.NonceSize() + gcm.Overhead()
	cw := &countingWriter{w: w}
	if err := decryptChunkStream(r, cw, gcm, encryptedChunkSize); err != nil {
		return cw.n, err
	}
	return cw.n, nil
}

// countingWriter wraps an io.Writer and counts bytes successfully written.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// decryptSFSE2FullFromReaderPostMagic continues parsing an SFSE2 header from
// a reader whose first 6 bytes (magic + version) have already been consumed
// by the version-peek logic in DecryptSFSEFromReader. Reads the remaining
// 12 bytes (chunk_size + total_plaintext_len) and runs a full decrypt.
func decryptSFSE2FullFromReaderPostMagic(r io.Reader, w io.Writer, keyHex string, encFileID []byte, expectedSHA256Hex string, expectedPlaintextLen, encryptedSize int64) (int64, error) {
	if len(encFileID) != SFSE2EncFileIDSize {
		return 0, fmt.Errorf("enc_file_id must be %d bytes, got %d", SFSE2EncFileIDSize, len(encFileID))
	}
	gcm, err := newGCMFromKeyHex(keyHex)
	if err != nil {
		return 0, err
	}
	// Re-assemble the full SFSE2 header so readSFSE2Header can validate it as
	// a unit. The caller has already consumed 6 bytes (magic + version); we
	// prepend a synthetic copy so the parser sees a complete header.
	var trailer [SFSE2HeaderSize - 6]byte
	if _, err := io.ReadFull(r, trailer[:]); err != nil {
		return 0, fmt.Errorf("failed to read SFSE2 header trailer: %w", err)
	}
	var reconstructed [SFSE2HeaderSize]byte
	copy(reconstructed[:5], StreamEncryptionMagic)
	reconstructed[5] = StreamEncryptionVersionV2
	copy(reconstructed[6:], trailer[:])
	chunkSize, totalPlaintextLen, err := readSFSE2Header(bytes.NewReader(reconstructed[:]))
	if err != nil {
		return 0, err
	}
	if expectedPlaintextLen >= 0 && totalPlaintextLen != expectedPlaintextLen {
		return 0, fmt.Errorf("%w: header total_plaintext_len=%d, caller expected=%d", ErrSFSE2IntegrityCheckFailed, totalPlaintextLen, expectedPlaintextLen)
	}
	p, empty, err := newSFSE2RangeParams(encFileID, chunkSize, totalPlaintextLen, 0, -1, expectedSHA256Hex, gcm)
	if err != nil {
		return 0, err
	}
	if empty {
		return 0, nil
	}
	if encryptedSize >= 0 && encryptedSize != p.expectedCiphertextSize {
		return 0, fmt.Errorf("%w: ciphertext size %d, header expects %d", ErrSFSE2IntegrityCheckFailed, encryptedSize, p.expectedCiphertextSize)
	}
	return decryptSFSE2Core(r, w, gcm, p)
}


