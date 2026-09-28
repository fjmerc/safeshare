package utils

import (
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"sync"
)

// MaxSFSEChunkSize is the largest chunk_size an SFSE header may declare.
// Old SFSE1 files used 64MB chunks; DefaultChunkSize (10MB) is used for
// everything encrypted since. Anything larger is refused at open time —
// it cannot be a value this codebase ever wrote, so it is either
// corruption or a forged header.
const MaxSFSEChunkSize = 64 * 1024 * 1024

// maxSFSEPlainLen bounds the plaintext length OpenSFSEReader and
// ClassifyStoredFile will accept. 1<<50 (1 PiB) is already absurd for a
// single file on this codebase's storage backends; the real purpose of the
// bound is to keep the totalChunks * encChunkSize and similar int64
// multiplications elsewhere in this file (and in classify.go) comfortably
// clear of overflow for any input, including a maliciously forged DB row or
// header field, without needing checked/big-int arithmetic on every hot
// path.
const maxSFSEPlainLen = 1 << 50

// sfseChunkBufPool holds reusable [DefaultChunkSize+overhead]byte buffers for
// SFSEReader instances opened against DefaultChunkSize-chunked files (the
// overwhelming majority — every file encrypted since the 10MB default was
// introduced). Files with a non-default chunk_size (old 64MB SFSE1 files)
// allocate their own buffer directly rather than distorting the pool's
// buffer size.
var sfseChunkBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, DefaultChunkSize+SFSE2OverheadPerChunk)
		return &b
	},
}

func getSFSEChunkBuffer(chunkSize int64) (buf []byte, pooled bool) {
	size := chunkSize + SFSE2OverheadPerChunk
	if chunkSize == DefaultChunkSize {
		bp := sfseChunkBufPool.Get().(*[]byte)
		if int64(len(*bp)) != size {
			// Defensive: should be unreachable since the pool only ever
			// stores DefaultChunkSize+overhead buffers.
			*bp = make([]byte, size)
		}
		return *bp, true
	}
	return make([]byte, size), false
}

func putSFSEChunkBuffer(buf []byte, pooled bool) {
	if buf == nil {
		return
	}
	// Wipe decrypted plaintext before the buffer is reused or dropped, so a
	// file's contents don't linger in memory for the next unrelated stream.
	clear(buf)
	if !pooled {
		return
	}
	sfseChunkBufPool.Put(&buf)
}

// errSFSEReaderClosed is returned by Read, Seek and Prime after Close.
var errSFSEReaderClosed = errors.New("SFSEReader: use after Close")

// SFSEReader is a seekable, decrypting io.ReadSeeker over an SFSE1 or SFSE2
// encrypted file. It is built for http.ServeContent: Seek only moves a
// logical position (no I/O), and Read decrypts on demand via os.File.ReadAt
// against a single reused chunk buffer — one buffer for the lifetime of the
// stream, not one per Read (T34).
//
// Whole-file SHA-256 verification (when the caller supplies a non-empty
// sha256Hex) only engages for a strictly sequential, from-offset-0 read
// pattern: the moment a chunk is decrypted out of order (a Seek jumped
// ahead, or the stream started mid-file), verification is permanently
// disabled for the rest of the stream. A Range read therefore relies on
// per-chunk AEAD authentication plus the open-time ciphertext-size check,
// exactly like the existing DecryptFileStreamingRangeV2 path — it cannot
// detect trailing-chunk truncation that the requested range never reaches.
type SFSEReader struct {
	f       *os.File
	gcm     cipher.AEAD
	version byte

	chunkSize            int64
	headerSize           int64
	totalPlaintextLen    int64
	totalChunks          int64
	finalChunkPlainBytes int64
	encChunkSize         int64 // chunkSize + nonce+tag overhead
	encFileID            []byte

	buf    []byte
	pooled bool

	pos int64

	curChunkIdx int64 // -1 = nothing decrypted yet
	closed      bool  // set by Close; further Read/Seek/Prime fail
	curPlain    []byte

	hashActive        bool
	hashChunkNext     int64
	hasher            hash.Hash
	expectedSHA256Hex string

	err error
}

// OpenSFSEReader validates an SFSE1 or SFSE2 header against f/fi and, on
// success, returns a ready-to-use *SFSEReader. All structural validation
// (magic, version, chunk_size bounds, enc_file_id length, and — critically —
// that the on-disk size matches exactly what the header implies) happens
// here, before the caller writes any response headers. This rejects
// truncation and appended-data tampering that per-chunk AEAD alone would
// only catch once the affected chunk is actually read.
//
// f must already be open for reading; OpenSFSEReader never closes it — that
// remains the caller's responsibility. fi is f's os.FileInfo (passed in so
// callers that already stat'd the file don't pay for it twice).
//
// plainLen is the plaintext length the caller expects (typically
// files.file_size from the DB). For SFSE1 it is trusted as-is (V1 has no
// length field in its header). For SFSE2 it is checked against the header's
// total_plaintext_len; a mismatch is a header-forgery / zero-byte-collapse
// attempt and returns ErrSFSE2IntegrityCheckFailed (see decryptSFSE2Stream's
// identical check).
//
// encFileID is required (exactly SFSE2EncFileIDSize bytes) for SFSE2 files
// and ignored for SFSE1 (which has no per-chunk AAD).
//
// sha256Hex, when non-empty, enables whole-file digest verification — see
// the SFSEReader doc comment for when it actually fires.
func OpenSFSEReader(f *os.File, fi os.FileInfo, keyHex string, encFileID []byte, plainLen int64, sha256Hex string) (*SFSEReader, error) {
	if plainLen < 0 || plainLen > maxSFSEPlainLen {
		return nil, fmt.Errorf("SFSEReader: plainLen %d out of range [0, %d]", plainLen, maxSFSEPlainLen)
	}

	gcm, err := newGCMFromKeyHex(keyHex)
	if err != nil {
		return nil, err
	}

	// The first 10 bytes (magic+version+chunk_size) are common to both
	// versions; SFSE2 extends with an 8-byte total_plaintext_len trailer.
	var hdr [SFSE1HeaderSize]byte
	n, err := f.ReadAt(hdr[:], 0)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("SFSEReader: failed to read header: %w", err)
	}
	if n < SFSE1HeaderSize {
		return nil, fmt.Errorf("SFSEReader: header truncated (%d bytes)", n)
	}
	if string(hdr[0:5]) != StreamEncryptionMagic {
		return nil, fmt.Errorf("SFSEReader: invalid magic header")
	}
	version := hdr[5]
	if version != StreamEncryptionVersion && version != StreamEncryptionVersionV2 {
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedSFSEVersion, version)
	}

	chunkSize := int64(binary.LittleEndian.Uint32(hdr[6:10]))
	if chunkSize <= 0 || chunkSize > MaxSFSEChunkSize {
		return nil, fmt.Errorf("SFSEReader: chunk_size %d out of range (0, %d]", chunkSize, MaxSFSEChunkSize)
	}

	headerSize := int64(SFSE1HeaderSize)
	totalPlaintextLen := plainLen

	if version == StreamEncryptionVersionV2 {
		if len(encFileID) != SFSE2EncFileIDSize {
			return nil, fmt.Errorf("SFSEReader: enc_file_id must be %d bytes, got %d", SFSE2EncFileIDSize, len(encFileID))
		}
		var tail [8]byte
		tn, err := f.ReadAt(tail[:], SFSE1HeaderSize)
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("SFSEReader: failed to read SFSE2 trailer: %w", err)
		}
		if tn < 8 {
			return nil, fmt.Errorf("SFSEReader: SFSE2 header truncated")
		}
		headerPlainLen := int64(binary.BigEndian.Uint64(tail[:]))
		if headerPlainLen < 0 {
			return nil, fmt.Errorf("SFSEReader: invalid total_plaintext_len %d", headerPlainLen)
		}
		if headerPlainLen != plainLen {
			return nil, fmt.Errorf("%w: header total_plaintext_len=%d, expected=%d", ErrSFSE2IntegrityCheckFailed, headerPlainLen, plainLen)
		}
		headerSize = SFSE2HeaderSize
	}

	totalChunks := chunkCountFromPlaintextLen(totalPlaintextLen, chunkSize)
	var finalChunkPlainBytes int64
	if totalChunks > 0 {
		finalChunkPlainBytes = totalPlaintextLen - (totalChunks-1)*chunkSize
	}
	encChunkSize := chunkSize + SFSE2OverheadPerChunk

	expectedCiphertextSize := headerSize
	if totalChunks > 0 {
		expectedCiphertextSize += (totalChunks-1)*encChunkSize + finalChunkPlainBytes + SFSE2OverheadPerChunk
	}
	if fi.Size() != expectedCiphertextSize {
		return nil, fmt.Errorf("%w: on-disk size %d, expected %d", ErrSFSE2IntegrityCheckFailed, fi.Size(), expectedCiphertextSize)
	}

	buf, pooled := getSFSEChunkBuffer(chunkSize)

	r := &SFSEReader{
		f:                    f,
		gcm:                  gcm,
		version:              version,
		chunkSize:            chunkSize,
		headerSize:           headerSize,
		totalPlaintextLen:    totalPlaintextLen,
		totalChunks:          totalChunks,
		finalChunkPlainBytes: finalChunkPlainBytes,
		encChunkSize:         encChunkSize,
		buf:                  buf,
		pooled:               pooled,
		curChunkIdx:          -1,
		expectedSHA256Hex:    sha256Hex,
	}
	if version == StreamEncryptionVersionV2 {
		r.encFileID = encFileID
	}
	if sha256Hex != "" && totalPlaintextLen > 0 {
		r.hashActive = true
		r.hasher = sha256.New()
	}
	return r, nil
}

// loadChunk decrypts chunk chunkIdx into r.buf (in place) if it isn't
// already the cached chunk. On success r.curChunkIdx/r.curPlain point at the
// decrypted plaintext. On failure r.err is set (sticky) and returned.
func (r *SFSEReader) loadChunk(chunkIdx int64) error {
	if r.err != nil {
		return r.err
	}
	if chunkIdx == r.curChunkIdx {
		return nil
	}

	isLast := chunkIdx == r.totalChunks-1
	expectedReadSize := r.encChunkSize
	if isLast {
		expectedReadSize = r.finalChunkPlainBytes + SFSE2OverheadPerChunk
	}

	offset := r.headerSize + chunkIdx*r.encChunkSize
	window := r.buf[:expectedReadSize]
	n, err := r.f.ReadAt(window, offset)
	if err != nil && err != io.EOF {
		r.err = fmt.Errorf("SFSEReader: read chunk %d: %w", chunkIdx, err)
		return r.err
	}
	if int64(n) != expectedReadSize {
		r.err = fmt.Errorf("%w: chunk %d read %d bytes, expected %d", ErrSFSEShortRead, chunkIdx, n, expectedReadSize)
		return r.err
	}

	var aad []byte
	if r.version == StreamEncryptionVersionV2 {
		aad, err = buildSFSE2AAD(r.encFileID, uint64(chunkIdx), isLast)
		if err != nil {
			r.err = err
			return r.err
		}
	}

	nonce := window[:SFSE2NonceSize]
	ciphertext := window[SFSE2NonceSize:n]
	// Decrypt in place: dst and src share the same backing array (ct[:0]),
	// so this stream uses exactly one chunk-sized buffer for its whole
	// lifetime instead of one allocation per chunk read (T34).
	plaintext, decErr := r.gcm.Open(ciphertext[:0], nonce, ciphertext, aad)
	if decErr != nil {
		// Wrapped in ErrSFSEChunkAuthFailed, which itself wraps the
		// umbrella ErrSFSE2IntegrityCheckFailed (round-3 security-audit
		// finding, refined in round 4): an AEAD auth-tag failure means the
		// chunk was tampered with or corrupted — distinct from a short
		// read (ErrSFSEShortRead) or a whole-file hash mismatch
		// (ErrSFSEHashMismatch), which wrap the same umbrella but are
		// their own sentinels so a caller that cares (cmd/migrate-encryption
		// --verify) can tell them apart, while claim_range.go's coarser
		// errors.Is(err, ErrSFSE2IntegrityCheckFailed) check (only "was
		// this an integrity problem at all, vs. a plain I/O error") still
		// works unchanged against any of the three.
		r.err = fmt.Errorf("SFSEReader: decrypt chunk %d: %w: %w", chunkIdx, ErrSFSEChunkAuthFailed, decErr)
		return r.err
	}

	if r.hashActive {
		if chunkIdx != r.hashChunkNext {
			// Non-contiguous chunk access (a Seek skipped ahead, or the
			// stream never started at offset 0) — whole-file verification
			// is no longer meaningful; give up on it for the rest of the
			// stream. Per-chunk AEAD keeps authenticating regardless.
			r.hashActive = false
		} else {
			r.hasher.Write(plaintext)
			r.hashChunkNext++
			if isLast {
				sum := hex.EncodeToString(r.hasher.Sum(nil))
				if sum != r.expectedSHA256Hex {
					r.err = fmt.Errorf("%w: SHA-256 mismatch", ErrSFSEHashMismatch)
					return r.err
				}
			}
		}
	}

	r.curChunkIdx = chunkIdx
	r.curPlain = plaintext
	return nil
}

// Read implements io.Reader. It decrypts chunks on demand (cache size 1)
// and never buffers more than the current chunk's plaintext.
func (r *SFSEReader) Read(p []byte) (int, error) {
	if r.closed {
		return 0, errSFSEReaderClosed
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.pos >= r.totalPlaintextLen {
		return 0, io.EOF
	}
	if len(p) == 0 {
		return 0, nil
	}

	chunkIdx := r.pos / r.chunkSize
	if err := r.loadChunk(chunkIdx); err != nil {
		return 0, err
	}

	offsetInChunk := r.pos % r.chunkSize
	n := copy(p, r.curPlain[offsetInChunk:])
	r.pos += int64(n)
	return n, nil
}

// Seek implements io.Seeker. It only moves the logical read position — no
// I/O and no decryption happen here, matching how http.ServeContent probes
// size (Seek to end) before seeking back to the serving position.
func (r *SFSEReader) Seek(offset int64, whence int) (int64, error) {
	if r.closed {
		return 0, errSFSEReaderClosed
	}
	if r.err != nil {
		return 0, r.err
	}
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = r.pos + offset
	case io.SeekEnd:
		newPos = r.totalPlaintextLen + offset
	default:
		return 0, fmt.Errorf("SFSEReader: invalid whence %d", whence)
	}
	if newPos < 0 {
		return 0, fmt.Errorf("SFSEReader: negative resulting position %d", newPos)
	}
	r.pos = newPos
	return newPos, nil
}

// Prime eagerly decrypts the chunk containing plaintext offset off, without
// moving the read position. Callers use this to surface a wrong key or a
// corrupt/truncated first chunk as an error before committing to writing
// response headers. off == the reader's total plaintext length is a no-op
// (nothing to decrypt at EOF).
func (r *SFSEReader) Prime(off int64) error {
	if r.closed {
		return errSFSEReaderClosed
	}
	if r.err != nil {
		return r.err
	}
	if off < 0 || off > r.totalPlaintextLen {
		return fmt.Errorf("SFSEReader: prime offset %d out of range [0,%d]", off, r.totalPlaintextLen)
	}
	if r.totalPlaintextLen == 0 || off == r.totalPlaintextLen {
		return nil
	}
	return r.loadChunk(off / r.chunkSize)
}

// Err returns the sticky error that caused the stream to fail, if any.
func (r *SFSEReader) Err() error {
	return r.err
}

// Close wipes and releases the reader's chunk buffer. It is idempotent, and
// later Read/Seek/Prime calls return an error instead of touching the
// released buffer. Err still reports any integrity failure seen before
// Close. It does NOT close the underlying *os.File passed to
// OpenSFSEReader — the caller owns that file's lifecycle.
func (r *SFSEReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	putSFSEChunkBuffer(r.buf, r.pooled)
	r.buf = nil
	r.curPlain = nil
	r.curChunkIdx = -1
	return nil
}
