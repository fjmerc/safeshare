package utils

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

// StoredFormat identifies how a file's bytes are laid out on disk, as
// distinguished by ClassifyStoredFile.
type StoredFormat int

const (
	// FormatUnknown is the zero value, returned alongside an error.
	FormatUnknown StoredFormat = iota
	// FormatPlaintext means the stored bytes are the original file
	// content, unencrypted (on-disk size == DB file_size).
	FormatPlaintext
	// FormatSFSE1 means the file is SFSE1-encrypted (magic header, no
	// per-chunk AAD, no length trailer).
	FormatSFSE1
	// FormatSFSE2 means the file is SFSE2-encrypted (magic header,
	// per-chunk AAD, total_plaintext_len trailer).
	FormatSFSE2
	// FormatLegacy means the file is single-shot AES-256-GCM encrypted
	// (no magic header): [nonce(12)][ciphertext][tag(16)].
	FormatLegacy
)

// String returns a short lowercase name for f, used in log lines and the
// migrate-encryption --verify report.
func (f StoredFormat) String() string {
	switch f {
	case FormatPlaintext:
		return "plaintext"
	case FormatSFSE1:
		return "sfse1"
	case FormatSFSE2:
		return "sfse2"
	case FormatLegacy:
		return "legacy"
	default:
		return "unknown"
	}
}

// ErrEncryptionKeyMissing is returned by ClassifyStoredFile when the stored
// file's shape requires a key to decrypt (SFSE1/SFSE2/legacy) but the
// server has none configured.
var ErrEncryptionKeyMissing = errors.New("stored file requires an encryption key but none is configured")

// ErrStoredSizeMismatch is returned by ClassifyStoredFile when the on-disk
// size does not match the DB-recorded size, and does not match any
// recognized encrypted-format size either — i.e. the file is neither a
// plaintext match, a structurally valid SFSE1/SFSE2 ciphertext for that
// plaintext length, nor a legacy-format ciphertext.
var ErrStoredSizeMismatch = errors.New("stored file size does not match the database record for any recognized format")

// ClassifyStoredFile determines the on-disk format of a stored file by
// comparing its size (and, when present, its SFSE header) to dbFileSize —
// never by the old "len(data) >= 29" heuristic, which cannot distinguish a
// short plaintext file from an encrypted one.
//
// Disambiguation rule for the "plaintext file that happens to start with
// the SFSE magic bytes" edge case: a real SFSE ciphertext is always
// strictly larger than its plaintext (header + at least one chunk's
// nonce+tag overhead, even for a zero-byte plaintext, which still costs a
// header). So an EXACT match between on-disk size and dbFileSize can only
// ever be produced by a plaintext file — never by a genuine SFSE1/SFSE2
// ciphertext — and is therefore checked first, before the magic bytes are
// even inspected. Size match wins.
//
// f must be open for reading; fi is f's os.FileInfo. keyEnabled reports
// whether the server has an encryption key configured — without one, any
// non-plaintext classification is reported as ErrEncryptionKeyMissing
// rather than a (useless, undecryptable) format value.
func ClassifyStoredFile(f *os.File, fi os.FileInfo, dbFileSize int64, keyEnabled bool) (StoredFormat, error) {
	if dbFileSize < 0 || dbFileSize > maxSFSEPlainLen {
		return FormatUnknown, fmt.Errorf("%w: db file_size %d out of range [0, %d]", ErrStoredSizeMismatch, dbFileSize, maxSFSEPlainLen)
	}

	size := fi.Size()

	if size == dbFileSize {
		return FormatPlaintext, nil
	}

	var hdr [SFSE2HeaderSize]byte
	n, err := f.ReadAt(hdr[:], 0)
	if err != nil && err != io.EOF {
		return FormatUnknown, fmt.Errorf("failed to read file header: %w", err)
	}

	if n >= 6 && string(hdr[0:5]) == StreamEncryptionMagic {
		version := hdr[5]
		switch version {
		case StreamEncryptionVersion:
			if !keyEnabled {
				return FormatUnknown, ErrEncryptionKeyMissing
			}
			if n < SFSE1HeaderSize {
				return FormatUnknown, fmt.Errorf("%w: SFSE1 header truncated", ErrStoredSizeMismatch)
			}
			chunkSize := int64(binary.LittleEndian.Uint32(hdr[6:10]))
			if chunkSize <= 0 || chunkSize > MaxSFSEChunkSize {
				return FormatUnknown, fmt.Errorf("%w: chunk_size %d out of range", ErrStoredSizeMismatch, chunkSize)
			}
			expected := expectedSFSECiphertextSize(SFSE1HeaderSize, chunkSize, dbFileSize)
			if size != expected {
				return FormatUnknown, fmt.Errorf("%w: on-disk size %d, expected %d for SFSE1", ErrStoredSizeMismatch, size, expected)
			}
			return FormatSFSE1, nil

		case StreamEncryptionVersionV2:
			if !keyEnabled {
				return FormatUnknown, ErrEncryptionKeyMissing
			}
			if n < SFSE2HeaderSize {
				return FormatUnknown, fmt.Errorf("%w: SFSE2 header truncated", ErrStoredSizeMismatch)
			}
			chunkSize := int64(binary.LittleEndian.Uint32(hdr[6:10]))
			if chunkSize <= 0 || chunkSize > MaxSFSEChunkSize {
				return FormatUnknown, fmt.Errorf("%w: chunk_size %d out of range", ErrStoredSizeMismatch, chunkSize)
			}
			headerPlainLen := int64(binary.BigEndian.Uint64(hdr[10:18]))
			if headerPlainLen != dbFileSize {
				return FormatUnknown, fmt.Errorf("%w: SFSE2 header plaintext length %d, db size %d", ErrStoredSizeMismatch, headerPlainLen, dbFileSize)
			}
			expected := expectedSFSECiphertextSize(SFSE2HeaderSize, chunkSize, dbFileSize)
			if size != expected {
				return FormatUnknown, fmt.Errorf("%w: on-disk size %d, expected %d for SFSE2", ErrStoredSizeMismatch, size, expected)
			}
			return FormatSFSE2, nil

		default:
			return FormatUnknown, fmt.Errorf("%w: %d", ErrUnsupportedSFSEVersion, version)
		}
	}

	// Legacy single-shot format: [nonce(12)][ciphertext == dbFileSize bytes][tag(16)].
	if size == dbFileSize+int64(SFSE2OverheadPerChunk) {
		if !keyEnabled {
			return FormatUnknown, ErrEncryptionKeyMissing
		}
		return FormatLegacy, nil
	}

	return FormatUnknown, fmt.Errorf("%w: on-disk size %d, db size %d", ErrStoredSizeMismatch, size, dbFileSize)
}

// expectedSFSECiphertextSize computes the on-disk size an SFSE1 or SFSE2
// file must have for a given header size and chunk size to hold exactly
// plainLen plaintext bytes: the header, plus per-chunk nonce+tag overhead
// on every chunk. A zero-length plaintext still costs the header (no
// chunks are written).
func expectedSFSECiphertextSize(headerSize, chunkSize, plainLen int64) int64 {
	totalChunks := chunkCountFromPlaintextLen(plainLen, chunkSize)
	if totalChunks == 0 {
		return headerSize
	}
	finalChunkPlainBytes := plainLen - (totalChunks-1)*chunkSize
	return headerSize + (totalChunks-1)*(chunkSize+SFSE2OverheadPerChunk) + finalChunkPlainBytes + SFSE2OverheadPerChunk
}
