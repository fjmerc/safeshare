package privacy

import (
	"encoding/binary"
	"fmt"
	"os"
)

// ID3v2 and ID3v1 constants.
const (
	id3v2HeaderSize  = 10 // "ID3" + version (2) + flags (1) + synchsafe size (4)
	id3v2FooterSize  = 10 // Mirror of header, present when flags bit 4 is set
	id3v1TagSize     = 128
	apeTagHeaderSize = 32
	apeTagFooterSize = 32

	// id3v2FlagFooterPresent is bit 4 (0x10) in the ID3v2 flags byte.
	id3v2FlagFooterPresent = 0x10

	// apeFlagHasHeader is bit 29 of the APE tag flags field (uint32 little-endian at offset 20).
	apeFlagHasHeader = 1 << 29
)

var (
	id3v2Preamble = []byte{'I', 'D', '3'}
	id3v1Preamble = []byte{'T', 'A', 'G'}
	apePreamble   = []byte{'A', 'P', 'E', 'T', 'A', 'G', 'E', 'X'}
)

// decodeID3v2SynchsafeInt decodes a 4-byte synchsafe integer as used in ID3v2 headers.
// Each byte contributes only 7 bits (bit 7 is always 0).
func decodeID3v2SynchsafeInt(b []byte) int {
	return int(b[0])<<21 | int(b[1])<<14 | int(b[2])<<7 | int(b[3])
}

// stripMP3Metadata removes ID3v2, ID3v1, and APE tags from an MP3 file.
// The file is modified in-place. Returns nil if no metadata tags are found.
func stripMP3Metadata(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("stat MP3 file: %w", err)
	}
	if info.Size() > maxStrippableFileSize {
		return fmt.Errorf("file too large for metadata stripping: %d bytes (max %d)", info.Size(), maxStrippableFileSize)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read MP3 file: %w", err)
	}

	result, stripped, err := removeMP3Tags(data)
	if err != nil {
		return err
	}

	if !stripped {
		return nil // No metadata tags found, file unchanged
	}

	return os.WriteFile(filePath, result, info.Mode().Perm())
}

// removeMP3Tags strips ID3v2 (at start), APE (at end), and ID3v1 (at end) tags.
// Returns the modified data and whether any tags were removed.
func removeMP3Tags(data []byte) ([]byte, bool, error) {
	stripped := false

	// --- Step 1: strip ID3v2 tag from the start of the file ---
	prefixBytes, ok, err := parseID3v2Tag(data)
	if err != nil {
		return nil, false, err
	}
	if ok {
		data = data[prefixBytes:]
		stripped = true
	}

	// --- Step 2: strip trailing ID3v1 tag ---
	// ID3v1 is exactly the last 128 bytes starting with "TAG".
	id3v1Bytes, ok := parseID3v1Tag(data)
	if ok {
		data = data[:len(data)-id3v1Bytes]
		stripped = true
	}

	// --- Step 3: strip trailing APE tag (sits before ID3v1 if both present) ---
	apeBytes, ok, err := parseAPETag(data)
	if err != nil {
		return nil, false, err
	}
	if ok {
		data = data[:len(data)-apeBytes]
		stripped = true
	}

	return data, stripped, nil
}

// parseID3v2Tag inspects the beginning of data for an ID3v2 tag.
// Returns the total number of bytes occupied by the tag and true when found.
func parseID3v2Tag(data []byte) (int, bool, error) {
	if len(data) < id3v2HeaderSize {
		return 0, false, nil
	}

	if data[0] != id3v2Preamble[0] || data[1] != id3v2Preamble[1] || data[2] != id3v2Preamble[2] {
		return 0, false, nil
	}

	flags := data[5]
	sizeBytes := data[6:10]

	// Validate that all four synchsafe size bytes have their high bit clear.
	for i, b := range sizeBytes {
		if b&0x80 != 0 {
			return 0, false, fmt.Errorf("invalid ID3v2 synchsafe integer: byte %d has bit 7 set (0x%02x)", i, b)
		}
	}

	tagBodySize := decodeID3v2SynchsafeInt(sizeBytes)
	total := id3v2HeaderSize + tagBodySize

	if flags&id3v2FlagFooterPresent != 0 {
		total += id3v2FooterSize
	}

	if total > len(data) {
		return 0, false, fmt.Errorf("ID3v2 tag size %d exceeds file length %d", total, len(data))
	}

	return total, true, nil
}

// parseID3v1Tag inspects the end of data for an ID3v1 tag.
// Returns the number of bytes to remove and true when found.
func parseID3v1Tag(data []byte) (int, bool) {
	if len(data) < id3v1TagSize {
		return 0, false
	}

	offset := len(data) - id3v1TagSize
	if data[offset] != id3v1Preamble[0] || data[offset+1] != id3v1Preamble[1] || data[offset+2] != id3v1Preamble[2] {
		return 0, false
	}

	return id3v1TagSize, true
}

// parseAPETag inspects the end of data for an APE tag (v1 or v2).
// Returns the total number of bytes occupied by the tag and true when found.
// The APE footer is always present; an APE header is optional and indicated by
// bit 29 in the flags field of the footer.
func parseAPETag(data []byte) (int, bool, error) {
	if len(data) < apeTagFooterSize {
		return 0, false, nil
	}

	// The APE footer occupies the last 32 bytes of what remains after any ID3v1 strip.
	footerStart := len(data) - apeTagFooterSize
	footer := data[footerStart:]

	// Verify "APETAGEX" preamble.
	for i, b := range apePreamble {
		if footer[i] != b {
			return 0, false, nil
		}
	}

	// Tag size (item data + footer, does NOT include the header) at offset 12, uint32 LE.
	tagSize := int(binary.LittleEndian.Uint32(footer[12:16]))

	// Flags at offset 20, uint32 LE.
	flags := binary.LittleEndian.Uint32(footer[20:24])

	total := tagSize + apeTagFooterSize
	if flags&apeFlagHasHeader != 0 {
		total += apeTagHeaderSize
	}

	if total > len(data) {
		return 0, false, fmt.Errorf("APE tag size %d exceeds available data length %d", total, len(data))
	}

	return total, true, nil
}
