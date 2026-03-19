package privacy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
)

// PNG signature (8 bytes)
var pngSignature = []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

// PNG metadata chunk types to strip
var pngMetadataChunks = map[string]bool{
	"tEXt": true, // Uncompressed text (author, software, etc.)
	"iTXt": true, // International text
	"zTXt": true, // Compressed text
	"eXIf": true, // EXIF data in PNG (rare but possible)
	"tIME": true, // Last modification timestamp
}

// stripPNGMetadata removes text metadata chunks from a PNG file.
// The stripping is lossless — only metadata chunks are removed.
func stripPNGMetadata(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("stat PNG file: %w", err)
	}
	if info.Size() > maxStrippableFileSize {
		return fmt.Errorf("file too large for metadata stripping: %d bytes (max %d)", info.Size(), maxStrippableFileSize)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read PNG file: %w", err)
	}

	if len(data) < 8 || !bytes.Equal(data[:8], pngSignature) {
		return fmt.Errorf("not a valid PNG file: missing signature")
	}

	result, stripped, err := filterPNGChunks(data)
	if err != nil {
		return err
	}

	if !stripped {
		return nil // No metadata chunks found, file unchanged
	}

	return os.WriteFile(filePath, result, info.Mode().Perm())
}

// filterPNGChunks walks PNG chunks and removes metadata chunks.
// Returns the modified data and whether any chunks were removed.
func filterPNGChunks(data []byte) ([]byte, bool, error) {
	result := make([]byte, 0, len(data))
	// Copy PNG signature
	result = append(result, data[:8]...)

	pos := 8
	stripped := false

	for pos < len(data) {
		// Each chunk: 4 bytes length + 4 bytes type + data + 4 bytes CRC
		if pos+8 > len(data) {
			return nil, false, fmt.Errorf("truncated PNG: unexpected end at position %d", pos)
		}

		chunkLen := binary.BigEndian.Uint32(data[pos : pos+4])
		chunkType := string(data[pos+4 : pos+8])

		// Total chunk size: 4 (length) + 4 (type) + chunkLen (data) + 4 (CRC)
		// Use int64 arithmetic to prevent uint32 overflow
		totalChunkSize := int64(chunkLen) + 12
		if totalChunkSize > int64(len(data)-pos) {
			return nil, false, fmt.Errorf("truncated PNG chunk '%s' at position %d: need %d bytes, have %d", chunkType, pos, totalChunkSize, len(data)-pos)
		}
		chunkEnd := pos + int(totalChunkSize)

		// Validate CRC
		expectedCRC := binary.BigEndian.Uint32(data[chunkEnd-4 : chunkEnd])
		actualCRC := crc32.ChecksumIEEE(data[pos+4 : chunkEnd-4])
		if expectedCRC != actualCRC {
			return nil, false, fmt.Errorf("PNG CRC mismatch in chunk '%s' at position %d", chunkType, pos)
		}

		if pngMetadataChunks[chunkType] {
			stripped = true
			pos = chunkEnd
			continue
		}

		// Keep this chunk
		result = append(result, data[pos:chunkEnd]...)
		pos = chunkEnd
	}

	return result, stripped, nil
}
