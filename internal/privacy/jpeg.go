package privacy

import (
	"encoding/binary"
	"fmt"
	"os"
)

// JPEG marker constants
const (
	markerPrefix = 0xFF
	markerSOI    = 0xD8 // Start of Image
	markerAPP0   = 0xE0 // JFIF header (keep)
	markerSOS    = 0xDA // Start of Scan (image data follows)
	markerCOM    = 0xFE // Comment segment
)

// isMetadataMarker returns true for APP1-APP15 and COM markers.
// APP0 (JFIF) is preserved as it's needed for basic JPEG rendering.
func isMetadataMarker(markerType byte) bool {
	// APP1 (0xE1) through APP15 (0xEF) — EXIF, XMP, IPTC, ICC, Adobe, etc.
	if markerType >= 0xE1 && markerType <= 0xEF {
		return true
	}
	// COM (0xFE) — arbitrary comment text
	return markerType == markerCOM
}

// stripJPEGMetadata removes all metadata segments (APP1-APP15, COM) from a JPEG file.
// APP0 (JFIF) is preserved for rendering. The stripping is lossless — image data is untouched.
// Note: Multi-scan progressive JPEGs with segments after SOS are not fully supported;
// all data from the first SOS to EOF is copied verbatim.
func stripJPEGMetadata(filePath string) error {
	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("stat JPEG file: %w", err)
	}
	if info.Size() > maxStrippableFileSize {
		return fmt.Errorf("file too large for metadata stripping: %d bytes (max %d)", info.Size(), maxStrippableFileSize)
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to read JPEG file: %w", err)
	}

	if len(data) < 2 || data[0] != markerPrefix || data[1] != markerSOI {
		return fmt.Errorf("not a valid JPEG file: missing SOI marker")
	}

	result, stripped, err := removeMetadataSegments(data)
	if err != nil {
		return err
	}

	if !stripped {
		return nil // No metadata segments found, file unchanged
	}

	return os.WriteFile(filePath, result, info.Mode().Perm())
}

// removeMetadataSegments walks JPEG markers and removes all metadata segments.
// Returns the modified data and whether any segments were removed.
func removeMetadataSegments(data []byte) ([]byte, bool, error) {
	// Pre-allocate result buffer (will be at most len(data))
	result := make([]byte, 0, len(data))
	// Copy SOI marker
	result = append(result, data[0], data[1])

	pos := 2
	stripped := false

	for pos < len(data)-1 {
		// Each marker starts with 0xFF
		if data[pos] != markerPrefix {
			// Non-marker data encountered outside SOS — copy the rest
			result = append(result, data[pos:]...)
			break
		}

		markerType := data[pos+1]

		// Skip padding bytes (0xFF 0xFF sequences)
		if markerType == markerPrefix {
			pos++
			continue
		}

		// Markers without length (standalone markers: RST0-RST7, SOI, EOI, TEM)
		if markerType == 0x00 || markerType == 0x01 || (markerType >= 0xD0 && markerType <= 0xD9) {
			result = append(result, data[pos], data[pos+1])
			pos += 2
			continue
		}

		// SOS marker — everything after its header is image data until EOI.
		// For multi-scan progressive JPEGs, additional segments may follow
		// a SOS block, but we copy everything from SOS to EOF verbatim
		// to avoid corrupting the image data stream.
		if markerType == markerSOS {
			result = append(result, data[pos:]...)
			break
		}

		// Read segment length (big-endian, includes the 2 length bytes but not the marker)
		if pos+3 >= len(data) {
			return nil, false, fmt.Errorf("truncated JPEG: unexpected end at position %d", pos)
		}
		segmentLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		if segmentLen < 2 {
			return nil, false, fmt.Errorf("invalid JPEG segment length %d at position %d", segmentLen, pos)
		}

		segmentEnd := pos + 2 + segmentLen
		if segmentEnd > len(data) {
			return nil, false, fmt.Errorf("truncated JPEG segment at position %d: need %d bytes, have %d", pos, segmentEnd, len(data))
		}

		// Remove metadata segments (APP1-APP15 and COM)
		if isMetadataMarker(markerType) {
			stripped = true
			pos = segmentEnd
			continue
		}

		// Keep all other segments (APP0/JFIF, DQT, DHT, SOF, etc.)
		result = append(result, data[pos:segmentEnd]...)
		pos = segmentEnd
	}

	return result, stripped, nil
}
