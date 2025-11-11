package utils

import (
	"fmt"
	"strconv"
	"strings"
)

// HTTPRange represents a parsed HTTP Range request
type HTTPRange struct {
	Start int64
	End   int64
}

// ParseRange parses an HTTP Range header value and returns the byte range.
// Supports RFC 7233 formats:
//   - "bytes=0-1023" (specific range)
//   - "bytes=1024-" (from offset to end)
//   - "bytes=-500" (last 500 bytes)
//
// Returns the resolved start and end positions (inclusive), or an error if invalid.
// Note: Multi-range requests (e.g., "bytes=0-100,200-300") are not supported.
func ParseRange(rangeHeader string, fileSize int64) (*HTTPRange, error) {
	// Validate file size
	if fileSize < 0 {
		return nil, fmt.Errorf("invalid file size: %d", fileSize)
	}

	// Check for "bytes=" prefix
	const bytesPrefix = "bytes="
	if !strings.HasPrefix(rangeHeader, bytesPrefix) {
		return nil, fmt.Errorf("invalid range header format: missing 'bytes=' prefix")
	}

	// Extract range specification
	rangeSpec := strings.TrimPrefix(rangeHeader, bytesPrefix)
	rangeSpec = strings.TrimSpace(rangeSpec)

	// Check for multi-range (not supported)
	if strings.Contains(rangeSpec, ",") {
		return nil, fmt.Errorf("multi-range requests are not supported")
	}

	// Split on hyphen
	parts := strings.Split(rangeSpec, "-")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid range format: expected 'start-end'")
	}

	startStr := strings.TrimSpace(parts[0])
	endStr := strings.TrimSpace(parts[1])

	var start, end int64

	// Handle suffix-byte-range (e.g., "-500" = last 500 bytes)
	if startStr == "" {
		if endStr == "" {
			return nil, fmt.Errorf("invalid range: both start and end are empty")
		}
		suffixLen, err := strconv.ParseInt(endStr, 10, 64)
		if err != nil || suffixLen < 0 {
			return nil, fmt.Errorf("invalid suffix length: %s", endStr)
		}
		if suffixLen == 0 {
			return nil, fmt.Errorf("invalid range: suffix length cannot be zero")
		}

		// Calculate start position for last N bytes
		start = fileSize - suffixLen
		if start < 0 {
			start = 0
		}
		end = fileSize - 1
	} else {
		// Parse start position
		var err error
		start, err = strconv.ParseInt(startStr, 10, 64)
		if err != nil || start < 0 {
			return nil, fmt.Errorf("invalid start position: %s", startStr)
		}

		// Handle open-ended range (e.g., "1024-")
		if endStr == "" {
			end = fileSize - 1
		} else {
			end, err = strconv.ParseInt(endStr, 10, 64)
			if err != nil || end < 0 {
				return nil, fmt.Errorf("invalid end position: %s", endStr)
			}
		}
	}

	// Validate range
	if start > end {
		return nil, fmt.Errorf("invalid range: start (%d) > end (%d)", start, end)
	}

	// Check if range is satisfiable (start must be within file bounds)
	if start >= fileSize {
		return nil, fmt.Errorf("range not satisfiable: start position %d >= file size %d", start, fileSize)
	}

	// Clamp end to file size
	if end >= fileSize {
		end = fileSize - 1
	}

	return &HTTPRange{
		Start: start,
		End:   end,
	}, nil
}

// ContentLength returns the number of bytes in this range
func (r *HTTPRange) ContentLength() int64 {
	return r.End - r.Start + 1
}

// ContentRangeHeader returns the Content-Range header value for this range
// Format: "bytes start-end/total"
func (r *HTTPRange) ContentRangeHeader(fileSize int64) string {
	return fmt.Sprintf("bytes %d-%d/%d", r.Start, r.End, fileSize)
}
