package privacy

import (
	"errors"
	"fmt"
	"os"
)

// ErrFileTooLarge is returned (wrapped) by StripFileMetadata when a file of a
// supported type exceeds maxStrippableFileSize and therefore was NOT stripped.
// Callers that must fail closed (anonymous mode) treat this like any other
// stripping failure; best-effort callers may continue with the original file.
var ErrFileTooLarge = errors.New("file too large for metadata stripping")

// ErrEncryptedDocument is returned (wrapped) by StripFileMetadata when a
// document is password-protected or encrypted and therefore was NOT stripped.
// Like ErrFileTooLarge, fail-closed callers reject the upload.
var ErrEncryptedDocument = errors.New("encrypted document cannot be stripped")

// ErrStripTimeout is returned (wrapped) by StripFileMetadata when stripping a
// document took longer than its time limit and therefore was NOT stripped.
// Like ErrFileTooLarge, fail-closed callers reject the upload.
var ErrStripTimeout = errors.New("metadata stripping timed out")

// maxStrippableFileSize is the maximum file size we'll attempt to strip metadata from.
// Files larger than this are skipped (non-fatal) to prevent excessive memory usage,
// since stripping requires loading the entire file into memory.
const maxStrippableFileSize = 100 * 1024 * 1024 // 100 MB

// supportedMimeTypes maps MIME types to their stripping functions.
var supportedMimeTypes = map[string]func(string) error{
	"image/jpeg":      stripJPEGMetadata,
	"image/png":       stripPNGMetadata,
	"application/pdf": stripPDFMetadata,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   stripOfficeMetadata, // .docx
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         stripOfficeMetadata, // .xlsx
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": stripOfficeMetadata, // .pptx
	"video/mp4":       stripMP4Metadata, // .mp4
	"video/quicktime": stripMP4Metadata, // .mov
	"audio/mpeg":      stripMP3Metadata, // .mp3
}

// supportedBytesStrippers is supportedMimeTypes for in-memory files. The two
// maps must cover the same types (checked by a test).
var supportedBytesStrippers = map[string]func([]byte) ([]byte, bool, error){
	"image/jpeg":      stripJPEGBytes,
	"image/png":       stripPNGBytes,
	"application/pdf": stripPDFBytes,
	"application/vnd.openxmlformats-officedocument.wordprocessingml.document":   stripOfficeBytes,
	"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet":         stripOfficeBytes,
	"application/vnd.openxmlformats-officedocument.presentationml.presentation": stripOfficeBytes,
	"video/mp4":       stripMP4Bytes,
	"video/quicktime": stripMP4Bytes,
	"audio/mpeg":      stripMP3Bytes,
}

// SupportsMetadataStripping returns true if the MIME type supports metadata stripping.
func SupportsMetadataStripping(mimeType string) bool {
	_, ok := supportedMimeTypes[mimeType]
	return ok
}

// StripFileMetadata removes identifying metadata from supported file types.
// Modifies the file in-place. Returns nil for unsupported types (no-op).
// Returns an error only if stripping was attempted but failed.
func StripFileMetadata(filePath string, mimeType string) error {
	stripFunc, ok := supportedMimeTypes[mimeType]
	if !ok {
		return nil // Unsupported type, no-op
	}

	info, err := os.Stat(filePath)
	if err != nil {
		return fmt.Errorf("cannot stat file: %w", err)
	}
	if info.Size() == 0 {
		return fmt.Errorf("file is empty")
	}
	if info.Size() > maxStrippableFileSize {
		return fmt.Errorf("%w: %d bytes (max %d)", ErrFileTooLarge, info.Size(), maxStrippableFileSize)
	}

	return stripFunc(filePath)
}

// StripMetadataBytes is StripFileMetadata for a file held in memory: it
// returns the file with its identifying metadata removed, without writing
// anything to disk. For an unsupported type, or a supported one with no
// metadata, it returns data unchanged. It returns an error, and no data,
// only if stripping was attempted but failed; the caller must not fall back
// to data in that case if it has to fail closed.
func StripMetadataBytes(data []byte, mimeType string) ([]byte, error) {
	strip, ok := supportedBytesStrippers[mimeType]
	if !ok {
		return data, nil
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("file is empty")
	}
	if len(data) > maxStrippableFileSize {
		return nil, fmt.Errorf("%w: %d bytes (max %d)", ErrFileTooLarge, len(data), maxStrippableFileSize)
	}
	out, changed, err := strip(data)
	if err != nil {
		return nil, err
	}
	if !changed {
		return data, nil
	}
	return out, nil
}
