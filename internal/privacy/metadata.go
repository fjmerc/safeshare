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
