package safeshare

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Standard errors returned by the SDK.
var (
	// ErrValidation indicates invalid input parameters.
	ErrValidation = errors.New("validation error")
	// ErrAuthentication indicates authentication failure.
	ErrAuthentication = errors.New("authentication failed")
	// ErrNotFound indicates the requested resource was not found.
	ErrNotFound = errors.New("not found")
	// ErrRateLimit indicates too many requests.
	ErrRateLimit = errors.New("rate limit exceeded")
	// ErrPasswordRequired indicates a password is needed.
	ErrPasswordRequired = errors.New("password required")
	// ErrDownloadLimitReached indicates no downloads remaining.
	ErrDownloadLimitReached = errors.New("download limit reached")
	// ErrFileTooLarge indicates the file exceeds size limits.
	ErrFileTooLarge = errors.New("file too large")
	// ErrQuotaExceeded indicates the user's quota was exceeded.
	ErrQuotaExceeded = errors.New("quota exceeded")

	// ErrMalwareDetected indicates the server's malware scan found a threat
	// and rejected the upload before storing it (ADR-015). Not retryable
	// with the same file content.
	ErrMalwareDetected = errors.New("malware detected")
	// ErrFileQuarantined indicates the requested file was found infected by
	// a scan and is permanently unavailable for download (ADR-015).
	ErrFileQuarantined = errors.New("file quarantined")
	// ErrScanPending indicates the file's malware scan has not completed
	// yet; the download may succeed on retry. Check APIError.RetryAfter for
	// how long to wait (ADR-015).
	ErrScanPending = errors.New("malware scan pending")
	// ErrScanUnavailable indicates the malware scanner could not be reached
	// or timed out; the request may succeed on retry once the scanner
	// recovers. Check APIError.RetryAfter for how long to wait (ADR-015).
	ErrScanUnavailable = errors.New("malware scanner unavailable")
	// ErrScanFailed indicates a file's malware scan previously errored and
	// the server will not serve it until re-verified (ADR-015). Not
	// retryable by the client.
	ErrScanFailed = errors.New("malware scan failed")
	// ErrUnscannableUpload indicates the server rejected an upload outright
	// because its content can never be scanned (end-to-end encrypted, or
	// larger than the server's scan size limit) and this server requires
	// all uploads to be scannable (MALWARE_SCAN_REJECT_UNSCANNABLE, ADR-015).
	ErrUnscannableUpload = errors.New("upload cannot be scanned for malware")
)

// APIError represents an error response from the SafeShare API.
type APIError struct {
	// StatusCode is the HTTP status code.
	StatusCode int
	// Message is the error message.
	Message string
	// Code is the server's machine-readable error code (the JSON response's
	// "code" field, e.g. "MALWARE_DETECTED", "SCAN_PENDING"), when present.
	Code string
	// RetryAfter is the server's suggested retry delay, parsed from the
	// Retry-After response header (0 if absent or not sent as whole seconds).
	RetryAfter time.Duration
	// Err is the underlying error type.
	Err error
}

// Error implements the error interface.
func (e *APIError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s (status %d)", e.Err.Error(), e.Message, e.StatusCode)
	}
	return fmt.Sprintf("%s (status %d)", e.Message, e.StatusCode)
}

// Unwrap returns the underlying error for errors.Is/As support.
func (e *APIError) Unwrap() error {
	return e.Err
}

// Is implements error comparison for errors.Is.
func (e *APIError) Is(target error) bool {
	if e.Err != nil && errors.Is(e.Err, target) {
		return true
	}
	return false
}

// ValidationError represents an input validation failure.
type ValidationError struct {
	// Field is the name of the invalid field.
	Field string
	// Message describes what's wrong.
	Message string
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("validation error: %s: %s", e.Field, e.Message)
	}
	return fmt.Sprintf("validation error: %s", e.Message)
}

// Is implements error comparison.
func (e *ValidationError) Is(target error) bool {
	return errors.Is(ErrValidation, target)
}

// Unwrap returns ErrValidation for errors.Is support.
func (e *ValidationError) Unwrap() error {
	return ErrValidation
}

// ChunkedUploadError represents an error during chunked upload.
type ChunkedUploadError struct {
	// UploadID is the upload session ID.
	UploadID string
	// ChunkNumber is the chunk that failed (if applicable).
	ChunkNumber int
	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *ChunkedUploadError) Error() string {
	if e.ChunkNumber > 0 {
		return fmt.Sprintf("chunked upload failed (upload_id=%s, chunk=%d): %v", e.UploadID, e.ChunkNumber, e.Err)
	}
	return fmt.Sprintf("chunked upload failed (upload_id=%s): %v", e.UploadID, e.Err)
}

// Unwrap returns the underlying error.
func (e *ChunkedUploadError) Unwrap() error {
	return e.Err
}

// newAPIError creates an APIError from an HTTP response. code is the
// server's machine-readable error code (the JSON response's "code" field);
// pass "" if unavailable (e.g. the response body didn't decode).
func newAPIError(statusCode int, message string, code string) *APIError {
	err := &APIError{
		StatusCode: statusCode,
		Message:    sanitizeErrorMessage(message),
		Code:       code,
	}

	// ADR-015 error codes are matched first and take priority over the
	// status-code heuristics below: several of them share an HTTP status
	// with an older, differently-meaning error (e.g. FILE_QUARANTINED and
	// the legacy download-limit-reached case both use 410), so the code is
	// the only reliable disambiguator.
	switch code {
	case "MALWARE_DETECTED":
		err.Err = ErrMalwareDetected
		return err
	case "FILE_QUARANTINED":
		err.Err = ErrFileQuarantined
		return err
	case "SCAN_PENDING":
		err.Err = ErrScanPending
		return err
	case "SCAN_UNAVAILABLE":
		err.Err = ErrScanUnavailable
		return err
	case "SCAN_FAILED":
		err.Err = ErrScanFailed
		return err
	case "UNSCANNABLE_UPLOAD":
		err.Err = ErrUnscannableUpload
		return err
	}

	// Map status codes to error types
	switch statusCode {
	case 400:
		err.Err = ErrValidation
	case 401:
		if containsAny(message, "password") {
			err.Err = ErrPasswordRequired
		} else {
			err.Err = ErrAuthentication
		}
	case 403:
		if containsAny(message, "quota") {
			err.Err = ErrQuotaExceeded
		}
	case 404:
		err.Err = ErrNotFound
	case 410:
		err.Err = ErrDownloadLimitReached
	case 413:
		err.Err = ErrFileTooLarge
	case 429:
		err.Err = ErrRateLimit
	}

	return err
}

// sanitizeErrorMessage removes potentially sensitive information from error messages.
func sanitizeErrorMessage(msg string) string {
	// List of sensitive keywords to check for
	sensitivePatterns := []string{
		"token",
		"password",
		"secret",
		"key",
		"authorization",
		"cookie",
		"credential",
	}

	lowerMsg := strings.ToLower(msg)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerMsg, pattern) {
			// If the message contains sensitive keywords, return a generic message
			// to prevent potential credential leakage
			return "request failed"
		}
	}

	return msg
}

// containsAny checks if s contains any of the substrings (case-insensitive).
func containsAny(s string, substrs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
