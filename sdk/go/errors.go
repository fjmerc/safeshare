package safeshare

import (
	"errors"
	"fmt"
	"strings"
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
)

// APIError represents an error response from the SafeShare API.
type APIError struct {
	// StatusCode is the HTTP status code.
	StatusCode int
	// Message is the error message.
	Message string
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

// newAPIError creates an APIError from an HTTP response.
func newAPIError(statusCode int, message string) *APIError {
	err := &APIError{
		StatusCode: statusCode,
		Message:    sanitizeErrorMessage(message),
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
