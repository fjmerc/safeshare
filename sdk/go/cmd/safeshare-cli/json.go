package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	safeshare "github.com/fjmerc/safeshare/sdk/go"
)

// jsonOut is the global --json flag: each command writes one JSON document
// to stdout and nothing else; notes and warnings stay on stderr, and errors
// go to stderr as a jsonError.
var jsonOut bool

// jsonSchema is the "schema" field of every document. Field names are an
// API for scripts: bump it only for a change that breaks them.
const jsonSchema = 1

// printJSON writes v as one line of JSON. Strings are written as they are,
// not escaped for the terminal as the human output is (display): JSON is
// data, and whoever reads it decides how to show it.
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// jsonError is how an error is reported on stderr with --json.
type jsonError struct {
	Error string `json:"error"`
	// Code is the server's machine-readable error code, when it sent one.
	Code string `json:"code,omitempty"`
	// Status is the HTTP status of a failed API request.
	Status int `json:"status,omitempty"`
}

func newJSONError(err error) jsonError {
	je := jsonError{Error: err.Error()}
	var apiErr *safeshare.APIError
	if errors.As(err, &apiErr) {
		je.Code, je.Status = apiErr.Code, apiErr.StatusCode
	}
	return je
}

// printError reports a command's error on stderr, as JSON with --json.
func printError(err error) {
	if jsonOut {
		_ = printJSON(os.Stderr, newJSONError(err))
		return
	}
	_, _ = io.WriteString(os.Stderr, escapeControls(err.Error())+"\n")
}

// uploadJSON is the --json document for an uploaded file.
type uploadJSON struct {
	Schema int `json:"schema"`
	// File is the path given on the command line.
	File              string     `json:"file"`
	ClaimCode         string     `json:"claim_code"`
	Filename          string     `json:"filename"`
	Size              int64      `json:"size"`
	MimeType          string     `json:"mime_type"`
	ExpiresAt         *time.Time `json:"expires_at"`
	DownloadLimit     *int       `json:"download_limit"`
	PasswordProtected bool       `json:"password_protected"`
	Encrypted         bool       `json:"encrypted"`
	// URL is the link to open: the claim page, or for an encrypted upload
	// the share link, which holds the decryption key. The SDK keeps that out
	// of its JSON (ShareURL is json:"-"); here it is the point of the
	// command, so it is added explicitly.
	URL string `json:"url"`
}

// uploadErrorJSON stands for a file that wasn't uploaded in the --json array
// of a several-file upload.
type uploadErrorJSON struct {
	Schema int    `json:"schema"`
	File   string `json:"file"`
	jsonError
}

func newUploadJSON(file, server string, r *safeshare.UploadResult) uploadJSON {
	return uploadJSON{
		Schema:            jsonSchema,
		File:              file,
		ClaimCode:         r.ClaimCode,
		Filename:          r.Filename,
		Size:              r.Size,
		MimeType:          r.MimeType,
		ExpiresAt:         r.ExpiresAt,
		DownloadLimit:     r.DownloadLimit,
		PasswordProtected: r.PasswordProtected,
		Encrypted:         r.Encrypted,
		URL:               uploadURL(server, r),
	}
}
