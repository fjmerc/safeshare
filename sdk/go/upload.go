package safeshare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Upload uploads a file to SafeShare.
// It automatically uses chunked upload for large files based on server configuration.
//
// Example:
//
//	result, err := client.Upload(ctx, "/path/to/file.txt", &safeshare.UploadOptions{
//	    ExpiresInHours: intPtr(24),
//	    DownloadLimit:  intPtr(10),
//	    OnProgress: func(p safeshare.UploadProgress) {
//	        fmt.Printf("Upload: %d%%\n", p.Percentage)
//	    },
//	})
func (c *Client) Upload(ctx context.Context, filePath string, opts *UploadOptions) (*UploadResult, error) {
	if opts == nil {
		opts = &UploadOptions{}
	}

	// Get absolute path and validate
	absPath, err := filepath.Abs(filePath)
	if err != nil {
		return nil, fmt.Errorf("resolving path: %w", err)
	}

	// Get file info
	fileInfo, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("getting file info: %w", err)
	}

	filename := filepath.Base(absPath)
	if err := validateFilename(filename); err != nil {
		return nil, err
	}

	// Get config to determine if chunked upload is needed
	config, err := c.GetConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting config: %w", err)
	}

	if fileInfo.Size() >= config.ChunkUploadThreshold {
		return c.uploadChunked(ctx, absPath, fileInfo.Size(), opts)
	}

	return c.uploadSimple(ctx, absPath, fileInfo.Size(), opts)
}

// uploadSimple performs a simple (non-chunked) file upload.
func (c *Client) uploadSimple(ctx context.Context, filePath string, fileSize int64, opts *UploadOptions) (*UploadResult, error) {
	filename := filepath.Base(filePath)

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	// Create multipart form
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)

	// Add file field
	part, err := writer.CreateFormFile("file", filename)
	if err != nil {
		return nil, fmt.Errorf("creating form file: %w", err)
	}

	// Copy file with progress tracking
	var bytesWritten int64
	progressReader := &progressReader{
		reader: file,
		size:   fileSize,
		onProgress: func(n int64) {
			bytesWritten = n
			if opts.OnProgress != nil {
				opts.OnProgress(UploadProgress{
					BytesUploaded: bytesWritten,
					TotalBytes:    fileSize,
					Percentage:    int(float64(bytesWritten) / float64(fileSize) * 100),
				})
			}
		},
	}

	if _, err := io.Copy(part, progressReader); err != nil {
		return nil, fmt.Errorf("copying file: %w", err)
	}

	// Add optional fields
	if opts.ExpiresInHours != nil {
		writer.WriteField("expires_in_hours", strconv.Itoa(*opts.ExpiresInHours))
	}
	if opts.DownloadLimit != nil {
		writer.WriteField("download_limit", strconv.Itoa(*opts.DownloadLimit))
	}
	if opts.Password != "" {
		writer.WriteField("password", opts.Password)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("closing multipart writer: %w", err)
	}

	// Make request
	resp, err := c.request(ctx, http.MethodPost, "/api/upload", &buf, writer.FormDataContentType())
	if err != nil {
		return nil, err
	}

	var apiResp apiUploadResponse
	if err := handleResponse(resp, &apiResp); err != nil {
		return nil, err
	}

	return &UploadResult{
		ClaimCode:         apiResp.ClaimCode,
		Filename:          apiResp.Filename,
		Size:              apiResp.Size,
		MimeType:          apiResp.MimeType,
		ExpiresAt:         parseTime(apiResp.ExpiresAt),
		DownloadLimit:     apiResp.DownloadLimit,
		PasswordProtected: apiResp.PasswordProtected,
		UserID:            apiResp.UserID,
	}, nil
}

// uploadChunked performs a chunked file upload for large files.
func (c *Client) uploadChunked(ctx context.Context, filePath string, fileSize int64, opts *UploadOptions) (*UploadResult, error) {
	filename := filepath.Base(filePath)

	// Initialize chunked upload
	initBody := map[string]interface{}{
		"filename":   filename,
		"total_size": fileSize,
	}
	if opts.ExpiresInHours != nil {
		initBody["expires_in_hours"] = *opts.ExpiresInHours
	}
	if opts.DownloadLimit != nil {
		initBody["download_limit"] = *opts.DownloadLimit
	}
	if opts.Password != "" {
		initBody["password"] = opts.Password
	}

	initJSON, err := json.Marshal(initBody)
	if err != nil {
		return nil, fmt.Errorf("marshaling init body: %w", err)
	}

	resp, err := c.request(ctx, http.MethodPost, "/api/upload/init", bytes.NewReader(initJSON), "application/json")
	if err != nil {
		return nil, err
	}

	var session apiChunkedUploadInitResponse
	if err := handleResponse(resp, &session); err != nil {
		return nil, err
	}

	uploadID := session.UploadID
	// Validate server-provided upload ID to prevent URL injection
	if err := validateUploadID(uploadID); err != nil {
		return nil, fmt.Errorf("server returned invalid upload_id: %w", err)
	}
	chunkSize := session.ChunkSize
	totalChunks := session.TotalChunks

	// Open file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	// Upload chunks
	var bytesUploaded int64
	chunkBuffer := make([]byte, chunkSize)

	for chunkNum := 0; chunkNum < totalChunks; chunkNum++ {
		// Read chunk
		n, err := io.ReadFull(file, chunkBuffer)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			c.cancelUpload(ctx, uploadID)
			return nil, &ChunkedUploadError{
				UploadID:    uploadID,
				ChunkNumber: chunkNum,
				Err:         fmt.Errorf("reading chunk: %w", err),
			}
		}

		chunk := chunkBuffer[:n]

		// Create multipart form for chunk
		var buf bytes.Buffer
		writer := multipart.NewWriter(&buf)

		part, err := writer.CreateFormFile("chunk", "chunk")
		if err != nil {
			c.cancelUpload(ctx, uploadID)
			return nil, &ChunkedUploadError{
				UploadID:    uploadID,
				ChunkNumber: chunkNum,
				Err:         fmt.Errorf("creating chunk form: %w", err),
			}
		}

		if _, err := part.Write(chunk); err != nil {
			c.cancelUpload(ctx, uploadID)
			return nil, &ChunkedUploadError{
				UploadID:    uploadID,
				ChunkNumber: chunkNum,
				Err:         fmt.Errorf("writing chunk: %w", err),
			}
		}

		if err := writer.Close(); err != nil {
			c.cancelUpload(ctx, uploadID)
			return nil, &ChunkedUploadError{
				UploadID:    uploadID,
				ChunkNumber: chunkNum,
				Err:         fmt.Errorf("closing chunk writer: %w", err),
			}
		}

		// Upload chunk
		path := fmt.Sprintf("/api/upload/chunk/%s/%d", uploadID, chunkNum)
		chunkResp, err := c.request(ctx, http.MethodPost, path, &buf, writer.FormDataContentType())
		if err != nil {
			c.cancelUpload(ctx, uploadID)
			return nil, &ChunkedUploadError{
				UploadID:    uploadID,
				ChunkNumber: chunkNum,
				Err:         err,
			}
		}

		if err := handleResponse(chunkResp, nil); err != nil {
			c.cancelUpload(ctx, uploadID)
			return nil, &ChunkedUploadError{
				UploadID:    uploadID,
				ChunkNumber: chunkNum,
				Err:         err,
			}
		}

		bytesUploaded += int64(n)

		// Report progress
		if opts.OnProgress != nil {
			opts.OnProgress(UploadProgress{
				BytesUploaded: bytesUploaded,
				TotalBytes:    fileSize,
				Percentage:    int(float64(bytesUploaded) / float64(fileSize) * 100),
				CurrentChunk:  chunkNum + 1,
				TotalChunks:   totalChunks,
			})
		}
	}

	// Complete the upload
	completeResp, err := c.request(ctx, http.MethodPost, fmt.Sprintf("/api/upload/complete/%s", uploadID), nil, "")
	if err != nil {
		c.cancelUpload(ctx, uploadID)
		return nil, &ChunkedUploadError{
			UploadID: uploadID,
			Err:      err,
		}
	}

	// Check if server returned 202 Accepted (async assembly in progress)
	if completeResp.StatusCode == http.StatusAccepted {
		completeResp.Body.Close()
		// Poll for completion
		return c.pollForCompletion(ctx, uploadID, filename, fileSize, opts)
	}

	var apiResp apiUploadResponse
	if err := handleResponse(completeResp, &apiResp); err != nil {
		c.cancelUpload(ctx, uploadID)
		return nil, &ChunkedUploadError{
			UploadID: uploadID,
			Err:      err,
		}
	}

	return &UploadResult{
		ClaimCode:         apiResp.ClaimCode,
		Filename:          apiResp.Filename,
		Size:              apiResp.Size,
		MimeType:          apiResp.MimeType,
		ExpiresAt:         parseTime(apiResp.ExpiresAt),
		DownloadLimit:     apiResp.DownloadLimit,
		PasswordProtected: apiResp.PasswordProtected,
		UserID:            apiResp.UserID,
	}, nil
}

// cancelUpload attempts to cancel a chunked upload session.
func (c *Client) cancelUpload(ctx context.Context, uploadID string) {
	// Best effort - ignore errors
	resp, err := c.request(ctx, http.MethodDelete, fmt.Sprintf("/api/upload/cancel/%s", uploadID), nil, "")
	if err == nil {
		resp.Body.Close()
	}
}

// pollForCompletion polls the upload status endpoint until assembly is complete.
// This is used when the server returns 202 Accepted for async assembly.
func (c *Client) pollForCompletion(ctx context.Context, uploadID, filename string, fileSize int64, opts *UploadOptions) (*UploadResult, error) {
	// Poll with exponential backoff: start at 500ms, max 5s, timeout after 10 minutes
	const (
		initialDelay  = 500 * time.Millisecond
		maxDelay      = 5 * time.Second
		maxDuration   = 10 * time.Minute
		maxIterations = 200 // Safety limit to prevent runaway polling
	)

	deadline := time.Now().Add(maxDuration)
	delay := initialDelay

	for iteration := 0; iteration < maxIterations && time.Now().Before(deadline); iteration++ {
		// Check context cancellation
		select {
		case <-ctx.Done():
			c.cancelUpload(context.Background(), uploadID)
			return nil, ctx.Err()
		default:
		}

		// Get status
		status, err := c.getUploadStatusInternal(ctx, uploadID)
		if err != nil {
			return nil, &ChunkedUploadError{
				UploadID: uploadID,
				Err:      fmt.Errorf("polling status: %w", err),
			}
		}

		switch status.Status {
		case "completed":
			// Assembly complete - return result
			if status.ClaimCode == nil || *status.ClaimCode == "" {
				return nil, &ChunkedUploadError{
					UploadID: uploadID,
					Err:      fmt.Errorf("upload completed but no claim code returned"),
				}
			}
			return &UploadResult{
				ClaimCode:         *status.ClaimCode,
				Filename:          filename,
				Size:              fileSize,
				MimeType:          "", // Not available in status response
				ExpiresAt:         &status.ExpiresAt,
				DownloadLimit:     status.MaxDownloads,
				PasswordProtected: false, // Not available in status response
			}, nil

		case "failed":
			errMsg := "assembly failed"
			if status.ErrorMessage != nil {
				errMsg = fmt.Sprintf("assembly failed: %q", *status.ErrorMessage)
			}
			return nil, &ChunkedUploadError{
				UploadID: uploadID,
				Err:      fmt.Errorf("%s", errMsg),
			}

		case "processing", "uploading":
			// Wait with cancellation support before retrying
			select {
			case <-ctx.Done():
				c.cancelUpload(context.Background(), uploadID)
				return nil, ctx.Err()
			case <-time.After(delay):
			}
			// Exponential backoff
			delay = delay * 2
			if delay > maxDelay {
				delay = maxDelay
			}

		default:
			return nil, &ChunkedUploadError{
				UploadID: uploadID,
				Err:      fmt.Errorf("unexpected status: %s", status.Status),
			}
		}
	}

	return nil, &ChunkedUploadError{
		UploadID: uploadID,
		Err:      fmt.Errorf("timeout waiting for assembly to complete (max %v)", maxDuration),
	}
}

// GetUploadStatus retrieves the status of a chunked upload session.
func (c *Client) GetUploadStatus(ctx context.Context, uploadID string) (*UploadStatus, error) {
	if err := validateUploadID(uploadID); err != nil {
		return nil, err
	}
	return c.getUploadStatusInternal(ctx, uploadID)
}

// getUploadStatusInternal is the internal implementation of GetUploadStatus.
// It's separated to allow calling without re-validating the uploadID during polling.
func (c *Client) getUploadStatusInternal(ctx context.Context, uploadID string) (*UploadStatus, error) {
	resp, err := c.request(ctx, http.MethodGet, fmt.Sprintf("/api/upload/status/%s", uploadID), nil, "")
	if err != nil {
		return nil, err
	}

	var apiResp struct {
		UploadID       string  `json:"upload_id"`
		Filename       string  `json:"filename"`
		TotalSize      int64   `json:"total_size"`
		UploadedSize   int64   `json:"uploaded_size"`
		UploadedChunks []int   `json:"uploaded_chunks"`
		TotalChunks    int     `json:"total_chunks"`
		ChunkSize      int64   `json:"chunk_size"`
		ExpiresAt      string  `json:"expires_at"`
		Complete       bool    `json:"complete"`
		Status         string  `json:"status"`
		ClaimCode      *string `json:"claim_code,omitempty"`
		ErrorMessage   *string `json:"error_message,omitempty"`
		MaxDownloads   *int    `json:"max_downloads,omitempty"`
	}

	if err := handleResponse(resp, &apiResp); err != nil {
		return nil, err
	}

	return &UploadStatus{
		UploadID:       apiResp.UploadID,
		Filename:       apiResp.Filename,
		TotalSize:      apiResp.TotalSize,
		UploadedSize:   apiResp.UploadedSize,
		UploadedChunks: apiResp.UploadedChunks,
		TotalChunks:    apiResp.TotalChunks,
		ChunkSize:      apiResp.ChunkSize,
		ExpiresAt:      parseTimeRequired(apiResp.ExpiresAt),
		Complete:       apiResp.Complete,
		Status:         apiResp.Status,
		ClaimCode:      apiResp.ClaimCode,
		ErrorMessage:   apiResp.ErrorMessage,
		MaxDownloads:   apiResp.MaxDownloads,
	}, nil
}

// progressReader wraps an io.Reader to track read progress.
type progressReader struct {
	reader     io.Reader
	size       int64
	read       int64
	onProgress func(int64)
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	if n > 0 {
		pr.read += int64(n)
		if pr.onProgress != nil {
			pr.onProgress(pr.read)
		}
	}
	return n, err
}
