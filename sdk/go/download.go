package safeshare

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
)

// Download downloads a file by claim code and saves it to the destination path.
//
// Example:
//
//	err := client.Download(ctx, "abc12345", "/path/to/output.pdf", &safeshare.DownloadOptions{
//	    Password: "secret",
//	    OnProgress: func(p safeshare.DownloadProgress) {
//	        fmt.Printf("Download: %d%%\n", p.Percentage)
//	    },
//	})
func (c *Client) Download(ctx context.Context, claimCode, destination string, opts *DownloadOptions) error {
	if err := validateClaimCode(claimCode); err != nil {
		return err
	}

	if opts == nil {
		opts = &DownloadOptions{}
	}

	// Resolve destination path
	destPath, err := filepath.Abs(destination)
	if err != nil {
		return fmt.Errorf("resolving destination path: %w", err)
	}

	// Ensure parent directory exists
	destDir := filepath.Dir(destPath)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return fmt.Errorf("creating destination directory: %w", err)
	}

	// Security: Check if destination exists and is a symlink (prevent symlink attacks)
	if info, err := os.Lstat(destPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("destination is a symbolic link, refusing to overwrite for security")
		}
		// File exists - check if overwrite is allowed
		if !opts.Overwrite {
			return fmt.Errorf("destination file already exists, set Overwrite option to true to replace")
		}
	}

	// Build URL with optional password
	downloadURL := fmt.Sprintf("/api/claim/%s", claimCode)
	if opts.Password != "" {
		downloadURL += "?password=" + url.QueryEscape(opts.Password)
	}

	// Make request
	resp, err := c.request(ctx, http.MethodGet, downloadURL, nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp struct {
			Error string `json:"error"`
		}
		// Try to decode error
		if err := handleResponse(resp, nil); err != nil {
			return err
		}
		return newAPIError(resp.StatusCode, errResp.Error)
	}

	// Get content length for progress
	contentLength, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)

	// Create destination file
	file, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("creating destination file: %w", err)
	}
	defer file.Close()

	// Download with progress tracking
	var reader io.Reader = resp.Body
	if opts.OnProgress != nil {
		reader = &progressDownloadReader{
			reader:     resp.Body,
			totalBytes: contentLength,
			onProgress: opts.OnProgress,
		}
	}

	if _, err := io.Copy(file, reader); err != nil {
		// Clean up partial file on error
		file.Close()
		os.Remove(destPath)
		return fmt.Errorf("downloading file: %w", err)
	}

	return nil
}

// DownloadToWriter downloads a file by claim code and writes it to the provided writer.
// This is useful for streaming downloads or writing to memory.
//
// Example:
//
//	var buf bytes.Buffer
//	err := client.DownloadToWriter(ctx, "abc12345", &buf, nil)
func (c *Client) DownloadToWriter(ctx context.Context, claimCode string, w io.Writer, opts *DownloadOptions) error {
	if err := validateClaimCode(claimCode); err != nil {
		return err
	}

	if opts == nil {
		opts = &DownloadOptions{}
	}

	// Build URL with optional password
	downloadURL := fmt.Sprintf("/api/claim/%s", claimCode)
	if opts.Password != "" {
		downloadURL += "?password=" + url.QueryEscape(opts.Password)
	}

	// Make request
	resp, err := c.request(ctx, http.MethodGet, downloadURL, nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return handleResponse(resp, nil)
	}

	// Get content length for progress
	contentLength, _ := strconv.ParseInt(resp.Header.Get("Content-Length"), 10, 64)

	// Download with progress tracking
	var reader io.Reader = resp.Body
	if opts.OnProgress != nil {
		reader = &progressDownloadReader{
			reader:     resp.Body,
			totalBytes: contentLength,
			onProgress: opts.OnProgress,
		}
	}

	if _, err := io.Copy(w, reader); err != nil {
		return fmt.Errorf("downloading file: %w", err)
	}

	return nil
}

// GetFileInfo retrieves information about a file by claim code.
//
// Example:
//
//	info, err := client.GetFileInfo(ctx, "abc12345")
//	if err != nil {
//	    if errors.Is(err, safeshare.ErrNotFound) {
//	        fmt.Println("File not found or expired")
//	    }
//	    return err
//	}
//	fmt.Printf("File: %s (%d bytes)\n", info.Filename, info.Size)
func (c *Client) GetFileInfo(ctx context.Context, claimCode string) (*FileInfo, error) {
	if err := validateClaimCode(claimCode); err != nil {
		return nil, err
	}

	resp, err := c.request(ctx, http.MethodGet, fmt.Sprintf("/api/claim/%s/info", claimCode), nil, "")
	if err != nil {
		return nil, err
	}

	var apiResp apiFileInfoResponse
	if err := handleResponse(resp, &apiResp); err != nil {
		return nil, err
	}

	// Calculate downloads remaining from max_downloads and download_count
	var downloadsRemaining *int
	if apiResp.MaxDownloads != nil {
		remaining := *apiResp.MaxDownloads - apiResp.DownloadCount
		if remaining < 0 {
			remaining = 0
		}
		downloadsRemaining = &remaining
	}

	return &FileInfo{
		Filename:           apiResp.Filename,
		Size:               apiResp.Size,
		MimeType:           apiResp.MimeType,
		ExpiresAt:          parseTime(apiResp.ExpiresAt),
		PasswordProtected:  apiResp.PasswordProtected,
		DownloadsRemaining: downloadsRemaining,
	}, nil
}

// progressDownloadReader wraps an io.Reader to track download progress.
type progressDownloadReader struct {
	reader     io.Reader
	totalBytes int64
	downloaded int64
	onProgress func(DownloadProgress)
}

func (pr *progressDownloadReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	if n > 0 {
		pr.downloaded += int64(n)
		if pr.onProgress != nil {
			percentage := -1
			if pr.totalBytes > 0 {
				percentage = int(float64(pr.downloaded) / float64(pr.totalBytes) * 100)
			}
			pr.onProgress(DownloadProgress{
				BytesDownloaded: pr.downloaded,
				TotalBytes:      pr.totalBytes,
				Percentage:      percentage,
			})
		}
	}
	return n, err
}
