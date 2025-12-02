package safeshare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// ListFiles retrieves a paginated list of files uploaded by the authenticated user.
// The limit parameter specifies how many files to return (default: 50, max: 100).
// The offset parameter specifies how many files to skip (default: 0).
//
// Example:
//
//	files, err := client.ListFiles(ctx, 50, 0)
//	for _, f := range files.Files {
//	    fmt.Printf("%s: %s (%d bytes)\n", f.ClaimCode, f.Filename, f.Size)
//	}
func (c *Client) ListFiles(ctx context.Context, limit, offset int) (*UserFilesResponse, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}

	path := fmt.Sprintf("/api/user/files?limit=%d&offset=%d", limit, offset)
	resp, err := c.request(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return nil, err
	}

	var apiResp apiUserFilesResponse
	if err := handleResponse(resp, &apiResp); err != nil {
		return nil, err
	}

	files := make([]UserFile, len(apiResp.Files))
	for i, f := range apiResp.Files {
		files[i] = UserFile{
			ID:                 f.ID,
			ClaimCode:          f.ClaimCode,
			Filename:           f.OriginalFilename,
			Size:               f.FileSize,
			MimeType:           f.MimeType,
			UploadedAt:         parseTimeRequired(f.CreatedAt),
			ExpiresAt:          parseTimeNonPointer(f.ExpiresAt),
			CompletedDownloads: f.CompletedDownloads,
			DownloadCount:      f.DownloadCount,
			DownloadLimit:      f.MaxDownloads,
			PasswordProtected:  f.PasswordProtected,
		}
	}

	// Calculate page info for backward compatibility
	page := 0
	if limit > 0 {
		page = offset / limit
	}

	return &UserFilesResponse{
		Files:   files,
		Total:   apiResp.Total,
		Page:    page,
		PerPage: limit,
	}, nil
}

// DeleteFile deletes a file by claim code.
//
// Example:
//
//	err := client.DeleteFile(ctx, "abc12345")
func (c *Client) DeleteFile(ctx context.Context, claimCode string) error {
	if err := validateClaimCode(claimCode); err != nil {
		return err
	}

	resp, err := c.request(ctx, http.MethodDelete, fmt.Sprintf("/api/user/files/%s", claimCode), nil, "")
	if err != nil {
		return err
	}

	return handleResponse(resp, nil)
}

// RenameResult represents the result of a rename operation.
type RenameResult struct {
	Message     string `json:"message"`
	NewFilename string `json:"new_filename"`
}

// RenameFile renames a file.
// Note: The API returns a simple message response, not the full file object.
//
// Example:
//
//	result, err := client.RenameFile(ctx, "abc12345", "new-name.pdf")
//	fmt.Printf("Renamed to: %s\n", result.NewFilename)
func (c *Client) RenameFile(ctx context.Context, claimCode, newFilename string) (*RenameResult, error) {
	if err := validateClaimCode(claimCode); err != nil {
		return nil, err
	}
	if err := validateFilename(newFilename); err != nil {
		return nil, err
	}

	// The API expects file_id + new_filename, but the SDK uses claim code
	// The rename endpoint at /api/user/files/rename expects JSON body with file_id
	// For now, we need to send the request as the API expects
	body, err := json.Marshal(map[string]string{"filename": newFilename})
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.request(ctx, http.MethodPut, fmt.Sprintf("/api/user/files/%s/rename", claimCode), bytes.NewReader(body), "application/json")
	if err != nil {
		return nil, err
	}

	var apiResp RenameResult
	if err := handleResponse(resp, &apiResp); err != nil {
		return nil, err
	}

	return &apiResp, nil
}

// ExpirationResult represents the result of an expiration update operation.
type ExpirationResult struct {
	Message       string `json:"message"`
	NewExpiration string `json:"new_expiration"`
}

// UpdateExpiration updates a file's expiration time.
// Set expiresInHours to nil to remove expiration.
// Note: The API returns a simple message response, not the full file object.
//
// Example:
//
//	hours := 48
//	result, err := client.UpdateExpiration(ctx, "abc12345", &hours)
//	fmt.Printf("New expiration: %s\n", result.NewExpiration)
func (c *Client) UpdateExpiration(ctx context.Context, claimCode string, expiresInHours *int) (*ExpirationResult, error) {
	if err := validateClaimCode(claimCode); err != nil {
		return nil, err
	}

	body, err := json.Marshal(map[string]interface{}{"expires_in_hours": expiresInHours})
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.request(ctx, http.MethodPut, fmt.Sprintf("/api/user/files/%s/expiration", claimCode), bytes.NewReader(body), "application/json")
	if err != nil {
		return nil, err
	}

	var apiResp ExpirationResult
	if err := handleResponse(resp, &apiResp); err != nil {
		return nil, err
	}

	return &apiResp, nil
}

// RegenerateResult represents the result of a claim code regeneration.
type RegenerateResult struct {
	Message     string `json:"message"`
	ClaimCode   string `json:"claim_code"`
	DownloadURL string `json:"download_url"`
}

// RegenerateClaimCode generates a new claim code for a file.
// The old claim code will no longer work.
// Note: The API returns the new claim code and download URL.
//
// Example:
//
//	result, err := client.RegenerateClaimCode(ctx, "oldcode123")
//	fmt.Printf("New claim code: %s\n", result.ClaimCode)
func (c *Client) RegenerateClaimCode(ctx context.Context, claimCode string) (*RegenerateResult, error) {
	if err := validateClaimCode(claimCode); err != nil {
		return nil, err
	}

	resp, err := c.request(ctx, http.MethodPost, fmt.Sprintf("/api/user/files/%s/regenerate", claimCode), nil, "")
	if err != nil {
		return nil, err
	}

	var apiResp RegenerateResult
	if err := handleResponse(resp, &apiResp); err != nil {
		return nil, err
	}

	return &apiResp, nil
}
