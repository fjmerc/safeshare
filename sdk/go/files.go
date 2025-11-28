package safeshare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// ListFiles retrieves a paginated list of files uploaded by the authenticated user.
//
// Example:
//
//	files, err := client.ListFiles(ctx, 1, 20)
//	for _, f := range files.Files {
//	    fmt.Printf("%s: %s (%d bytes)\n", f.ClaimCode, f.Filename, f.Size)
//	}
func (c *Client) ListFiles(ctx context.Context, page, perPage int) (*UserFilesResponse, error) {
	if err := validatePagination(page, perPage); err != nil {
		return nil, err
	}

	path := fmt.Sprintf("/api/user/files?page=%d&per_page=%d", page, perPage)
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
			ID:                f.ID,
			ClaimCode:         f.ClaimCode,
			Filename:          f.Filename,
			Size:              f.Size,
			MimeType:          f.MimeType,
			UploadedAt:        parseTimeRequired(f.UploadedAt),
			ExpiresAt:         parseTime(f.ExpiresAt),
			DownloadCount:     f.DownloadCount,
			DownloadLimit:     f.DownloadLimit,
			PasswordProtected: f.PasswordProtected,
		}
	}

	return &UserFilesResponse{
		Files:   files,
		Total:   apiResp.Total,
		Page:    apiResp.Page,
		PerPage: apiResp.PerPage,
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

// RenameFile renames a file.
//
// Example:
//
//	file, err := client.RenameFile(ctx, "abc12345", "new-name.pdf")
func (c *Client) RenameFile(ctx context.Context, claimCode, newFilename string) (*UserFile, error) {
	if err := validateClaimCode(claimCode); err != nil {
		return nil, err
	}
	if err := validateFilename(newFilename); err != nil {
		return nil, err
	}

	body, err := json.Marshal(map[string]string{"filename": newFilename})
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.request(ctx, http.MethodPut, fmt.Sprintf("/api/user/files/%s/rename", claimCode), bytes.NewReader(body), "application/json")
	if err != nil {
		return nil, err
	}

	var apiResp apiUserFileResponse
	if err := handleResponse(resp, &apiResp); err != nil {
		return nil, err
	}

	return &UserFile{
		ID:                apiResp.ID,
		ClaimCode:         apiResp.ClaimCode,
		Filename:          apiResp.Filename,
		Size:              apiResp.Size,
		MimeType:          apiResp.MimeType,
		UploadedAt:        parseTimeRequired(apiResp.UploadedAt),
		ExpiresAt:         parseTime(apiResp.ExpiresAt),
		DownloadCount:     apiResp.DownloadCount,
		DownloadLimit:     apiResp.DownloadLimit,
		PasswordProtected: apiResp.PasswordProtected,
	}, nil
}

// UpdateExpiration updates a file's expiration time.
// Set expiresInHours to nil to remove expiration.
//
// Example:
//
//	hours := 48
//	file, err := client.UpdateExpiration(ctx, "abc12345", &hours)
func (c *Client) UpdateExpiration(ctx context.Context, claimCode string, expiresInHours *int) (*UserFile, error) {
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

	var apiResp apiUserFileResponse
	if err := handleResponse(resp, &apiResp); err != nil {
		return nil, err
	}

	return &UserFile{
		ID:                apiResp.ID,
		ClaimCode:         apiResp.ClaimCode,
		Filename:          apiResp.Filename,
		Size:              apiResp.Size,
		MimeType:          apiResp.MimeType,
		UploadedAt:        parseTimeRequired(apiResp.UploadedAt),
		ExpiresAt:         parseTime(apiResp.ExpiresAt),
		DownloadCount:     apiResp.DownloadCount,
		DownloadLimit:     apiResp.DownloadLimit,
		PasswordProtected: apiResp.PasswordProtected,
	}, nil
}

// RegenerateClaimCode generates a new claim code for a file.
// The old claim code will no longer work.
//
// Example:
//
//	file, err := client.RegenerateClaimCode(ctx, "oldcode123")
//	fmt.Printf("New claim code: %s\n", file.ClaimCode)
func (c *Client) RegenerateClaimCode(ctx context.Context, claimCode string) (*UserFile, error) {
	if err := validateClaimCode(claimCode); err != nil {
		return nil, err
	}

	resp, err := c.request(ctx, http.MethodPost, fmt.Sprintf("/api/user/files/%s/regenerate", claimCode), nil, "")
	if err != nil {
		return nil, err
	}

	var apiResp apiUserFileResponse
	if err := handleResponse(resp, &apiResp); err != nil {
		return nil, err
	}

	return &UserFile{
		ID:                apiResp.ID,
		ClaimCode:         apiResp.ClaimCode,
		Filename:          apiResp.Filename,
		Size:              apiResp.Size,
		MimeType:          apiResp.MimeType,
		UploadedAt:        parseTimeRequired(apiResp.UploadedAt),
		ExpiresAt:         parseTime(apiResp.ExpiresAt),
		DownloadCount:     apiResp.DownloadCount,
		DownloadLimit:     apiResp.DownloadLimit,
		PasswordProtected: apiResp.PasswordProtected,
	}, nil
}
