package safeshare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// CreateToken creates a new API token.
// Note: Token creation typically requires session authentication, not API token auth.
//
// The returned token value is only shown once - store it securely!
//
// Example:
//
//	token, err := client.CreateToken(ctx, safeshare.CreateTokenRequest{
//	    Name:          "Automation Token",
//	    Scopes:        []string{"upload", "download", "manage"},
//	    ExpiresInDays: intPtr(90),
//	})
//	fmt.Printf("Token (save this!): %s\n", token.Token)
func (c *Client) CreateToken(ctx context.Context, req CreateTokenRequest) (*TokenCreatedResponse, error) {
	body, err := json.Marshal(map[string]interface{}{
		"name":            req.Name,
		"scopes":          req.Scopes,
		"expires_in_days": req.ExpiresInDays,
	})
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	resp, err := c.request(ctx, http.MethodPost, "/api/tokens", bytes.NewReader(body), "application/json")
	if err != nil {
		return nil, err
	}

	var apiResp apiTokenCreatedResponse
	if err := handleResponse(resp, &apiResp); err != nil {
		return nil, err
	}

	return &TokenCreatedResponse{
		Token:     apiResp.Token,
		Name:      apiResp.Name,
		Scopes:    apiResp.Scopes,
		ExpiresAt: parseTime(apiResp.ExpiresAt),
		CreatedAt: parseTimeRequired(apiResp.CreatedAt),
	}, nil
}

// ListTokens retrieves all API tokens for the authenticated user.
//
// Example:
//
//	tokens, err := client.ListTokens(ctx)
//	for _, t := range tokens {
//	    fmt.Printf("%s: %v (last used: %v)\n", t.Name, t.Scopes, t.LastUsedAt)
//	}
func (c *Client) ListTokens(ctx context.Context) ([]TokenInfo, error) {
	resp, err := c.request(ctx, http.MethodGet, "/api/tokens", nil, "")
	if err != nil {
		return nil, err
	}

	var apiResp apiTokenListResponse
	if err := handleResponse(resp, &apiResp); err != nil {
		return nil, err
	}

	tokens := make([]TokenInfo, len(apiResp.Tokens))
	for i, t := range apiResp.Tokens {
		tokens[i] = TokenInfo{
			ID:         t.ID,
			Name:       t.Name,
			Scopes:     t.Scopes,
			ExpiresAt:  parseTime(t.ExpiresAt),
			CreatedAt:  parseTimeRequired(t.CreatedAt),
			LastUsedAt: parseTime(t.LastUsedAt),
		}
	}

	return tokens, nil
}

// RevokeToken revokes an API token by ID.
// Note: Token revocation typically requires session authentication, not API token auth.
//
// Example:
//
//	err := client.RevokeToken(ctx, 123)
func (c *Client) RevokeToken(ctx context.Context, tokenID int) error {
	if err := validateTokenID(tokenID); err != nil {
		return err
	}

	resp, err := c.request(ctx, http.MethodDelete, fmt.Sprintf("/api/tokens/%d", tokenID), nil, "")
	if err != nil {
		return err
	}

	return handleResponse(resp, nil)
}
