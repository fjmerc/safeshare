package models

import "time"

// APITokenUsageLog represents a single usage log entry for an API token.
type APITokenUsageLog struct {
	ID             int64     `json:"id"`
	TokenID        int64     `json:"token_id"`
	Timestamp      time.Time `json:"timestamp"`
	Endpoint       string    `json:"endpoint"`
	IPAddress      string    `json:"ip_address"`
	UserAgent      string    `json:"user_agent"`
	ResponseStatus int       `json:"response_status"`
}

// APITokenUsageFilter defines the filter parameters for usage log queries.
type APITokenUsageFilter struct {
	StartDate *time.Time // Filter logs from this date
	EndDate   *time.Time // Filter logs until this date
	Limit     int        // Maximum number of records to return
	Offset    int        // Number of records to skip (for pagination)
}

// APITokenUsageResponse is the paginated response for token usage logs.
type APITokenUsageResponse struct {
	Usage      []APITokenUsageLog `json:"usage"`
	Total      int                `json:"total"`
	Limit      int                `json:"limit"`
	Offset     int                `json:"offset"`
	TokenID    int64              `json:"token_id"`
	TokenName  string             `json:"token_name,omitempty"`
	StartDate  *time.Time         `json:"start_date,omitempty"`
	EndDate    *time.Time         `json:"end_date,omitempty"`
}

// EndpointStat represents usage statistics for a single endpoint.
type EndpointStat struct {
	Endpoint string `json:"endpoint"`
	Count    int64  `json:"count"`
}

// TokenUsageStats provides aggregated usage statistics for an API token.
type TokenUsageStats struct {
	TotalRequests   int64          `json:"total_requests"`
	Last24hRequests int64          `json:"last_24h_requests"`
	UniqueIPs       int64          `json:"unique_ips"`
	TopEndpoints    []EndpointStat `json:"top_endpoints"`
}
