package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

// tokenUsagePathRegex matches /admin/api/tokens/{id}/usage where id is numeric
var tokenUsagePathRegex = regexp.MustCompile(`^/admin/api/tokens/([0-9]+)/usage/?$`)

// Handler-level validation limits (defense-in-depth)
const (
	maxUsageLimit  = 1000
	maxUsageOffset = 100000
)

// AdminGetTokenUsageHandler returns paginated usage logs for a specific API token.
// GET /admin/api/tokens/{id}/usage
// Query parameters:
//   - limit: maximum number of records (default: 50, max: 1000)
//   - offset: number of records to skip (default: 0)
//   - start_date: filter logs from this date (RFC3339 format)
//   - end_date: filter logs until this date (RFC3339 format)
func AdminGetTokenUsageHandler(repos *repository.Repositories) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		ctx := r.Context()

		// Parse token ID from path using regex
		matches := tokenUsagePathRegex.FindStringSubmatch(r.URL.Path)
		if len(matches) != 2 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid request path",
				"code":  "INVALID_PATH",
			})
			return
		}

		tokenID, err := strconv.ParseInt(matches[1], 10, 64)
		if err != nil || tokenID <= 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Invalid token ID",
				"code":  "INVALID_TOKEN_ID",
			})
			return
		}

		// Verify token exists
		token, err := repos.APITokens.GetByID(ctx, tokenID)
		if err != nil {
			slog.Error("failed to get token", "error", err, "token_id", tokenID)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if token == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			json.NewEncoder(w).Encode(map[string]string{
				"error": "Token not found",
				"code":  "TOKEN_NOT_FOUND",
			})
			return
		}

		// Parse query parameters with handler-level validation
		filter := repository.UsageFilter{
			Limit:  50, // Default
			Offset: 0,
		}

		if l := r.URL.Query().Get("limit"); l != "" {
			if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
				if parsed > maxUsageLimit {
					parsed = maxUsageLimit
				}
				filter.Limit = parsed
			}
		}

		if o := r.URL.Query().Get("offset"); o != "" {
			if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
				if parsed > maxUsageOffset {
					parsed = maxUsageOffset
				}
				filter.Offset = parsed
			}
		}

		// Parse date filters
		if sd := r.URL.Query().Get("start_date"); sd != "" {
			t, err := time.Parse(time.RFC3339, sd)
			if err != nil {
				// Try parsing without timezone
				t, err = time.Parse("2006-01-02", sd)
				if err != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{
						"error": "Invalid start_date format. Use RFC3339 (e.g., 2024-01-01T00:00:00Z) or YYYY-MM-DD",
						"code":  "INVALID_START_DATE",
					})
					return
				}
			}
			filter.StartDate = &t
		}

		if ed := r.URL.Query().Get("end_date"); ed != "" {
			t, err := time.Parse(time.RFC3339, ed)
			if err != nil {
				// Try parsing without timezone
				t, err = time.Parse("2006-01-02", ed)
				if err != nil {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusBadRequest)
					json.NewEncoder(w).Encode(map[string]string{
						"error": "Invalid end_date format. Use RFC3339 (e.g., 2024-01-01T23:59:59Z) or YYYY-MM-DD",
						"code":  "INVALID_END_DATE",
					})
					return
				}
				// If only date is provided, set to end of day
				t = t.Add(23*time.Hour + 59*time.Minute + 59*time.Second)
			}
			filter.EndDate = &t
		}

		// Validate date range (start_date must be before end_date)
		if filter.StartDate != nil && filter.EndDate != nil {
			if filter.StartDate.After(*filter.EndDate) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{
					"error": "start_date must be before end_date",
					"code":  "INVALID_DATE_RANGE",
				})
				return
			}
		}

		// Get usage logs
		logs, total, err := repos.APITokens.GetUsageLogs(ctx, tokenID, filter)
		if err != nil {
			slog.Error("failed to get token usage logs",
				"error", err,
				"token_id", tokenID,
			)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Ensure we return empty array instead of null
		if logs == nil {
			logs = []models.APITokenUsageLog{}
		}

		// Build response
		response := models.APITokenUsageResponse{
			Usage:     logs,
			Total:     total,
			Limit:     filter.Limit,
			Offset:    filter.Offset,
			TokenID:   tokenID,
			TokenName: token.Name,
			StartDate: filter.StartDate,
			EndDate:   filter.EndDate,
		}

		slog.Debug("admin retrieved token usage logs",
			"token_id", tokenID,
			"token_name", token.Name,
			"count", len(logs),
			"total", total,
		)

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store, max-age=0")
		json.NewEncoder(w).Encode(response)
	}
}

// IsTokenUsagePath checks if a path matches the token usage endpoint pattern.
// Exported for use in route registration.
func IsTokenUsagePath(path string) bool {
	return tokenUsagePathRegex.MatchString(path)
}
