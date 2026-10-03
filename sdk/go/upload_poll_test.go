package safeshare

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// T52: a 429 from the status endpoint while an upload assembles must not
// abort the upload - the claim code is only ever returned by that endpoint.
func TestPollForCompletion_RateLimitedStatusKeepsPolling(t *testing.T) {
	oldMin, oldMax := rateLimitPollMinWait, rateLimitPollMaxWait
	rateLimitPollMinWait, rateLimitPollMaxWait = 10*time.Millisecond, 50*time.Millisecond
	defer func() { rateLimitPollMinWait, rateLimitPollMaxWait = oldMin, oldMax }()

	const uploadID = "550e8400-e29b-41d4-a716-446655440052"
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/upload/status/"+uploadID {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if polls.Add(1) <= 3 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"error":"Rate limit exceeded","code":"RATE_LIMITED"}`)
			return
		}
		fmt.Fprintf(w, `{"upload_id":%q,"status":"completed","claim_code":"AbCdEfGh12345678","expires_at":"2030-01-01T00:00:00Z"}`, uploadID)
	}))
	defer srv.Close()

	c, err := NewClient(ClientConfig{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.pollForCompletion(context.Background(), uploadID, "f.bin", 10, &UploadOptions{})
	if err != nil {
		t.Fatalf("pollForCompletion = %v, want success after rate-limited polls", err)
	}
	if res.ClaimCode != "AbCdEfGh12345678" {
		t.Errorf("ClaimCode = %q", res.ClaimCode)
	}
	if got := polls.Load(); got != 4 {
		t.Errorf("status polls = %d, want 4", got)
	}
}

func TestRateLimitPollDelay(t *testing.T) {
	for _, tc := range []struct {
		retryAfter time.Duration
		want       time.Duration
	}{
		{0, 15 * time.Second},
		{5 * time.Second, 15 * time.Second},
		{30 * time.Second, 30 * time.Second},
		{10 * time.Minute, 60 * time.Second},
	} {
		err := &APIError{StatusCode: 429, Err: ErrRateLimit, RetryAfter: tc.retryAfter}
		if got := rateLimitPollDelay(err); got != tc.want {
			t.Errorf("RetryAfter %v: delay = %v, want %v", tc.retryAfter, got, tc.want)
		}
	}
}
