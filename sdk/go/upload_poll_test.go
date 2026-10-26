package safeshare

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// A claim code from the server ends up in links and on the terminal, so one
// that isn't a claim code is refused.
func TestUploadRejectsBadClaimCodeFromServer(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/config":
			_, _ = io.WriteString(w, `{"max_file_size":1048576,"chunked_upload_threshold":1048576,"chunk_size":65536}`)
		case "/api/upload":
			_, _ = io.WriteString(w, `{"claim_code":"abcd1234\u001b]52;c;ZXZpbA==\u0007","original_filename":"a.txt","file_size":5}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	client, err := NewClient(ClientConfig{BaseURL: srv.URL, DisableProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "a.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []EncryptMode{EncryptNever, EncryptAlways} {
		if _, err := client.Upload(context.Background(), path, &UploadOptions{Encrypt: mode}); err == nil || !strings.Contains(err.Error(), "invalid claim code") {
			t.Errorf("mode %v: err = %v", mode, err)
		}
	}
}
