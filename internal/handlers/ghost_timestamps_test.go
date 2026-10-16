package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

func onHourUTC(t time.Time) bool {
	return t.Equal(t.UTC().Truncate(time.Hour))
}

// uploadAndFetch uploads a small file with the given expiry and returns the
// stored record plus the wall-clock window around the request.
func uploadAndFetch(t *testing.T, e *ghostEnv, hours string) (*models.File, time.Time, time.Time) {
	t.Helper()
	before := time.Now()
	rr := postUpload(t, UploadHandler(e.repos, e.cfg), []byte("timestamp test"), "t.txt",
		map[string]string{"expires_in_hours": hours})
	after := time.Now()
	if rr.Code != http.StatusCreated {
		t.Fatalf("upload status = %d; %s", rr.Code, rr.Body.String())
	}
	var resp models.UploadResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	f, err := e.repos.Files.GetByClaimCode(context.Background(), resp.ClaimCode)
	if err != nil || f == nil {
		t.Fatalf("lookup: %v %v", f, err)
	}
	return f, before, after
}

func TestAnonymousMode_UploadStoresRoundedTimes(t *testing.T) {
	e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true", "REQUIRE_CLIENT_ENCRYPTION": "false"})
	f, before, after := uploadAndFetch(t, e, "24")

	if !onHourUTC(f.CreatedAt) {
		t.Errorf("created_at = %v, want on a UTC hour boundary", f.CreatedAt)
	}
	// Rounded down: within the hour before the request, never in the future.
	if f.CreatedAt.After(after) || before.Sub(f.CreatedAt) >= time.Hour+time.Second {
		t.Errorf("created_at = %v not within the hour preceding the upload (%v..%v)", f.CreatedAt, before, after)
	}
	if !onHourUTC(f.ExpiresAt) {
		t.Errorf("expires_at = %v, want on a UTC hour boundary", f.ExpiresAt)
	}
	// Expiry must never be shortened: stored >= the earliest possible true
	// expiry (request start + 24h), and less than an hour past the latest.
	trueMin := before.Add(24 * time.Hour)
	if f.ExpiresAt.Before(trueMin.Truncate(time.Second)) {
		t.Errorf("expires_at %v is earlier than the real expiry %v (file would expire early)", f.ExpiresAt, trueMin)
	}
	if f.ExpiresAt.After(after.Add(24*time.Hour + time.Hour)) {
		t.Errorf("expires_at %v extended by more than an hour", f.ExpiresAt)
	}
}

func TestAnonymousMode_NeverExpireStillFarFuture(t *testing.T) {
	e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true", "REQUIRE_CLIENT_ENCRYPTION": "false"})
	f, before, _ := uploadAndFetch(t, e, "0")
	if f.ExpiresAt.Before(before.Add(99 * 365 * 24 * time.Hour)) {
		t.Errorf("never-expire file got expires_at %v", f.ExpiresAt)
	}
	if !onHourUTC(f.ExpiresAt) {
		t.Errorf("expires_at = %v, want on a UTC hour boundary", f.ExpiresAt)
	}
}

func TestNormalMode_UploadKeepsExactTimes(t *testing.T) {
	e := newGhostEnv(t, map[string]string{"REQUIRE_CLIENT_ENCRYPTION": "false"})
	f, before, after := uploadAndFetch(t, e, "24")

	// Exact (second-precision) times, as before this feature.
	if f.CreatedAt.Before(before.Add(-2*time.Second)) || f.CreatedAt.After(after.Add(2*time.Second)) {
		t.Errorf("created_at = %v, want within [%v, %v]", f.CreatedAt, before, after)
	}
	wantMin := before.Add(24 * time.Hour).Add(-2 * time.Second)
	wantMax := after.Add(24 * time.Hour).Add(2 * time.Second)
	if f.ExpiresAt.Before(wantMin) || f.ExpiresAt.After(wantMax) {
		t.Errorf("expires_at = %v, want within [%v, %v]", f.ExpiresAt, wantMin, wantMax)
	}
}

func TestAnonymousMode_DownloadStoresNoExactTimestamp(t *testing.T) {
	e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true", "REQUIRE_CLIENT_ENCRYPTION": "false"})
	f, _, _ := uploadAndFetch(t, e, "24")

	req := httptest.NewRequest(http.MethodGet, "/api/claim/"+f.ClaimCode, nil)
	rr := httptest.NewRecorder()
	ClaimHandler(e.repos, e.cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("download status = %d; %s", rr.Code, rr.Body.String())
	}

	after, err := e.repos.Files.GetByClaimCode(context.Background(), f.ClaimCode)
	if err != nil || after == nil {
		t.Fatalf("lookup after download: %v %v", after, err)
	}
	if after.DownloadCount != 1 {
		t.Fatalf("download_count = %d, want 1 (download did not register)", after.DownloadCount)
	}
	// No time column on the file record may change or become exact.
	if !after.CreatedAt.Equal(f.CreatedAt) || !after.ExpiresAt.Equal(f.ExpiresAt) {
		t.Errorf("download altered file times: created %v->%v expires %v->%v",
			f.CreatedAt, after.CreatedAt, f.ExpiresAt, after.ExpiresAt)
	}
	if !onHourUTC(after.CreatedAt) || !onHourUTC(after.ExpiresAt) {
		t.Errorf("file record holds a non-rounded time after download: %v / %v", after.CreatedAt, after.ExpiresAt)
	}
	if after.ScannedAt != nil && !onHourUTC(*after.ScannedAt) {
		t.Errorf("scanned_at = %v, want rounded", *after.ScannedAt)
	}
}

func TestStoreHelpers_ModeSwitch(t *testing.T) {
	e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true"})
	n := newGhostEnv(t, nil)
	in := time.Date(2026, 10, 16, 14, 59, 59, 0, time.UTC)
	if got := storeExpiry(in, e.cfg); got.Before(in) || !onHourUTC(got) {
		t.Errorf("anon storeExpiry(%v) = %v", in, got)
	}
	if got := storeExpiry(in, n.cfg); !got.Equal(in) {
		t.Errorf("normal storeExpiry(%v) = %v, want unchanged", in, got)
	}
	if !storeCreatedAt(n.cfg).IsZero() {
		t.Error("normal mode storeCreatedAt must be zero so the database stamps the row")
	}
	if got := storeCreatedAt(e.cfg); got.IsZero() || !onHourUTC(got) {
		t.Errorf("anon storeCreatedAt = %v, want hour-rounded", got)
	}
}
