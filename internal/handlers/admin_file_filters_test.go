package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/repository/sqlite"
	"github.com/fjmerc/safeshare/internal/testutil"
)

type adminFilterEnv struct {
	repos   *repository.Repositories
	handler http.HandlerFunc
	alice   int64
}

// newAdminFilterEnv seeds alice (two files), bob (one) and two anonymous files.
func newAdminFilterEnv(t *testing.T) *adminFilterEnv {
	t.Helper()
	db := testutil.SetupTestDB(t)
	cfg := testutil.SetupTestConfig(t)
	repos, err := sqlite.NewRepositories(cfg, db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	ctx := context.Background()
	alice, err := repos.Users.Create(ctx, "alice", "alice@example.com", "hash", "user", false)
	if err != nil {
		t.Fatalf("create alice: %v", err)
	}
	bob, err := repos.Users.Create(ctx, "bob", "bob@example.com", "hash", "user", false)
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}
	for i, fx := range []struct {
		code string
		user *int64
		size int64
	}{
		{"AliceSmall01", &alice.ID, 100},
		{"AliceLarge01", &alice.ID, 5 << 20},
		{"BobFile00001", &bob.ID, 2 << 20},
		{"AnonFile0001", nil, 300},
		{"AnonFile0002", nil, 400},
	} {
		if err := repos.Files.Create(ctx, &models.File{
			ClaimCode:        fx.code,
			OriginalFilename: fx.code + ".txt",
			StoredFilename:   fx.code + ".dat",
			FileSize:         fx.size,
			MimeType:         "text/plain",
			CreatedAt:        time.Now().Add(-time.Duration(i+1) * time.Minute),
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "127.0.0.1",
			UserID:           fx.user,
		}); err != nil {
			t.Fatalf("create %s: %v", fx.code, err)
		}
	}
	return &adminFilterEnv{repos: repos, handler: AdminDashboardDataHandler(repos, cfg), alice: alice.ID}
}

type adminDashboardResp struct {
	Files []struct {
		ClaimCode string `json:"claim_code"`
	} `json:"files"`
	Pagination struct {
		Total           int `json:"total"`
		UnfilteredTotal int `json:"unfiltered_total"`
	} `json:"pagination"`
	Stats map[string]interface{} `json:"stats"`
}

func (e *adminFilterEnv) get(t *testing.T, query string) (*httptest.ResponseRecorder, adminDashboardResp) {
	t.Helper()
	rr := httptest.NewRecorder()
	e.handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/api/dashboard?"+query, nil))
	var resp adminDashboardResp
	if rr.Code == http.StatusOK {
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
	}
	return rr, resp
}

func codesOf(resp adminDashboardResp) []string {
	out := []string{}
	for _, f := range resp.Files {
		out = append(out, f.ClaimCode)
	}
	return out
}

func TestAdminDashboardDataHandler_Filters(t *testing.T) {
	e := newAdminFilterEnv(t)
	aliceID := strconv.FormatInt(e.alice, 10)

	tests := []struct {
		query string
		want  []string
	}{
		{"", []string{"AliceSmall01", "AliceLarge01", "BobFile00001", "AnonFile0001", "AnonFile0002"}},
		{"user_id=" + aliceID, []string{"AliceSmall01", "AliceLarge01"}},
		{"user=anonymous", []string{"AnonFile0001", "AnonFile0002"}},
		{"min_size=1048576", []string{"AliceLarge01", "BobFile00001"}},
		{"max_size=1048576&sort=largest", []string{"AnonFile0002", "AnonFile0001", "AliceSmall01"}},
		{"user_id=" + aliceID + "&min_size=1048576&max_size=10485760", []string{"AliceLarge01"}},
		{"search=anon&sort=oldest", []string{"AnonFile0002", "AnonFile0001"}},
		{"search=bob&user=anonymous", []string{}},
		{"status=active&scan=not_scanned&uploaded=24h", []string{"AliceSmall01", "AliceLarge01", "BobFile00001", "AnonFile0001", "AnonFile0002"}},
		{"uploaded=older_30d", []string{}},
		{"sort=smallest", []string{"AliceSmall01", "AnonFile0001", "AnonFile0002", "BobFile00001", "AliceLarge01"}},
	}
	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			rr, resp := e.get(t, tt.query)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d (%s)", rr.Code, rr.Body.String())
			}
			if got := codesOf(resp); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("files = %v, want %v", got, tt.want)
			}
			if resp.Pagination.Total != len(tt.want) {
				t.Errorf("total = %d, want %d", resp.Pagination.Total, len(tt.want))
			}
			if resp.Pagination.UnfilteredTotal != 5 {
				t.Errorf("unfiltered_total = %d, want 5", resp.Pagination.UnfilteredTotal)
			}
		})
	}
}

func TestAdminDashboardDataHandler_FiltersPaginate(t *testing.T) {
	e := newAdminFilterEnv(t)
	_, resp := e.get(t, "user=anonymous&page=2&page_size=1")
	if got := codesOf(resp); !reflect.DeepEqual(got, []string{"AnonFile0002"}) || resp.Pagination.Total != 2 {
		t.Errorf("page 2 = %v (total %d), want [AnonFile0002] of 2", got, resp.Pagination.Total)
	}
}

func TestAdminDashboardDataHandler_FiltersLeaveStatsAlone(t *testing.T) {
	e := newAdminFilterEnv(t)
	_, all := e.get(t, "")
	_, filtered := e.get(t, "user=anonymous&min_size=350&search=anon")
	if len(filtered.Files) != 1 {
		t.Fatalf("filtered files = %v, want one", codesOf(filtered))
	}
	if !reflect.DeepEqual(all.Stats, filtered.Stats) {
		t.Errorf("stats changed with filters:\n%v\n%v", all.Stats, filtered.Stats)
	}
	if all.Stats["total_files"] != float64(5) {
		t.Errorf("stats.total_files = %v, want 5", all.Stats["total_files"])
	}
}

func TestAdminDashboardDataHandler_InvalidFilters(t *testing.T) {
	e := newAdminFilterEnv(t)
	for query, wantMsg := range map[string]string{
		"status=expired":                "Invalid status",
		"scan=skipped":                  "Invalid scan",
		"sort=created_at":               "Invalid sort",
		"uploaded=1y":                   "Invalid uploaded",
		"user=alice":                    "Invalid user",
		"user_id=0":                     "Invalid user_id",
		"user_id=-3":                    "Invalid user_id",
		"user_id=abc":                   "Invalid user_id",
		"user=anonymous&user_id=1":      "can't be combined",
		"min_size=-1":                   "Invalid min_size",
		"max_size=1.5":                  "Invalid max_size",
		"max_size=0":                    "Invalid max_size",
		"min_size=10&max_size=10":       "Invalid size range",
		"min_size=99999999999999999999": "Invalid min_size",
	} {
		t.Run(query, func(t *testing.T) {
			rr, _ := e.get(t, query)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rr.Code)
			}
			if !strings.Contains(rr.Body.String(), wantMsg) {
				t.Errorf("body = %q, want it to mention %q", rr.Body.String(), wantMsg)
			}
		})
	}
}

func TestAdminFileUploadersHandler(t *testing.T) {
	e := newAdminFilterEnv(t)
	if _, err := e.repos.Users.Create(context.Background(), "carol", "carol@example.com", "hash", "user", false); err != nil {
		t.Fatalf("create carol: %v", err)
	}
	rr := httptest.NewRecorder()
	AdminFileUploadersHandler(e.repos).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/api/files/uploaders", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var got map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := map[string]interface{}{
		"anonymous_count": float64(2),
		"users": []interface{}{
			map[string]interface{}{"user_id": float64(e.alice), "username": "alice", "file_count": float64(2)},
			map[string]interface{}{"user_id": float64(e.alice + 1), "username": "bob", "file_count": float64(1)},
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v\nwant %v", got, want)
	}
}

func TestAdminFileUploadersHandler_NoFiles(t *testing.T) {
	db := testutil.SetupTestDB(t)
	repos, err := sqlite.NewRepositories(testutil.SetupTestConfig(t), db)
	if err != nil {
		t.Fatalf("failed to create repositories: %v", err)
	}
	rr := httptest.NewRecorder()
	AdminFileUploadersHandler(repos).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/api/files/uploaders", nil))
	if body := strings.TrimSpace(rr.Body.String()); body != `{"anonymous_count":0,"users":[]}` {
		t.Errorf("body = %s", body)
	}
}

func TestAdminFileUploadersHandler_MethodNotAllowed(t *testing.T) {
	e := newAdminFilterEnv(t)
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		rr := httptest.NewRecorder()
		AdminFileUploadersHandler(e.repos).ServeHTTP(rr, httptest.NewRequest(method, "/admin/api/files/uploaders", nil))
		if rr.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s: status = %d, want 405", method, rr.Code)
		}
	}
}
