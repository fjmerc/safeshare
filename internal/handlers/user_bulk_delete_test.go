package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
)

type bulkDeleteResp struct {
	RequestedCount int     `json:"requested_count"`
	DeletedCount   int     `json:"deleted_count"`
	Deleted        []int64 `json:"deleted"`
	Failed         []struct {
		FileID int64  `json:"file_id"`
		Error  string `json:"error"`
	} `json:"failed"`
}

func bulkDeleteReq(e *ghostEnv, user *models.User, method, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "/api/user/files/delete/bulk", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if user != nil {
		r = r.WithContext(context.WithValue(r.Context(), middleware.ContextKeyUser, user))
	}
	rr := httptest.NewRecorder()
	UserBulkDeleteFilesHandler(e.repos, e.cfg).ServeHTTP(rr, r)
	return rr
}

func idsBody(ids ...int64) string {
	b, _ := json.Marshal(map[string][]int64{"file_ids": ids})
	return string(b)
}

func fileGone(t *testing.T, e *ghostEnv, f *models.File) bool {
	t.Helper()
	got, err := e.repos.Files.GetByID(context.Background(), f.ID)
	if err != nil && !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("get %d: %v", f.ID, err)
	}
	_, statErr := os.Stat(filepath.Join(e.cfg.UploadDir, f.StoredFilename))
	return got == nil && os.IsNotExist(statErr)
}

func TestUserBulkDelete_DeletesOwnedFiles(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice := ownerUser(t, e, "alice")
	a := ownedFile(t, e, alice, "bulkA0001", "a", nil)
	b := ownedFile(t, e, alice, "bulkB0001", "b", nil)
	keep := ownedFile(t, e, alice, "bulkK0001", "k", nil)

	rr := bulkDeleteReq(e, alice, http.MethodPost, idsBody(a.ID, b.ID))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	var resp bulkDeleteResp
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.RequestedCount != 2 || resp.DeletedCount != 2 || len(resp.Deleted) != 2 || len(resp.Failed) != 0 {
		t.Errorf("resp = %+v", resp)
	}
	if !fileGone(t, e, a) || !fileGone(t, e, b) {
		t.Error("selected files still present")
	}
	if fileGone(t, e, keep) {
		t.Error("unselected file was deleted")
	}
}

func TestUserBulkDelete_PartialFailure(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice, bob := ownerUser(t, e, "alice"), ownerUser(t, e, "bob")
	mine := ownedFile(t, e, alice, "bulkM0001", "m", nil)
	theirs := ownedFile(t, e, bob, "bulkT0001", "t", nil)

	rr := bulkDeleteReq(e, alice, http.MethodPost, idsBody(mine.ID, theirs.ID, 999999))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d %s", rr.Code, rr.Body.String())
	}
	var resp bulkDeleteResp
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.RequestedCount != 3 || resp.DeletedCount != 1 || len(resp.Failed) != 2 {
		t.Fatalf("resp = %+v", resp)
	}
	if resp.Deleted[0] != mine.ID {
		t.Errorf("deleted = %v, want [%d]", resp.Deleted, mine.ID)
	}
	failed := map[int64]bool{}
	for _, f := range resp.Failed {
		failed[f.FileID] = true
		if f.Error == "" {
			t.Errorf("failure %d has no message", f.FileID)
		}
	}
	if !failed[theirs.ID] || !failed[999999] {
		t.Errorf("failed = %+v", resp.Failed)
	}
	if fileGone(t, e, theirs) {
		t.Error("another user's file was deleted")
	}
}

func TestUserBulkDelete_SkipsBundleMembers(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice := ownerUser(t, e, "alice")
	b := ownedBundle(t, e, alice, "one", "two")
	members, err := e.repos.Bundles.ListMembers(context.Background(), b.BundleID)
	if err != nil || len(members) != 2 {
		t.Fatalf("members: %v %d", err, len(members))
	}
	rr := bulkDeleteReq(e, alice, http.MethodPost, idsBody(members[0].ID))
	var resp bulkDeleteResp
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if rr.Code != http.StatusOK || resp.DeletedCount != 0 || len(resp.Failed) != 1 {
		t.Fatalf("status %d resp %+v", rr.Code, resp)
	}
	if got, err := e.repos.Files.GetByID(context.Background(), members[0].ID); err != nil || got == nil {
		t.Error("bundle member was deleted on its own")
	}
}

func TestUserBulkDelete_DuplicateIDsCountOnce(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice := ownerUser(t, e, "alice")
	a := ownedFile(t, e, alice, "bulkD0001", "d", nil)
	rr := bulkDeleteReq(e, alice, http.MethodPost, idsBody(a.ID, a.ID))
	var resp bulkDeleteResp
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if rr.Code != http.StatusOK || resp.RequestedCount != 1 || resp.DeletedCount != 1 || len(resp.Failed) != 0 {
		t.Errorf("status %d resp %+v", rr.Code, resp)
	}
}

func TestUserBulkDelete_RejectsBadRequests(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice := ownerUser(t, e, "alice")
	tooMany := make([]int64, maxBulkDeleteFiles+1)
	for i := range tooMany {
		tooMany[i] = int64(i + 1)
	}
	cases := []struct {
		name   string
		user   *models.User
		method string
		body   string
		want   int
	}{
		{"wrong method", alice, http.MethodGet, idsBody(1), http.StatusMethodNotAllowed},
		{"no user", nil, http.MethodPost, idsBody(1), http.StatusUnauthorized},
		{"bad json", alice, http.MethodPost, "{", http.StatusBadRequest},
		{"empty list", alice, http.MethodPost, idsBody(), http.StatusBadRequest},
		{"missing field", alice, http.MethodPost, `{}`, http.StatusBadRequest},
		{"zero id", alice, http.MethodPost, idsBody(0), http.StatusBadRequest},
		{"negative id", alice, http.MethodPost, idsBody(-4), http.StatusBadRequest},
		{"too many", alice, http.MethodPost, idsBody(tooMany...), http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := bulkDeleteReq(e, c.user, c.method, c.body)
			if rr.Code != c.want {
				t.Errorf("status %d, want %d (%s)", rr.Code, c.want, rr.Body.String())
			}
		})
	}
	// Exactly the limit is accepted.
	atLimit := tooMany[:maxBulkDeleteFiles]
	if rr := bulkDeleteReq(e, alice, http.MethodPost, idsBody(atLimit...)); rr.Code != http.StatusOK {
		t.Errorf("at limit: %d %s", rr.Code, rr.Body.String())
	}
}
