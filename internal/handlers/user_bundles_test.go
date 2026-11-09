package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
)

func ownerUser(t *testing.T, e *ghostEnv, name string) *models.User {
	t.Helper()
	u, err := e.repos.Users.Create(context.Background(), name, name+"@example.com", "hash", "user", false)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// ownedBundle publishes a bundle created by user.
func ownedBundle(t *testing.T, e *ghostEnv, user *models.User, contents ...string) models.BundleCreateResponse {
	t.Helper()
	rr := createBundleReq(t, e, map[string]any{"file_count": len(contents)}, user)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rr.Code, rr.Body.String())
	}
	var b models.BundleCreateResponse
	json.Unmarshal(rr.Body.Bytes(), &b)
	for i, c := range contents {
		form := map[string]string{"bundle_id": fmt.Sprint(b.BundleID), "bundle_position": fmt.Sprint(i)}
		body, ct := testutil.CreateMultipartForm(t, []byte(c), fmt.Sprintf("u%d.txt", i), form)
		req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
		req.Header.Set("Content-Type", ct)
		req.Header.Set(bundleUploadTokenHeader, b.UploadToken)
		req = req.WithContext(context.WithValue(req.Context(), middleware.ContextKeyUser, user))
		ur := httptest.NewRecorder()
		UploadHandler(e.repos, e.cfg).ServeHTTP(ur, req)
		if ur.Code != http.StatusCreated {
			t.Fatalf("member: %d %s", ur.Code, ur.Body.String())
		}
	}
	req := httptest.NewRequest(http.MethodPost, publishPath(b.BundleID), bytes.NewReader([]byte("{}")))
	req.Header.Set(bundleUploadTokenHeader, b.UploadToken)
	req = req.WithContext(context.WithValue(req.Context(), middleware.ContextKeyUser, user))
	pr := httptest.NewRecorder()
	BundleManageHandler(e.repos, e.cfg).ServeHTTP(pr, req)
	if pr.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", pr.Code, pr.Body.String())
	}
	return b
}

func userBundlesReq(e *ghostEnv, user *models.User, method, path string, body any) *httptest.ResponseRecorder {
	var r *http.Request
	if body != nil {
		raw, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(raw))
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	r = r.WithContext(context.WithValue(r.Context(), middleware.ContextKeyUser, user))
	rr := httptest.NewRecorder()
	UserBundlesHandler(e.repos, e.cfg).ServeHTTP(rr, r)
	return rr
}

func TestUserBundles_List(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice, bob := ownerUser(t, e, "alice"), ownerUser(t, e, "bob")
	first := ownedBundle(t, e, alice, "aaa", "bb")
	second := ownedBundle(t, e, alice, "c")
	ownedBundle(t, e, bob, "d")
	createBundleReq(t, e, map[string]any{"file_count": 1}, alice) // draft: not listed

	rr := userBundlesReq(e, alice, http.MethodGet, "/api/user/bundles", nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Bundles []struct {
			ID         int64  `json:"id"`
			BundleCode string `json:"bundle_code"`
			FileCount  int    `json:"file_count"`
			TotalSize  int64  `json:"total_size"`
			Files      []struct {
				Position int    `json:"position"`
				Name     string `json:"name"`
				Size     int64  `json:"size"`
			} `json:"files"`
		} `json:"bundles"`
		Total int `json:"total"`
	}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.Total != 2 || len(resp.Bundles) != 2 {
		t.Fatalf("list: %s", rr.Body.String())
	}
	if resp.Bundles[0].ID != second.BundleID || resp.Bundles[1].ID != first.BundleID {
		t.Fatalf("not newest first: %+v", resp.Bundles)
	}
	got := resp.Bundles[1]
	if got.BundleCode != first.BundleCode || got.FileCount != 2 || got.TotalSize != 5 || len(got.Files) != 2 || got.Files[1].Name != "u1.txt" {
		t.Fatalf("bundle entry: %+v", got)
	}
}

func TestUserBundles_DeleteExpirationRegenerate(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice, bob := ownerUser(t, e, "alice"), ownerUser(t, e, "bob")
	b := ownedBundle(t, e, alice, "x")
	path := fmt.Sprintf("/api/user/bundles/%d", b.BundleID)

	newExp := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Second).Format(time.RFC3339)
	if rr := userBundlesReq(e, bob, http.MethodPut, path+"/expiration", map[string]string{"new_expiration": newExp}); rr.Code != http.StatusNotFound {
		t.Fatalf("bob changes expiry: %d", rr.Code)
	}
	if rr := userBundlesReq(e, alice, http.MethodPut, path+"/expiration", map[string]string{"new_expiration": "yesterday"}); rr.Code != http.StatusBadRequest {
		t.Fatalf("bad date: %d", rr.Code)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if rr := userBundlesReq(e, alice, http.MethodPut, path+"/expiration", map[string]string{"new_expiration": past}); rr.Code != http.StatusBadRequest {
		t.Fatalf("past date: %d", rr.Code)
	}
	if rr := userBundlesReq(e, alice, http.MethodPut, path+"/expiration", map[string]string{"new_expiration": newExp}); rr.Code != http.StatusOK {
		t.Fatalf("change expiry: %d %s", rr.Code, rr.Body.String())
	}
	m, _ := e.repos.Bundles.GetMember(context.Background(), b.BundleID, 0)
	if m.ExpiresAt.UTC().Format(time.RFC3339) != newExp {
		t.Fatalf("member expiry %v, want %s", m.ExpiresAt, newExp)
	}

	if rr := userBundlesReq(e, bob, http.MethodPut, path+"/regenerate-code", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("bob regenerates: %d", rr.Code)
	}
	rr := userBundlesReq(e, alice, http.MethodPut, path+"/regenerate-code", nil)
	var regen struct {
		BundleCode string `json:"bundle_code"`
	}
	json.Unmarshal(rr.Body.Bytes(), &regen)
	if rr.Code != http.StatusOK || regen.BundleCode == "" || regen.BundleCode == b.BundleCode {
		t.Fatalf("regenerate: %d %s", rr.Code, rr.Body.String())
	}
	if got, _ := e.repos.Bundles.GetPublishedByCode(context.Background(), b.BundleCode); got != nil {
		t.Fatal("old code still works")
	}

	stored := filepath.Join(e.cfg.UploadDir, m.StoredFilename)
	if rr := userBundlesReq(e, bob, http.MethodDelete, path, nil); rr.Code != http.StatusNotFound {
		t.Fatalf("bob deletes: %d", rr.Code)
	}
	if rr := userBundlesReq(e, alice, http.MethodDelete, path, nil); rr.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
	if got, _ := e.repos.Bundles.GetByID(context.Background(), b.BundleID); got != nil {
		t.Fatal("bundle not deleted")
	}
	if _, err := os.Stat(stored); !os.IsNotExist(err) {
		t.Fatal("member file still on disk")
	}
}

func TestAdminDeleteMember_DeletesWholeBundle(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := publishedBundle(t, e, map[string]any{}, "one", "two")
	members, _ := e.repos.Bundles.ListMembers(context.Background(), b.BundleID)

	req := httptest.NewRequest(http.MethodDelete, "/admin/api/files/delete?claim_code="+url.QueryEscape(members[0].ClaimCode), nil)
	rr := httptest.NewRecorder()
	AdminDeleteFileHandler(e.repos, e.cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("admin delete: %d %s", rr.Code, rr.Body.String())
	}
	if got, _ := e.repos.Bundles.GetByID(context.Background(), b.BundleID); got != nil {
		t.Fatal("bundle still exists after admin deleted a member")
	}
	for _, m := range members {
		if _, err := os.Stat(filepath.Join(e.cfg.UploadDir, m.StoredFilename)); !os.IsNotExist(err) {
			t.Fatalf("member %s still on disk", m.StoredFilename)
		}
	}
}

func TestAdminBulkDeleteMember_DeletesWholeBundle(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := publishedBundle(t, e, map[string]any{}, "one", "two")
	members, _ := e.repos.Bundles.ListMembers(context.Background(), b.BundleID)

	form := url.Values{"claim_codes": {members[1].ClaimCode}}
	req := httptest.NewRequest(http.MethodPost, "/admin/api/files/delete/bulk", bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	AdminBulkDeleteFilesHandler(e.repos, e.cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("bulk delete: %d %s", rr.Code, rr.Body.String())
	}
	if got, _ := e.repos.Bundles.GetByID(context.Background(), b.BundleID); got != nil {
		t.Fatal("bundle still exists after admin bulk-deleted a member")
	}
}

func TestAdminDashboard_ShowsBundleID(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := publishedBundle(t, e, map[string]any{}, "one")
	rr := httptest.NewRecorder()
	AdminDashboardDataHandler(e.repos, e.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/admin/api/dashboard", nil))
	var resp struct {
		Files []struct {
			BundleID *int64 `json:"bundle_id"`
		} `json:"files"`
	}
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if len(resp.Files) != 1 || resp.Files[0].BundleID == nil || *resp.Files[0].BundleID != b.BundleID {
		t.Fatalf("admin list bundle_id: %s", rr.Body.String())
	}
}

// TestUserBundles_RejectsNonCanonicalPaths: only the exact route forms are
// served, so a trailing slash or extra segment can't reach an action while
// dodging the path-matched rate limits.
func TestUserBundles_RejectsNonCanonicalPaths(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice := ownerUser(t, e, "alice")
	b := ownedBundle(t, e, alice, "x")
	for _, p := range []string{
		fmt.Sprintf("/api/user/bundles/%d/regenerate-code/", b.BundleID),
		fmt.Sprintf("/api/user/bundles/%d/regenerate-code/x", b.BundleID),
		fmt.Sprintf("/api/user/bundles/%d//regenerate-code", b.BundleID),
	} {
		if rr := userBundlesReq(e, alice, http.MethodPut, p, nil); rr.Code != http.StatusNotFound {
			t.Errorf("PUT %s: %d, want 404", p, rr.Code)
		}
	}
	if rr := userBundlesReq(e, alice, http.MethodDelete, fmt.Sprintf("/api/user/bundles/%d/", b.BundleID), nil); rr.Code != http.StatusNotFound {
		t.Errorf("DELETE with trailing slash: %d, want 404", rr.Code)
	}
}

// TestBundleDelete_EmitsFileDeletedWebhooks: every way of deleting a bundle
// tells webhook consumers about each file that went, as a single-file
// delete does.
func TestBundleDelete_EmitsFileDeletedWebhooks(t *testing.T) {
	var emitted int
	SetWebhookEmitGate(func() bool { emitted++; return false })
	t.Cleanup(func() { SetWebhookEmitGate(nil) })

	e := newGhostEnv(t, nil)
	alice := ownerUser(t, e, "alice")

	b := ownedBundle(t, e, alice, "one", "two")
	emitted = 0
	if rr := userBundlesReq(e, alice, http.MethodDelete, fmt.Sprintf("/api/user/bundles/%d", b.BundleID), nil); rr.Code != http.StatusOK {
		t.Fatalf("owner delete: %d", rr.Code)
	}
	if emitted != 2 {
		t.Errorf("owner delete emitted %d events, want 2", emitted)
	}

	pb := publishedBundle(t, e, map[string]any{}, "a", "b", "c")
	members, _ := e.repos.Bundles.ListMembers(context.Background(), pb.BundleID)
	emitted = 0
	rr := httptest.NewRecorder()
	AdminDeleteFileHandler(e.repos, e.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/admin/api/files/delete?claim_code="+url.QueryEscape(members[0].ClaimCode), nil))
	if rr.Code != http.StatusOK || emitted != 3 {
		t.Errorf("admin delete: status %d, emitted %d events, want 3", rr.Code, emitted)
	}

	draft := mustCreateBundle(t, e, map[string]any{"file_count": 2})
	uploadMember(t, e, draft, draft.UploadToken, 0, []byte("x"), "x.txt", nil)
	emitted = 0
	if rr := bundleManageReq(t, e, http.MethodDelete, fmt.Sprintf("/api/bundles/%d", draft.BundleID), draft.UploadToken, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("draft delete: %d", rr.Code)
	}
	if emitted != 1 {
		t.Errorf("draft delete emitted %d events, want 1", emitted)
	}
}
