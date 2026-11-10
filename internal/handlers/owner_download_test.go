package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/utils"
)

// ownedFile stores a standalone file owned by user, with optional changes.
func ownedFile(t *testing.T, e *ghostEnv, user *models.User, code, content string, mod func(*models.File)) *models.File {
	t.Helper()
	stored := code + ".bin"
	if err := os.WriteFile(filepath.Join(e.cfg.UploadDir, stored), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &models.File{
		ClaimCode:        code,
		OriginalFilename: code + ".txt",
		StoredFilename:   stored,
		FileSize:         int64(len(content)),
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
		UserID:           &user.ID,
	}
	if mod != nil {
		mod(f)
	}
	if err := e.repos.Files.Create(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	return f
}

func ownerDownloadReq(e *ghostEnv, user *models.User, method, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if user != nil {
		r = r.WithContext(context.WithValue(r.Context(), middleware.ContextKeyUser, user))
	}
	rr := httptest.NewRecorder()
	if strings.HasPrefix(path, "/api/user/bundles") {
		UserBundlesHandler(e.repos, e.cfg).ServeHTTP(rr, r)
	} else {
		UserDownloadFileHandler(e.repos, e.cfg).ServeHTTP(rr, r)
	}
	return rr
}

func claimReq(e *ghostEnv, code string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	ClaimHandler(e.repos, e.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/claim/"+code, nil))
	return rr
}

func downloadCounts(t *testing.T, e *ghostEnv, id int64) (int, int) {
	t.Helper()
	f, err := e.repos.Files.GetByID(context.Background(), id)
	if err != nil || f == nil {
		t.Fatalf("get file %d: %v", id, err)
	}
	return f.DownloadCount, f.CompletedDownloads
}

func TestOwnerDownload_StreamsWithoutCounting(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice := ownerUser(t, e, "alice")
	f := ownedFile(t, e, alice, "OwnerDl0001", "hello owner", nil)

	rr := ownerDownloadReq(e, alice, http.MethodGet, "/api/user/files/OwnerDl0001/download")
	if rr.Code != http.StatusOK || rr.Body.String() != "hello owner" {
		t.Fatalf("GET: %d %q", rr.Code, rr.Body.String())
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "OwnerDl0001.txt") {
		t.Errorf("Content-Disposition = %q, want the file name", cd)
	}
	if cc := rr.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if dc, cdl := downloadCounts(t, e, f.ID); dc != 0 || cdl != 0 {
		t.Errorf("owner download counted: download_count=%d completed=%d", dc, cdl)
	}
}

func TestOwnerDownload_LimitReachedStillServed(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice := ownerUser(t, e, "alice")
	one := 1
	ownedFile(t, e, alice, "OwnerDl0002", "once only", func(f *models.File) { f.MaxDownloads = &one })

	if rr := claimReq(e, "OwnerDl0002"); rr.Code != http.StatusOK {
		t.Fatalf("first claim: %d", rr.Code)
	}
	if rr := claimReq(e, "OwnerDl0002"); rr.Code != http.StatusGone {
		t.Fatalf("second claim: %d, want 410 (limit reached)", rr.Code)
	}
	rr := ownerDownloadReq(e, alice, http.MethodGet, "/api/user/files/OwnerDl0002/download")
	if rr.Code != http.StatusOK || rr.Body.String() != "once only" {
		t.Fatalf("owner after limit: %d %q", rr.Code, rr.Body.String())
	}
}

func TestOwnerDownload_NoPasswordNeeded(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice := ownerUser(t, e, "alice")
	hash, err := utils.HashPassword("s3cret-pass")
	if err != nil {
		t.Fatal(err)
	}
	ownedFile(t, e, alice, "OwnerDl0003", "locked", func(f *models.File) { f.PasswordHash = hash })

	if rr := claimReq(e, "OwnerDl0003"); rr.Code != http.StatusUnauthorized {
		t.Fatalf("claim without password: %d, want 401", rr.Code)
	}
	rr := ownerDownloadReq(e, alice, http.MethodGet, "/api/user/files/OwnerDl0003/download")
	if rr.Code != http.StatusOK || rr.Body.String() != "locked" {
		t.Fatalf("owner: %d %q", rr.Code, rr.Body.String())
	}
}

func TestOwnerDownload_OnlyTheOwner(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice, bob := ownerUser(t, e, "alice"), ownerUser(t, e, "bob")
	ownedFile(t, e, alice, "OwnerDl0004", "alice's", nil)

	if rr := ownerDownloadReq(e, bob, http.MethodGet, "/api/user/files/OwnerDl0004/download"); rr.Code != http.StatusNotFound {
		t.Errorf("another user: %d, want 404", rr.Code)
	}
	if rr := ownerDownloadReq(e, alice, http.MethodGet, "/api/user/files/NoSuchCode9/download"); rr.Code != http.StatusNotFound {
		t.Errorf("unknown code: %d, want 404", rr.Code)
	}
	if rr := ownerDownloadReq(e, nil, http.MethodGet, "/api/user/files/OwnerDl0004/download"); rr.Code != http.StatusUnauthorized {
		t.Errorf("no session: %d, want 401", rr.Code)
	}
	if rr := ownerDownloadReq(e, alice, http.MethodPost, "/api/user/files/OwnerDl0004/download"); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d, want 405", rr.Code)
	}
}

func TestOwnerDownload_EncryptedAndExpiredRefused(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice := ownerUser(t, e, "alice")
	ownedFile(t, e, alice, "OwnerDl0005", "ciphertext", func(f *models.File) { f.ClientEncrypted = true })
	ownedFile(t, e, alice, "OwnerDl0006", "old", func(f *models.File) { f.ExpiresAt = time.Now().Add(-time.Hour) })

	rr := ownerDownloadReq(e, alice, http.MethodGet, "/api/user/files/OwnerDl0005/download")
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "CLIENT_ENCRYPTED") {
		t.Errorf("encrypted: %d %s, want 409 CLIENT_ENCRYPTED", rr.Code, rr.Body.String())
	}
	if rr := ownerDownloadReq(e, alice, http.MethodGet, "/api/user/files/OwnerDl0006/download"); rr.Code != http.StatusNotFound {
		t.Errorf("expired: %d, want 404", rr.Code)
	}
}

func TestOwnerDownload_Head(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice := ownerUser(t, e, "alice")
	f := ownedFile(t, e, alice, "OwnerDl0007", "head body", nil)

	rr := ownerDownloadReq(e, alice, http.MethodHead, "/api/user/files/OwnerDl0007/download")
	if rr.Code != http.StatusOK || rr.Body.Len() != 0 {
		t.Fatalf("HEAD: %d, body %d bytes", rr.Code, rr.Body.Len())
	}
	if rr.Header().Get("Content-Length") != fmt.Sprint(len("head body")) {
		t.Errorf("Content-Length = %q", rr.Header().Get("Content-Length"))
	}
	if dc, cdl := downloadCounts(t, e, f.ID); dc != 0 || cdl != 0 {
		t.Errorf("HEAD counted: %d %d", dc, cdl)
	}
}

func TestOwnerDownload_BundleMember(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice, bob := ownerUser(t, e, "alice"), ownerUser(t, e, "bob")
	b := ownedBundle(t, e, alice, "first", "second")
	path := fmt.Sprintf("/api/user/bundles/%d/files/1/download", b.BundleID)

	rr := ownerDownloadReq(e, alice, http.MethodGet, path)
	if rr.Code != http.StatusOK || rr.Body.String() != "second" {
		t.Fatalf("owner: %d %q", rr.Code, rr.Body.String())
	}
	members, err := e.repos.Bundles.ListMembers(context.Background(), b.BundleID)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range members {
		if m.DownloadCount != 0 || m.CompletedDownloads != 0 {
			t.Errorf("member %d counted: %d %d", *m.BundlePosition, m.DownloadCount, m.CompletedDownloads)
		}
	}
	if rr := ownerDownloadReq(e, bob, http.MethodGet, path); rr.Code != http.StatusNotFound {
		t.Errorf("another user: %d, want 404", rr.Code)
	}
	if rr := ownerDownloadReq(e, alice, http.MethodGet, fmt.Sprintf("/api/user/bundles/%d/files/9/download", b.BundleID)); rr.Code != http.StatusNotFound {
		t.Errorf("no such position: %d, want 404", rr.Code)
	}
	if rr := ownerDownloadReq(e, alice, http.MethodGet, fmt.Sprintf("/api/user/bundles/%d/files/x/download", b.BundleID)); rr.Code != http.StatusNotFound {
		t.Errorf("bad position: %d, want 404", rr.Code)
	}
	if rr := ownerDownloadReq(e, alice, http.MethodPut, path); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT: %d, want 405", rr.Code)
	}
}

func TestOwnerDownload_FileListSaysEncrypted(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice := ownerUser(t, e, "alice")
	ownedFile(t, e, alice, "OwnerDl0008", "ct", func(f *models.File) { f.ClientEncrypted = true })

	r := httptest.NewRequest(http.MethodGet, "/api/user/files", nil)
	r = r.WithContext(context.WithValue(r.Context(), middleware.ContextKeyUser, alice))
	rr := httptest.NewRecorder()
	UserDashboardDataHandler(e.repos, e.cfg).ServeHTTP(rr, r)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"client_encrypted":true`) {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}
}

func TestOwnerDownload_MoreRefusals(t *testing.T) {
	e := newGhostEnv(t, nil)
	alice := ownerUser(t, e, "alice")

	// An anonymous upload (no owner) is nobody's to download this way.
	ownedFile(t, e, alice, "OwnerDl0009", "anon", func(f *models.File) { f.UserID = nil })
	if rr := ownerDownloadReq(e, alice, http.MethodGet, "/api/user/files/OwnerDl0009/download"); rr.Code != http.StatusNotFound {
		t.Errorf("anonymous file: %d, want 404", rr.Code)
	}

	b := ownedBundle(t, e, alice, "one", "two")
	members, err := e.repos.Bundles.ListMembers(context.Background(), b.BundleID)
	if err != nil || len(members) != 2 {
		t.Fatalf("members: %v %d", err, len(members))
	}
	// Bundle members are never reachable by their own claim code.
	if rr := ownerDownloadReq(e, alice, http.MethodGet, "/api/user/files/"+members[0].ClaimCode+"/download"); rr.Code != http.StatusNotFound {
		t.Errorf("member by claim code: %d, want 404", rr.Code)
	}
	// A bundle encrypted in the browser can't be downloaded this way.
	if _, err := e.repos.DB.Exec(`UPDATE bundles SET client_encrypted = 1 WHERE id = ?`, b.BundleID); err != nil {
		t.Fatal(err)
	}
	rr := ownerDownloadReq(e, alice, http.MethodGet, fmt.Sprintf("/api/user/bundles/%d/files/0/download", b.BundleID))
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "CLIENT_ENCRYPTED") {
		t.Errorf("encrypted bundle: %d %s, want 409 CLIENT_ENCRYPTED", rr.Code, rr.Body.String())
	}
}

// Every owner GET is audit-logged with who made it, partial (Range) ones too.
func TestOwnerDownload_AuditedWithUser(t *testing.T) {
	ae := newAuditEnv(t)
	e := &ghostEnv{repos: ae.repos, cfg: ae.cfg}
	alice := ownerUser(t, e, "alice")
	ownedFile(t, e, alice, "OwnerDl0010", "audited bytes", nil)

	r := httptest.NewRequest(http.MethodGet, "/api/user/files/OwnerDl0010/download", nil)
	r.Header.Set("Range", "bytes=0-3")
	r = r.WithContext(context.WithValue(r.Context(), middleware.ContextKeyUser, alice))
	rr := httptest.NewRecorder()
	UserDownloadFileHandler(e.repos, e.cfg).ServeHTTP(rr, r)
	if rr.Code != http.StatusPartialContent {
		t.Fatalf("range: %d", rr.Code)
	}
	if rr := ownerDownloadReq(e, alice, http.MethodGet, "/api/user/files/OwnerDl0010/download"); rr.Code != http.StatusOK {
		t.Fatalf("full: %d", rr.Code)
	}
	got := ae.find(t, "file_download_owner", models.AuditOutcomeSuccess)
	if len(got) != 2 {
		t.Fatalf("want 2 file_download_owner entries (range + full), got %d", len(got))
	}
	for _, en := range got {
		if en.UserID != fmt.Sprint(alice.ID) || en.Username != "alice" {
			t.Errorf("entry without its user: user_id=%q username=%q", en.UserID, en.Username)
		}
	}
}
