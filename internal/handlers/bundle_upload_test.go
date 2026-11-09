package handlers

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/claimcode"
	"github.com/fjmerc/safeshare/internal/middleware"
	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/privacy"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// --- helpers -------------------------------------------------------------

func createBundleReq(t *testing.T, e *ghostEnv, body map[string]any, user *models.User) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/bundles", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if user != nil {
		req = req.WithContext(context.WithValue(req.Context(), middleware.ContextKeyUser, user))
	}
	rr := httptest.NewRecorder()
	BundleCreateHandler(e.repos, e.cfg).ServeHTTP(rr, req)
	return rr
}

func mustCreateBundle(t *testing.T, e *ghostEnv, body map[string]any) models.BundleCreateResponse {
	t.Helper()
	rr := createBundleReq(t, e, body, nil)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create bundle: %d %s", rr.Code, rr.Body.String())
	}
	var resp models.BundleCreateResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	return resp
}

func uploadMember(t *testing.T, e *ghostEnv, b models.BundleCreateResponse, token string, pos int, content []byte, name string, extra map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	form := map[string]string{"bundle_id": fmt.Sprint(b.BundleID), "bundle_position": fmt.Sprint(pos)}
	for k, v := range extra {
		form[k] = v
	}
	body, ct := testutil.CreateMultipartForm(t, content, name, form)
	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", ct)
	if token != "" {
		req.Header.Set(bundleUploadTokenHeader, token)
	}
	if form["client_encrypted"] == "true" {
		req.Header.Set(clientEncryptedHeaderName, "true")
	}
	rr := httptest.NewRecorder()
	UploadHandler(e.repos, e.cfg).ServeHTTP(rr, req)
	return rr
}

func bundleManageReq(t *testing.T, e *ghostEnv, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body != nil {
		raw, _ := json.Marshal(body)
		r = httptest.NewRequest(method, path, bytes.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set(bundleUploadTokenHeader, token)
	}
	rr := httptest.NewRecorder()
	BundleManageHandler(e.repos, e.cfg).ServeHTTP(rr, r)
	return rr
}

func publishPath(id int64) string { return fmt.Sprintf("/api/bundles/%d/publish", id) }

// --- create --------------------------------------------------------------

func TestBundleCreate_Validation(t *testing.T) {
	e := newGhostEnv(t, nil)
	cases := []struct {
		name string
		body map[string]any
		code string
		st   int
	}{
		{"zero files", map[string]any{"file_count": 0}, "INVALID_PARAMETER", 400},
		{"too many files", map[string]any{"file_count": 11}, "INVALID_PARAMETER", 400},
		{"negative max downloads", map[string]any{"file_count": 2, "max_downloads": -1}, "INVALID_PARAMETER", 400},
		{"negative expiry", map[string]any{"file_count": 2, "expires_in_hours": -1}, "INVALID_PARAMETER", 400},
		{"expiry too long", map[string]any{"file_count": 2, "expires_in_hours": 100000}, "EXPIRATION_TOO_LONG", 400},
	}
	for _, tc := range cases {
		rr := createBundleReq(t, e, tc.body, nil)
		if rr.Code != tc.st || errorCode(t, rr) != tc.code {
			t.Errorf("%s: %d %s", tc.name, rr.Code, rr.Body.String())
		}
	}

	resp := mustCreateBundle(t, e, map[string]any{"file_count": 3, "expires_in_hours": 24, "max_downloads": 0, "password": "pw"})
	if len(resp.UploadToken) != 43 || !claimcode.Valid(resp.BundleCode) || resp.BundleID == 0 {
		t.Fatalf("bad create response: %+v", resp)
	}
	b, _ := e.repos.Bundles.GetByID(context.Background(), resp.BundleID)
	if b == nil || b.Status != models.BundleStatusDraft || b.FileCount != 3 || b.MaxDownloads != nil ||
		!utils.VerifyPassword(b.PasswordHash, "pw") || b.UploadTokenHash == resp.UploadToken || b.UploadTokenHash == "" {
		t.Fatalf("stored bundle wrong: %+v", b)
	}
	if d := time.Until(b.ExpiresAt); d < 23*time.Hour || d > 25*time.Hour {
		t.Fatalf("expiry %v not ~24h out", d)
	}
}

func TestBundleCreate_E2ERequiredGate(t *testing.T) {
	e := newGhostEnv(t, map[string]string{"REQUIRE_CLIENT_ENCRYPTION": "true"})
	rr := createBundleReq(t, e, map[string]any{"file_count": 2}, nil)
	if rr.Code != http.StatusBadRequest || errorCode(t, rr) != "CLIENT_ENCRYPTION_REQUIRED" {
		t.Fatalf("plain bundle under E2E-required: %d %s", rr.Code, rr.Body.String())
	}
	if rr := createBundleReq(t, e, map[string]any{"file_count": 2, "client_encrypted": true}, nil); rr.Code != http.StatusCreated {
		t.Fatalf("E2E bundle: %d %s", rr.Code, rr.Body.String())
	}
}

func TestBundleCreate_GhostModeMinimizesRow(t *testing.T) {
	privacy.SetAnonymousMode(true)
	t.Cleanup(func() { privacy.SetAnonymousMode(false) })
	e := newGhostEnv(t, map[string]string{"ANONYMOUS_MODE": "true"})
	resp := mustCreateBundle(t, e, map[string]any{"file_count": 1, "client_encrypted": true})
	b, _ := e.repos.Bundles.GetByID(context.Background(), resp.BundleID)
	if b.UploaderIP != "anonymous" {
		t.Errorf("uploader_ip = %q, want anonymous", b.UploaderIP)
	}
	if b.CreatedAt.Minute() != 0 || b.CreatedAt.Second() != 0 {
		t.Errorf("created_at %v not rounded to the hour", b.CreatedAt)
	}
}

// --- member uploads ------------------------------------------------------

func TestBundleMemberUpload_Direct(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := mustCreateBundle(t, e, map[string]any{"file_count": 2, "expires_in_hours": 2, "max_downloads": 1, "password": "pw"})

	// Settings in the member request are ignored; the bundle's apply.
	rr := uploadMember(t, e, b, b.UploadToken, 1, []byte("second"), "b.txt", map[string]string{"max_downloads": "9", "expires_in_hours": "100"})
	if rr.Code != http.StatusCreated {
		t.Fatalf("member upload: %d %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), "claim_code") || strings.Contains(rr.Body.String(), "download_url") {
		t.Fatalf("member response reveals a claim code or URL: %s", rr.Body.String())
	}
	var resp models.BundleMemberUploadResponse
	json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp.BundleID != b.BundleID || resp.BundlePosition != 1 || resp.OriginalFilename != "b.txt" || resp.FileSize != 6 {
		t.Fatalf("member response: %+v", resp)
	}

	m, _ := e.repos.Bundles.GetMember(context.Background(), b.BundleID, 1)
	bundle, _ := e.repos.Bundles.GetByID(context.Background(), b.BundleID)
	if m == nil || m.MaxDownloads == nil || *m.MaxDownloads != 1 || !m.ExpiresAt.Equal(bundle.ExpiresAt) ||
		!utils.VerifyPassword(m.PasswordHash, "pw") {
		t.Fatalf("member did not take the bundle's settings: %+v", m)
	}
}

func TestBundleMemberUpload_Chunked(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := mustCreateBundle(t, e, map[string]any{"file_count": 1, "expires_in_hours": 3, "max_downloads": 2})
	content := []byte("chunked member content")

	initBody, _ := json.Marshal(map[string]any{
		"filename": "c.txt", "total_size": len(content), "chunk_size": len(content),
		"expires_in_hours": 100, "max_downloads": 9, "bundle_id": b.BundleID, "bundle_position": 0,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/upload/init", bytes.NewReader(initBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(bundleUploadTokenHeader, b.UploadToken)
	rr := httptest.NewRecorder()
	UploadInitHandler(e.repos, e.cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusCreated {
		t.Fatalf("init: %d %s", rr.Code, rr.Body.String())
	}
	var initResp models.UploadInitResponse
	json.Unmarshal(rr.Body.Bytes(), &initResp)

	up, _ := e.repos.PartialUploads.GetByUploadID(context.Background(), initResp.UploadID)
	if up == nil || up.BundleID == nil || *up.BundleID != b.BundleID || up.BundlePosition == nil || *up.BundlePosition != 0 || up.MaxDownloads != 2 {
		t.Fatalf("partial upload membership/settings wrong: %+v", up)
	}
	if err := utils.SaveChunk(e.cfg.UploadDir, initResp.UploadID, 0, content); err != nil {
		t.Fatal(err)
	}
	assembleUploadSync(t, e.repos, e.cfg, up)

	m, _ := e.repos.Bundles.GetMember(context.Background(), b.BundleID, 0)
	bundle, _ := e.repos.Bundles.GetByID(context.Background(), b.BundleID)
	if m == nil || m.MaxDownloads == nil || *m.MaxDownloads != 2 || !m.ExpiresAt.Equal(bundle.ExpiresAt) {
		t.Fatalf("assembled member did not take the bundle's settings: %+v", m)
	}

	// /status must not reveal the member's claim code either.
	sr := httptest.NewRecorder()
	UploadStatusHandler(e.repos, e.cfg).ServeHTTP(sr, httptest.NewRequest(http.MethodGet, "/api/upload/status/"+initResp.UploadID, nil))
	if strings.Contains(sr.Body.String(), "claim_code") || strings.Contains(sr.Body.String(), "download_url") {
		t.Fatalf("status reveals a member claim code: %s", sr.Body.String())
	}
}

func TestBundleMemberUpload_BadTokenOrBundle(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := mustCreateBundle(t, e, map[string]any{"file_count": 2})
	other := &models.User{ID: 4242, Username: "other"}

	var bodies []string
	check := func(name string, rr *httptest.ResponseRecorder) {
		if rr.Code != http.StatusNotFound || errorCode(t, rr) != "NOT_FOUND" {
			t.Errorf("%s: %d %s", name, rr.Code, rr.Body.String())
		}
		bodies = append(bodies, rr.Body.String())
	}
	check("wrong token", uploadMember(t, e, b, "wrong-token", 0, []byte("x"), "x.txt", nil))
	check("no token", uploadMember(t, e, b, "", 0, []byte("x"), "x.txt", nil))
	check("out of range", uploadMember(t, e, b, b.UploadToken, 2, []byte("x"), "x.txt", nil))
	bad := b
	bad.BundleID = 99999
	check("unknown bundle", uploadMember(t, e, bad, b.UploadToken, 0, []byte("x"), "x.txt", nil))

	// Another signed-in user cannot add to an anonymous bundle.
	form := map[string]string{"bundle_id": fmt.Sprint(b.BundleID), "bundle_position": "0"}
	body, ct := testutil.CreateMultipartForm(t, []byte("x"), "x.txt", form)
	req := httptest.NewRequest(http.MethodPost, "/api/upload", body)
	req.Header.Set("Content-Type", ct)
	req.Header.Set(bundleUploadTokenHeader, b.UploadToken)
	req = req.WithContext(context.WithValue(req.Context(), middleware.ContextKeyUser, other))
	rr := httptest.NewRecorder()
	UploadHandler(e.repos, e.cfg).ServeHTTP(rr, req)
	check("other user", rr)

	for _, s := range bodies[1:] {
		if s != bodies[0] {
			t.Errorf("rejection bodies differ: %q vs %q", s, bodies[0])
		}
	}
}

func TestBundleMemberUpload_PositionTaken(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := mustCreateBundle(t, e, map[string]any{"file_count": 2})
	if rr := uploadMember(t, e, b, b.UploadToken, 0, []byte("a"), "a.txt", nil); rr.Code != http.StatusCreated {
		t.Fatalf("first: %d %s", rr.Code, rr.Body.String())
	}
	rr := uploadMember(t, e, b, b.UploadToken, 0, []byte("b"), "b.txt", nil)
	if rr.Code != http.StatusConflict || errorCode(t, rr) != "BUNDLE_POSITION_TAKEN" {
		t.Fatalf("duplicate position: %d %s", rr.Code, rr.Body.String())
	}
}

func TestBundleMemberUpload_ClientEncryptedMismatch(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := mustCreateBundle(t, e, map[string]any{"file_count": 1, "client_encrypted": true})
	rr := uploadMember(t, e, b, b.UploadToken, 0, []byte("a"), "a.txt", nil)
	if rr.Code != http.StatusBadRequest || errorCode(t, rr) != "INVALID_PARAMETER" {
		t.Fatalf("plain member in E2E bundle: %d %s", rr.Code, rr.Body.String())
	}
}

func TestBundleMemberUpload_AfterPublishRejected(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := mustCreateBundle(t, e, map[string]any{"file_count": 1})
	uploadMember(t, e, b, b.UploadToken, 0, []byte("a"), "a.txt", nil)
	if rr := bundleManageReq(t, e, http.MethodPost, publishPath(b.BundleID), b.UploadToken, map[string]any{}); rr.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", rr.Code, rr.Body.String())
	}
	rr := uploadMember(t, e, b, b.UploadToken, 0, []byte("late"), "late.txt", nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("upload after publish: %d %s", rr.Code, rr.Body.String())
	}
}

// --- publish / delete ----------------------------------------------------

func TestBundlePublish_Incomplete(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := mustCreateBundle(t, e, map[string]any{"file_count": 2})
	uploadMember(t, e, b, b.UploadToken, 0, []byte("a"), "a.txt", nil)
	rr := bundleManageReq(t, e, http.MethodPost, publishPath(b.BundleID), b.UploadToken, map[string]any{})
	if rr.Code != http.StatusConflict || errorCode(t, rr) != "BUNDLE_INCOMPLETE" {
		t.Fatalf("incomplete publish: %d %s", rr.Code, rr.Body.String())
	}
	if rr := bundleManageReq(t, e, http.MethodPost, publishPath(b.BundleID), "wrong", map[string]any{}); rr.Code != http.StatusNotFound {
		t.Fatalf("publish with wrong token: %d", rr.Code)
	}
}

func TestBundlePublish_E2ERequiresManifest(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := mustCreateBundle(t, e, map[string]any{"file_count": 1, "client_encrypted": true})
	uploadMember(t, e, b, b.UploadToken, 0, []byte("ct"), "encrypted.bin", map[string]string{"client_encrypted": "true"})
	rr := bundleManageReq(t, e, http.MethodPost, publishPath(b.BundleID), b.UploadToken, map[string]any{})
	if rr.Code != http.StatusBadRequest || errorCode(t, rr) != "INVALID_PARAMETER" {
		t.Fatalf("E2E publish without manifest: %d %s", rr.Code, rr.Body.String())
	}
	big := base64.StdEncoding.EncodeToString(make([]byte, maxBundleManifestBytes+1))
	if rr := bundleManageReq(t, e, http.MethodPost, publishPath(b.BundleID), b.UploadToken, map[string]any{"encrypted_manifest": big}); rr.Code != http.StatusBadRequest {
		t.Fatalf("oversized manifest: %d %s", rr.Code, rr.Body.String())
	}
	manifest := base64.StdEncoding.EncodeToString([]byte("opaque"))
	if rr := bundleManageReq(t, e, http.MethodPost, publishPath(b.BundleID), b.UploadToken, map[string]any{"encrypted_manifest": manifest}); rr.Code != http.StatusOK {
		t.Fatalf("E2E publish: %d %s", rr.Code, rr.Body.String())
	}
	stored, _ := e.repos.Bundles.GetByID(context.Background(), b.BundleID)
	if string(stored.EncryptedManifest) != "opaque" {
		t.Fatalf("manifest not stored: %q", stored.EncryptedManifest)
	}
}

func TestBundlePublish_OK(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := mustCreateBundle(t, e, map[string]any{"file_count": 2, "max_downloads": 0})
	uploadMember(t, e, b, b.UploadToken, 1, []byte("bbbb"), "b.png", nil)
	uploadMember(t, e, b, b.UploadToken, 0, []byte("aa"), "a.png", nil)
	rr := bundleManageReq(t, e, http.MethodPost, publishPath(b.BundleID), b.UploadToken, map[string]any{})
	if rr.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", rr.Code, rr.Body.String())
	}
	var resp models.BundleResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.BundleCode != b.BundleCode || !strings.HasSuffix(resp.BundleURL, "/#/bundle/"+b.BundleCode) ||
		resp.MaxDownloads != nil || resp.ClientEncrypted || len(resp.Files) != 2 ||
		resp.Files[0].Name != "a.png" || resp.Files[0].Size != 2 || resp.Files[1].Position != 1 {
		t.Fatalf("publish response: %+v", resp)
	}
	if !strings.Contains(rr.Body.String(), `"max_downloads":null`) {
		t.Fatalf("unlimited bundle must report max_downloads null: %s", rr.Body.String())
	}
}

func TestBundleDelete_RemovesMemberFilesFromDisk(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := mustCreateBundle(t, e, map[string]any{"file_count": 2})
	uploadMember(t, e, b, b.UploadToken, 0, []byte("a"), "a.txt", nil)
	m, _ := e.repos.Bundles.GetMember(context.Background(), b.BundleID, 0)
	stored := filepath.Join(e.cfg.UploadDir, m.StoredFilename)
	if _, err := os.Stat(stored); err != nil {
		t.Fatalf("stored file missing before delete: %v", err)
	}

	if rr := bundleManageReq(t, e, http.MethodDelete, fmt.Sprintf("/api/bundles/%d", b.BundleID), "wrong", nil); rr.Code != http.StatusNotFound {
		t.Fatalf("delete with wrong token: %d", rr.Code)
	}
	if rr := bundleManageReq(t, e, http.MethodDelete, fmt.Sprintf("/api/bundles/%d", b.BundleID), b.UploadToken, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("delete: %d %s", rr.Code, rr.Body.String())
	}
	if _, err := os.Stat(stored); !os.IsNotExist(err) {
		t.Fatalf("stored file still on disk: %v", err)
	}
	if got, _ := e.repos.Bundles.GetByID(context.Background(), b.BundleID); got != nil {
		t.Fatal("bundle row still exists")
	}
}

func TestBundleDelete_PublishedNotDeletableWithToken(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := mustCreateBundle(t, e, map[string]any{"file_count": 1})
	uploadMember(t, e, b, b.UploadToken, 0, []byte("a"), "a.txt", nil)
	bundleManageReq(t, e, http.MethodPost, publishPath(b.BundleID), b.UploadToken, map[string]any{})
	if rr := bundleManageReq(t, e, http.MethodDelete, fmt.Sprintf("/api/bundles/%d", b.BundleID), b.UploadToken, nil); rr.Code != http.StatusNotFound {
		t.Fatalf("delete published via upload token: %d", rr.Code)
	}
}

// TestBundlePublish_LargeManifestAccepted: the file list of a full bundle
// (up to 100 files, names up to 1 KB each) fits under the manifest cap.
func TestBundlePublish_LargeManifestAccepted(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := mustCreateBundle(t, e, map[string]any{"file_count": 1, "client_encrypted": true})
	uploadMember(t, e, b, b.UploadToken, 0, []byte("ct"), "encrypted.bin", map[string]string{"client_encrypted": "true"})
	manifest := base64.StdEncoding.EncodeToString(make([]byte, 150*1024))
	if rr := bundleManageReq(t, e, http.MethodPost, publishPath(b.BundleID), b.UploadToken, map[string]any{"encrypted_manifest": manifest}); rr.Code != http.StatusOK {
		t.Fatalf("150 KiB manifest: %d %s", rr.Code, rr.Body.String())
	}
}
