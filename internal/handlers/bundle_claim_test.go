package handlers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

// publishedBundle creates and publishes a bundle with the given member contents.
func publishedBundle(t *testing.T, e *ghostEnv, settings map[string]any, contents ...string) models.BundleCreateResponse {
	t.Helper()
	settings["file_count"] = len(contents)
	b := mustCreateBundle(t, e, settings)
	encrypted := settings["client_encrypted"] == true
	for i, c := range contents {
		extra := map[string]string{}
		if encrypted {
			extra["client_encrypted"] = "true"
		}
		if rr := uploadMember(t, e, b, b.UploadToken, i, []byte(c), fmt.Sprintf("f%d.txt", i), extra); rr.Code != http.StatusCreated {
			t.Fatalf("member %d: %d %s", i, rr.Code, rr.Body.String())
		}
	}
	body := map[string]any{}
	if encrypted {
		body["encrypted_manifest"] = base64.StdEncoding.EncodeToString([]byte("opaque-manifest"))
	}
	if rr := bundleManageReq(t, e, http.MethodPost, publishPath(b.BundleID), b.UploadToken, body); rr.Code != http.StatusOK {
		t.Fatalf("publish: %d %s", rr.Code, rr.Body.String())
	}
	return b
}

func bundleInfo(e *ghostEnv, code string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	BundleInfoHandler(e.repos, e.cfg).ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/bundle/"+code+"/info", nil))
	return rr
}

func bundleFile(e *ghostEnv, code string, pos int, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("/api/bundle/%s/files/%d", code, pos), nil)
	req.Header.Set("Accept", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	BundleFileHandler(e.repos, e.cfg).ServeHTTP(rr, req)
	return rr
}

func TestBundleInfo_Published(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := publishedBundle(t, e, map[string]any{"max_downloads": 2, "password": "pw"}, "aaa", "bb")
	rr := bundleInfo(e, b.BundleCode)
	if rr.Code != http.StatusOK {
		t.Fatalf("info: %d %s", rr.Code, rr.Body.String())
	}
	var info struct {
		BundleCode       string           `json:"bundle_code"`
		FileCount        int              `json:"file_count"`
		MaxDownloads     *int             `json:"max_downloads"`
		PasswordRequired bool             `json:"password_required"`
		ClientEncrypted  bool             `json:"client_encrypted"`
		Files            []map[string]any `json:"files"`
	}
	json.Unmarshal(rr.Body.Bytes(), &info)
	if info.BundleCode != b.BundleCode || info.FileCount != 2 || info.MaxDownloads == nil || *info.MaxDownloads != 2 ||
		!info.PasswordRequired || info.ClientEncrypted || len(info.Files) != 2 {
		t.Fatalf("info: %+v", info)
	}
	if info.Files[0]["position"] != float64(0) || info.Files[0]["original_filename"] != "f0.txt" || info.Files[1]["file_size"] != float64(2) {
		t.Fatalf("files: %+v", info.Files)
	}
	if strings.Contains(rr.Body.String(), "encrypted_manifest") {
		t.Fatal("plain bundle info carries a manifest")
	}
	members, _ := e.repos.Bundles.ListMembers(context.Background(), b.BundleID)
	for _, m := range members {
		if strings.Contains(rr.Body.String(), m.ClaimCode) {
			t.Fatalf("info reveals member claim code %q", m.ClaimCode)
		}
	}
	if strings.Contains(rr.Body.String(), "claim_code") || strings.Contains(rr.Body.String(), "download_url") {
		t.Fatalf("info carries claim_code/download_url keys: %s", rr.Body.String())
	}
}

func TestBundleInfo_E2EManifest(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := publishedBundle(t, e, map[string]any{"client_encrypted": true}, "ct")
	rr := bundleInfo(e, b.BundleCode)
	var info map[string]any
	json.Unmarshal(rr.Body.Bytes(), &info)
	if info["encrypted_manifest"] != base64.StdEncoding.EncodeToString([]byte("opaque-manifest")) || info["client_encrypted"] != true {
		t.Fatalf("E2E info: %s", rr.Body.String())
	}
}

func TestBundleInfo_IndistinguishableFromUnknown(t *testing.T) {
	e := newGhostEnv(t, nil)
	unknown := httptest.NewRecorder()
	ClaimInfoHandler(e.repos, e.cfg).ServeHTTP(unknown, httptest.NewRequest(http.MethodGet, "/api/claim/NoSuchCode123/info", nil))

	draft := mustCreateBundle(t, e, map[string]any{"file_count": 1})
	expired := publishedBundle(t, e, map[string]any{}, "x")
	if _, err := e.repos.DB.Exec(`UPDATE bundles SET expires_at = ? WHERE id = ?`, time.Now().Add(-time.Hour).UTC().Format(time.RFC3339), expired.BundleID); err != nil {
		t.Fatal(err)
	}
	deleted := publishedBundle(t, e, map[string]any{}, "y")
	e.repos.Bundles.DeleteWithMembers(context.Background(), deleted.BundleID)

	for name, code := range map[string]string{"unknown": "NoSuchCode123", "draft": draft.BundleCode, "expired": expired.BundleCode, "deleted": deleted.BundleCode, "invalid": "x!"} {
		rr := bundleInfo(e, code)
		if rr.Code != unknown.Code || rr.Body.String() != unknown.Body.String() {
			t.Errorf("%s: %d %q, want %d %q", name, rr.Code, rr.Body.String(), unknown.Code, unknown.Body.String())
		}
		fr := bundleFile(e, code, 0, nil)
		claimReq := httptest.NewRequest(http.MethodGet, "/api/claim/NoSuchCode123", nil)
		claimReq.Header.Set("Accept", "application/json")
		cr := httptest.NewRecorder()
		ClaimHandler(e.repos, e.cfg).ServeHTTP(cr, claimReq)
		if fr.Code != cr.Code || fr.Body.String() != cr.Body.String() {
			t.Errorf("%s file: %d %q, want %d %q", name, fr.Code, fr.Body.String(), cr.Code, cr.Body.String())
		}
	}
}

func TestBundleFile_ServesMember(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := publishedBundle(t, e, map[string]any{}, "first", "second")
	for pos, want := range []string{"first", "second"} {
		rr := bundleFile(e, b.BundleCode, pos, nil)
		if rr.Code != http.StatusOK || rr.Body.String() != want {
			t.Fatalf("file %d: %d %q", pos, rr.Code, rr.Body.String())
		}
	}
	if rr := bundleFile(e, b.BundleCode, 2, nil); rr.Code != http.StatusNotFound {
		t.Fatalf("missing position: %d", rr.Code)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/bundle/"+b.BundleCode+"/files/-1", nil)
	rr := httptest.NewRecorder()
	BundleFileHandler(e.repos, e.cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("negative position: %d", rr.Code)
	}
}

func TestBundleFile_PasswordPerRequest(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := publishedBundle(t, e, map[string]any{"password": "pw"}, "secret")
	if rr := bundleFile(e, b.BundleCode, 0, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("no password: %d", rr.Code)
	}
	if rr := bundleFile(e, b.BundleCode, 0, map[string]string{"X-File-Password": "nope"}); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", rr.Code)
	}
	if rr := bundleFile(e, b.BundleCode, 0, map[string]string{"X-File-Password": "pw"}); rr.Code != http.StatusOK || rr.Body.String() != "secret" {
		t.Fatalf("right password: %d %q", rr.Code, rr.Body.String())
	}
}

func TestBundleFile_MaxDownloadsPerFile(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := publishedBundle(t, e, map[string]any{"max_downloads": 1}, "a", "b", "c")
	for pos := 0; pos < 3; pos++ {
		if rr := bundleFile(e, b.BundleCode, pos, nil); rr.Code != http.StatusOK {
			t.Fatalf("first download of %d: %d %s", pos, rr.Code, rr.Body.String())
		}
	}
	for pos := 0; pos < 3; pos++ {
		if rr := bundleFile(e, b.BundleCode, pos, nil); rr.Code != http.StatusGone {
			t.Fatalf("second download of %d: %d, want 410", pos, rr.Code)
		}
	}
}

func TestBundleFile_RangeAndSessionWork(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := publishedBundle(t, e, map[string]any{"max_downloads": 1}, strings.Repeat("z", 4000))
	rr := bundleFile(e, b.BundleCode, 0, map[string]string{"Range": "bytes=0-1999"})
	if rr.Code != http.StatusPartialContent || rr.Header().Get("X-Download-Session") == "" {
		t.Fatalf("range on capped member: %d, session %q", rr.Code, rr.Header().Get("X-Download-Session"))
	}
}

func TestClaim_RefusesMemberCode(t *testing.T) {
	e := newGhostEnv(t, nil)
	b := publishedBundle(t, e, map[string]any{}, "member")
	m, _ := e.repos.Bundles.GetMember(context.Background(), b.BundleID, 0)
	req := httptest.NewRequest(http.MethodGet, "/api/claim/"+m.ClaimCode, nil)
	rr := httptest.NewRecorder()
	ClaimHandler(e.repos, e.cfg).ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("claim by member code: %d", rr.Code)
	}
	ir := httptest.NewRecorder()
	ClaimInfoHandler(e.repos, e.cfg).ServeHTTP(ir, httptest.NewRequest(http.MethodGet, "/api/claim/"+m.ClaimCode+"/info", nil))
	if ir.Code != http.StatusNotFound {
		t.Fatalf("claim info by member code: %d", ir.Code)
	}
}
