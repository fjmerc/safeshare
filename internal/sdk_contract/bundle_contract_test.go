package sdk_contract

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	safeshare "github.com/fjmerc/safeshare/sdk/go"

	"github.com/fjmerc/safeshare/internal/handlers"
	"github.com/fjmerc/safeshare/internal/testutil"
)

// setupBundleServer mounts the real upload, config, bundle and bundle
// receive handlers, as cmd/safeshare does.
func setupBundleServer(t *testing.T) *httptest.Server {
	t.Helper()
	repos, cfg := testutil.SetupTestRepos(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/config", handlers.PublicConfigHandler(cfg))
	mux.HandleFunc("/api/upload", handlers.UploadHandler(repos, cfg))
	mux.HandleFunc("/api/bundles", handlers.BundleCreateHandler(repos, cfg))
	mux.HandleFunc("/api/bundles/", handlers.BundleManageHandler(repos, cfg))
	mux.HandleFunc("/api/bundle/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/info") {
			handlers.BundleInfoHandler(repos, cfg)(w, r)
			return
		}
		handlers.BundleFileHandler(repos, cfg)(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestBundleRoundTripContract(t *testing.T) {
	for _, mode := range []safeshare.EncryptMode{safeshare.EncryptNever, safeshare.EncryptAlways} {
		srv := setupBundleServer(t)
		client := createSDKClient(t, srv.URL)
		ctx := context.Background()

		src := t.TempDir()
		contents := map[string]string{"photo-1.png": "first image", "photo-2.png": "second", "clip.mp4": "video bytes"}
		var paths []string
		for _, name := range []string{"photo-1.png", "photo-2.png", "clip.mp4"} {
			p := filepath.Join(src, name)
			os.WriteFile(p, []byte(contents[name]), 0o600)
			paths = append(paths, p)
		}

		limit := 1
		res, err := client.UploadBundle(ctx, paths, &safeshare.UploadOptions{Encrypt: mode, DownloadLimit: &limit})
		if err != nil {
			t.Fatalf("mode %v: UploadBundle: %v", mode, err)
		}
		if len(res.Files) != 3 || res.DownloadLimit == nil || *res.DownloadLimit != 1 || res.Encrypted != (mode == safeshare.EncryptAlways) {
			t.Fatalf("mode %v: result %+v", mode, res)
		}

		info, err := client.GetBundleInfo(ctx, res.BundleCode)
		if err != nil || info.FileCount != 3 || info.ClientEncrypted != res.Encrypted || (res.Encrypted && len(info.EncryptedManifest) == 0) {
			t.Fatalf("mode %v: GetBundleInfo %+v %v", mode, info, err)
		}

		link, err := safeshare.ParseBundleURL(res.BundleURL)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(t.TempDir(), "got")
		saved, err := client.DownloadBundle(ctx, link, dir, nil)
		if err != nil || len(saved) != 3 {
			t.Fatalf("mode %v: DownloadBundle %v %v", mode, saved, err)
		}
		for _, p := range saved {
			data, _ := os.ReadFile(p)
			if string(data) != contents[filepath.Base(p)] {
				t.Fatalf("mode %v: %s = %q", mode, p, data)
			}
		}

		// Download limit 1 is per file: a second download of the bundle fails.
		if _, err := client.DownloadBundle(ctx, link, filepath.Join(t.TempDir(), "again"), nil); err == nil {
			t.Fatalf("mode %v: second download of a max_downloads=1 bundle succeeded", mode)
		}
	}
}
