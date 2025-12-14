package benchmarks

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/fjmerc/safeshare/internal/handlers"
	"github.com/fjmerc/safeshare/internal/testutil"
)

// BenchmarkUploadSmallFile benchmarks uploading a small file (10KB)
func BenchmarkUploadSmallFile(b *testing.B) {
	t := &testing.T{}
	repos, cfg := testutil.SetupTestRepos(t)

	handler := handlers.UploadHandler(repos, cfg)
	fileContent := bytes.Repeat([]byte("A"), 10*1024) // 10KB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		body, contentType := testutil.CreateMultipartForm(t, fileContent, "small.bin", nil)

		req := httptest.NewRequest("POST", "/api/upload", body)
		req.Header.Set("Content-Type", contentType)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != 201 { // Upload handler returns 201 (Created)
			b.Fatalf("upload failed: status = %d", rr.Code)
		}
	}
}

// BenchmarkUploadMediumFile benchmarks uploading a medium file (1MB)
func BenchmarkUploadMediumFile(b *testing.B) {
	t := &testing.T{}
	repos, cfg := testutil.SetupTestRepos(t)

	handler := handlers.UploadHandler(repos, cfg)
	fileContent := bytes.Repeat([]byte("B"), 1024*1024) // 1MB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		body, contentType := testutil.CreateMultipartForm(t, fileContent, "medium.bin", nil)

		req := httptest.NewRequest("POST", "/api/upload", body)
		req.Header.Set("Content-Type", contentType)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != 201 { // Upload handler returns 201 (Created)
			b.Fatalf("upload failed: status = %d", rr.Code)
		}
	}
}

// BenchmarkUploadWithPassword benchmarks uploading with password hashing
func BenchmarkUploadWithPassword(b *testing.B) {
	t := &testing.T{}
	repos, cfg := testutil.SetupTestRepos(t)

	handler := handlers.UploadHandler(repos, cfg)
	fileContent := bytes.Repeat([]byte("C"), 10*1024) // 10KB

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		body, contentType := testutil.CreateMultipartForm(t, fileContent, "password.bin", map[string]string{
			"password": "securepassword123",
		})

		req := httptest.NewRequest("POST", "/api/upload", body)
		req.Header.Set("Content-Type", contentType)
		rr := httptest.NewRecorder()

		handler.ServeHTTP(rr, req)

		if rr.Code != 201 { // Upload handler returns 201 (Created)
			b.Fatalf("upload failed: status = %d", rr.Code)
		}
	}
}

// BenchmarkConcurrentUploads benchmarks concurrent file uploads
func BenchmarkConcurrentUploads(b *testing.B) {
	t := &testing.T{}
	repos, cfg := testutil.SetupTestRepos(t)

	handler := handlers.UploadHandler(repos, cfg)
	fileContent := bytes.Repeat([]byte("D"), 10*1024) // 10KB

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			body, contentType := testutil.CreateMultipartForm(t, fileContent, "concurrent.bin", nil)

			req := httptest.NewRequest("POST", "/api/upload", body)
			req.Header.Set("Content-Type", contentType)
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			if rr.Code != 201 { // Upload handler returns 201 (Created)
				b.Fatalf("upload failed: status = %d", rr.Code)
			}
		}
	})
}
