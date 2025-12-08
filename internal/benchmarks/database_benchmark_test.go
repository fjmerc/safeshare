package benchmarks

import (
	"context"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/testutil"
	"github.com/fjmerc/safeshare/internal/utils"
)

// BenchmarkFileCreation benchmarks creating files in database
func BenchmarkFileCreation(b *testing.B) {
	// Create a minimal testing.T implementation for SetupTestRepos
	t := &testing.T{}
	repos, _ := testutil.SetupTestRepos(t)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		claimCode, _ := utils.GenerateClaimCode()
		file := &models.File{
			ClaimCode:        claimCode,
			StoredFilename:   "bench_" + claimCode + ".dat",
			OriginalFilename: "file.txt",
			FileSize:         1024,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "127.0.0.1",
		}

		repos.Files.Create(ctx, file)
	}
}

// BenchmarkFileRetrieval benchmarks retrieving files by claim code
func BenchmarkFileRetrieval(b *testing.B) {
	t := &testing.T{}
	repos, _ := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create a file
	claimCode, _ := utils.GenerateClaimCode()
	file := &models.File{
		ClaimCode:        claimCode,
		StoredFilename:   "retrieve_test.dat",
		OriginalFilename: "file.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	repos.Files.Create(ctx, file)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		repos.Files.GetByClaimCode(ctx, claimCode)
	}
}

// BenchmarkDownloadCountIncrement benchmarks incrementing download count
func BenchmarkDownloadCountIncrement(b *testing.B) {
	t := &testing.T{}
	repos, _ := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create a file
	claimCode, _ := utils.GenerateClaimCode()
	file := &models.File{
		ClaimCode:        claimCode,
		StoredFilename:   "counter_test.dat",
		OriginalFilename: "file.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	repos.Files.Create(ctx, file)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		repos.Files.IncrementDownloadCount(ctx, file.ID)
	}
}

// BenchmarkSessionCreation benchmarks creating sessions
func BenchmarkSessionCreation(b *testing.B) {
	t := &testing.T{}
	repos, _ := testutil.SetupTestRepos(t)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		sessionToken, _ := utils.GenerateSessionToken()
		expiresAt := time.Now().Add(24 * time.Hour)
		repos.Admin.CreateSession(ctx, sessionToken, expiresAt, "127.0.0.1", "test-agent")
	}
}

// BenchmarkSessionValidation benchmarks validating sessions
func BenchmarkSessionValidation(b *testing.B) {
	t := &testing.T{}
	repos, _ := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create a session
	sessionToken, _ := utils.GenerateSessionToken()
	expiresAt := time.Now().Add(24 * time.Hour)
	repos.Admin.CreateSession(ctx, sessionToken, expiresAt, "127.0.0.1", "test-agent")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		repos.Admin.GetSession(ctx, sessionToken)
	}
}

// BenchmarkPartialUploadCreation benchmarks creating partial uploads
func BenchmarkPartialUploadCreation(b *testing.B) {
	t := &testing.T{}
	repos, _ := testutil.SetupTestRepos(t)
	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		uploadID := "benchmark-upload-" + string(rune('0'+(i%10)))
		partialUpload := &models.PartialUpload{
			UploadID:     uploadID,
			Filename:     "bench.bin",
			TotalSize:    1024,
			ChunkSize:    1024,
			TotalChunks:  1,
			CreatedAt:    time.Now(),
			LastActivity: time.Now(),
		}

		repos.PartialUploads.Create(ctx, partialUpload)
	}
}

// BenchmarkGetStats benchmarks getting storage statistics
func BenchmarkGetStats(b *testing.B) {
	t := &testing.T{}
	repos, _ := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create some files
	for i := 0; i < 100; i++ {
		claimCode, _ := utils.GenerateClaimCode()
		file := &models.File{
			ClaimCode:        claimCode,
			StoredFilename:   "stats_" + claimCode + ".dat",
			OriginalFilename: "file.txt",
			FileSize:         1024,
			MimeType:         "text/plain",
			ExpiresAt:        time.Now().Add(24 * time.Hour),
			UploaderIP:       "127.0.0.1",
		}
		repos.Files.Create(ctx, file)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		repos.Files.GetStats(ctx, ".")
	}
}

// BenchmarkConcurrentDatabaseOperations benchmarks concurrent database access
func BenchmarkConcurrentDatabaseOperations(b *testing.B) {
	t := &testing.T{}
	repos, _ := testutil.SetupTestRepos(t)
	ctx := context.Background()

	// Create some initial data
	claimCode, _ := utils.GenerateClaimCode()
	file := &models.File{
		ClaimCode:        claimCode,
		StoredFilename:   "concurrent.dat",
		OriginalFilename: "file.txt",
		FileSize:         1024,
		MimeType:         "text/plain",
		ExpiresAt:        time.Now().Add(24 * time.Hour),
		UploaderIP:       "127.0.0.1",
	}
	repos.Files.Create(ctx, file)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Mix of read and write operations
			repos.Files.GetByClaimCode(ctx, claimCode)
			repos.Files.IncrementDownloadCount(ctx, file.ID)
			repos.Files.GetStats(ctx, ".")
		}
	})
}

// BenchmarkPasswordHashing benchmarks bcrypt password hashing
func BenchmarkPasswordHashing(b *testing.B) {
	password := "testpassword123"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		utils.HashPassword(password)
	}
}

// BenchmarkPasswordVerification benchmarks bcrypt password verification
func BenchmarkPasswordVerification(b *testing.B) {
	password := "testpassword123"
	hash, _ := utils.HashPassword(password)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		utils.VerifyPassword(hash, password)
	}
}

// BenchmarkClaimCodeGeneration benchmarks generating claim codes
func BenchmarkClaimCodeGeneration(b *testing.B) {
	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		utils.GenerateClaimCode()
	}
}

// BenchmarkFilenameSanitization benchmarks filename sanitization
func BenchmarkFilenameSanitization(b *testing.B) {
	filename := "../../../dangerous/../../path/traversal/file.exe"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		utils.SanitizeFilename(filename)
	}
}

// BenchmarkIsFileAllowed benchmarks file extension validation
func BenchmarkIsFileAllowed(b *testing.B) {
	filename := "document.pdf"
	blockedExts := []string{"exe", "bat", "sh", "cmd", "com", "scr"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		utils.IsFileAllowed(filename, blockedExts)
	}
}
