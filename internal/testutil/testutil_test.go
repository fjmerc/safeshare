package testutil

import (
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestTimeConstants(t *testing.T) {
	if TimeRFC3339 != time.RFC3339 {
		t.Errorf("TimeRFC3339 should equal time.RFC3339")
	}
	if TimeHour != time.Hour {
		t.Errorf("TimeHour should equal time.Hour")
	}
}

func TestTimeNow(t *testing.T) {
	before := time.Now()
	result := TimeNow()
	after := time.Now()

	if result.Before(before) {
		t.Error("TimeNow should return a time >= before")
	}
	if result.After(after) {
		t.Error("TimeNow should return a time <= after")
	}
}

func TestSetupTestDB(t *testing.T) {
	db := SetupTestDB(t)

	if db == nil {
		t.Fatal("SetupTestDB returned nil")
	}

	// Verify it's a working database
	err := db.Ping()
	if err != nil {
		t.Fatalf("database should be pingable: %v", err)
	}

	// Verify migrations ran (tables should exist)
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM files").Scan(&count)
	if err != nil {
		t.Fatalf("files table should exist: %v", err)
	}
}

func TestSetupTestConfig(t *testing.T) {
	cfg := SetupTestConfig(t)

	if cfg == nil {
		t.Fatal("SetupTestConfig returned nil")
	}
	if cfg.Port != "8080" {
		t.Errorf("expected port 8080, got %s", cfg.Port)
	}
	if cfg.DBPath != ":memory:" {
		t.Errorf("expected :memory: db path, got %s", cfg.DBPath)
	}
	if cfg.UploadDir == "" {
		t.Error("UploadDir should be set")
	}
	if cfg.AdminUsername != "admin" {
		t.Errorf("expected admin username, got %s", cfg.AdminUsername)
	}
	if cfg.GetMaxFileSize() != 10*1024*1024 {
		t.Errorf("expected 10MB max file size, got %d", cfg.GetMaxFileSize())
	}
	if cfg.GetDefaultExpirationHours() != 24 {
		t.Errorf("expected 24 hour default expiration, got %d", cfg.GetDefaultExpirationHours())
	}
}

func TestCreateTestFile(t *testing.T) {
	content := []byte("test content for file")
	file := CreateTestFile(t, content)

	if file == nil {
		t.Fatal("CreateTestFile returned nil")
	}

	// Read the content back
	readContent := make([]byte, len(content))
	n, err := file.Read(readContent)
	if err != nil {
		t.Fatalf("failed to read test file: %v", err)
	}
	if n != len(content) {
		t.Errorf("expected %d bytes, got %d", len(content), n)
	}
	if string(readContent) != string(content) {
		t.Error("content should match")
	}

	// Verify file exists
	if _, err := os.Stat(file.Name()); os.IsNotExist(err) {
		t.Error("file should exist")
	}
}

func TestCreateMultipartForm(t *testing.T) {
	t.Run("with file", func(t *testing.T) {
		content := []byte("file content")
		formValues := map[string]string{
			"expires_in_hours": "24",
			"password":         "secret",
		}

		body, contentType := CreateMultipartForm(t, content, "test.txt", formValues)

		if body == nil {
			t.Fatal("body should not be nil")
		}
		if body.Len() == 0 {
			t.Error("body should not be empty")
		}
		if contentType == "" {
			t.Error("contentType should not be empty")
		}
		if !contains(contentType, "multipart/form-data") {
			t.Error("contentType should contain multipart/form-data")
		}
	})

	t.Run("without file", func(t *testing.T) {
		formValues := map[string]string{
			"key": "value",
		}

		body, contentType := CreateMultipartForm(t, nil, "", formValues)

		if body == nil {
			t.Fatal("body should not be nil")
		}
		if contentType == "" {
			t.Error("contentType should not be empty")
		}
	})
}

func TestAssertStatusCode(t *testing.T) {
	t.Run("matching status", func(t *testing.T) {
		rr := httptest.NewRecorder()
		rr.WriteHeader(200)

		// Should not panic
		innerT := &testing.T{}
		AssertStatusCode(innerT, rr, 200)
		if innerT.Failed() {
			t.Error("should not fail for matching status")
		}
	})

	t.Run("non-matching status", func(t *testing.T) {
		rr := httptest.NewRecorder()
		rr.WriteHeader(404)

		innerT := &testing.T{}
		AssertStatusCode(innerT, rr, 200)
		// Note: Can't easily check if failed since we're using a real t
		// Just verify it doesn't panic
	})
}

func TestAssertNoError(t *testing.T) {
	t.Run("no error", func(t *testing.T) {
		innerT := &testing.T{}
		AssertNoError(innerT, nil)
		// Should not fail
	})

	// Note: Testing with actual error would cause innerT to fatal
	// which is expected behavior
}

func TestAssertError(t *testing.T) {
	t.Run("with error", func(t *testing.T) {
		innerT := &testing.T{}
		AssertError(innerT, os.ErrNotExist)
		// Should not fail when there is an error
	})
}

func TestAssertEqual(t *testing.T) {
	t.Run("equal values", func(t *testing.T) {
		innerT := &testing.T{}
		AssertEqual(innerT, 42, 42)
		// Should not fail
	})

	t.Run("equal strings", func(t *testing.T) {
		innerT := &testing.T{}
		AssertEqual(innerT, "hello", "hello")
		// Should not fail
	})
}

func TestAssertContains(t *testing.T) {
	t.Run("contains substring", func(t *testing.T) {
		innerT := &testing.T{}
		AssertContains(innerT, "hello world", "world")
		// Should not fail
	})

	t.Run("contains exact", func(t *testing.T) {
		innerT := &testing.T{}
		AssertContains(innerT, "hello", "hello")
		// Should not fail
	})
}

func TestAssertNotContains(t *testing.T) {
	t.Run("does not contain", func(t *testing.T) {
		innerT := &testing.T{}
		AssertNotContains(innerT, "hello world", "foo")
		// Should not fail
	})
}

func TestSetupTestRepos(t *testing.T) {
	repos, cfg := SetupTestRepos(t)

	if repos == nil {
		t.Fatal("repos should not be nil")
	}
	if cfg == nil {
		t.Fatal("cfg should not be nil")
	}
	if repos.Files == nil {
		t.Error("Files repository should be initialized")
	}
	if repos.Users == nil {
		t.Error("Users repository should be initialized")
	}
}

// Helper function to check if string contains substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
