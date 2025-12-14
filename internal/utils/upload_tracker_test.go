package utils

import (
	"context"
	"sync"
	"testing"
	"time"
)

// TestNewUploadTracker tests creation of upload tracker
func TestNewUploadTracker(t *testing.T) {
	tracker := NewUploadTracker()

	if tracker == nil {
		t.Fatal("NewUploadTracker() returned nil")
	}

	if tracker.GetActiveCount() != 0 {
		t.Errorf("GetActiveCount() = %d, want 0", tracker.GetActiveCount())
	}

	if tracker.IsShuttingDown() {
		t.Error("IsShuttingDown() should be false initially")
	}
}

// TestStartUpload tests starting an upload
func TestStartUpload(t *testing.T) {
	tracker := NewUploadTracker()

	ok := tracker.StartUpload("upload-1", "test.txt", 1024)
	if !ok {
		t.Error("StartUpload() returned false")
	}

	if tracker.GetActiveCount() != 1 {
		t.Errorf("GetActiveCount() = %d, want 1", tracker.GetActiveCount())
	}
}

// TestStartUpload_Multiple tests starting multiple uploads
func TestStartUpload_Multiple(t *testing.T) {
	tracker := NewUploadTracker()

	tracker.StartUpload("upload-1", "file1.txt", 1024)
	tracker.StartUpload("upload-2", "file2.txt", 2048)
	tracker.StartUpload("upload-3", "file3.txt", 4096)

	if tracker.GetActiveCount() != 3 {
		t.Errorf("GetActiveCount() = %d, want 3", tracker.GetActiveCount())
	}
}

// TestFinishUpload tests finishing an upload
func TestFinishUpload(t *testing.T) {
	tracker := NewUploadTracker()

	tracker.StartUpload("upload-1", "test.txt", 1024)
	tracker.FinishUpload("upload-1")

	if tracker.GetActiveCount() != 0 {
		t.Errorf("GetActiveCount() = %d, want 0", tracker.GetActiveCount())
	}
}

// TestFinishUpload_NonExistent tests finishing a non-existent upload
func TestFinishUpload_NonExistent(t *testing.T) {
	tracker := NewUploadTracker()

	// Should not panic
	tracker.FinishUpload("non-existent")

	if tracker.GetActiveCount() != 0 {
		t.Errorf("GetActiveCount() = %d, want 0", tracker.GetActiveCount())
	}
}

// TestGetActiveUploads tests retrieving active uploads
func TestGetActiveUploads(t *testing.T) {
	tracker := NewUploadTracker()

	tracker.StartUpload("upload-1", "file1.txt", 1024)
	tracker.StartUpload("upload-2", "file2.txt", 2048)

	uploads := tracker.GetActiveUploads()
	if len(uploads) != 2 {
		t.Errorf("len(uploads) = %d, want 2", len(uploads))
	}

	// Verify upload details
	uploadMap := make(map[string]activeUpload)
	for _, u := range uploads {
		uploadMap[u.ID] = u
	}

	if u, ok := uploadMap["upload-1"]; !ok {
		t.Error("upload-1 not found")
	} else {
		if u.Filename != "file1.txt" {
			t.Errorf("upload-1 Filename = %q, want %q", u.Filename, "file1.txt")
		}
		if u.Size != 1024 {
			t.Errorf("upload-1 Size = %d, want 1024", u.Size)
		}
	}
}

// TestBeginShutdown tests shutdown initiation
func TestBeginShutdown(t *testing.T) {
	tracker := NewUploadTracker()

	if tracker.IsShuttingDown() {
		t.Error("IsShuttingDown() should be false before BeginShutdown()")
	}

	tracker.BeginShutdown()

	if !tracker.IsShuttingDown() {
		t.Error("IsShuttingDown() should be true after BeginShutdown()")
	}
}

// TestBeginShutdown_DoubleCall tests calling BeginShutdown twice
func TestBeginShutdown_DoubleCall(t *testing.T) {
	tracker := NewUploadTracker()

	tracker.BeginShutdown()
	// Second call should not panic
	tracker.BeginShutdown()

	if !tracker.IsShuttingDown() {
		t.Error("IsShuttingDown() should be true")
	}
}

// TestStartUpload_DuringShutdown tests that new uploads are rejected during shutdown
func TestStartUpload_DuringShutdown(t *testing.T) {
	tracker := NewUploadTracker()

	tracker.BeginShutdown()

	ok := tracker.StartUpload("upload-1", "test.txt", 1024)
	if ok {
		t.Error("StartUpload() should return false during shutdown")
	}

	if tracker.GetActiveCount() != 0 {
		t.Errorf("GetActiveCount() = %d, want 0", tracker.GetActiveCount())
	}
}

// TestShutdownCh tests the shutdown channel
func TestShutdownCh(t *testing.T) {
	tracker := NewUploadTracker()

	ch := tracker.ShutdownCh()

	// Channel should not be closed initially
	select {
	case <-ch:
		t.Error("ShutdownCh should not be closed initially")
	default:
		// Expected
	}

	tracker.BeginShutdown()

	// Channel should be closed after shutdown
	select {
	case <-ch:
		// Expected
	default:
		t.Error("ShutdownCh should be closed after BeginShutdown()")
	}
}

// TestStartAssembly tests starting an assembly worker
func TestStartAssembly(t *testing.T) {
	tracker := NewUploadTracker()

	ok := tracker.StartAssembly("upload-1")
	if !ok {
		t.Error("StartAssembly() returned false")
	}

	// Finish to avoid blocking
	tracker.FinishAssembly("upload-1")
}

// TestStartAssembly_DuringShutdown tests that new assemblies are rejected during shutdown
func TestStartAssembly_DuringShutdown(t *testing.T) {
	tracker := NewUploadTracker()

	tracker.BeginShutdown()

	ok := tracker.StartAssembly("upload-1")
	if ok {
		t.Error("StartAssembly() should return false during shutdown")
	}
}

// TestFinishAssembly tests finishing an assembly worker
func TestFinishAssembly(t *testing.T) {
	tracker := NewUploadTracker()

	tracker.StartAssembly("upload-1")
	// Should not panic
	tracker.FinishAssembly("upload-1")
}

// TestWaitForUploads_NoUploads tests waiting when there are no uploads
func TestWaitForUploads_NoUploads(t *testing.T) {
	tracker := NewUploadTracker()

	completed := tracker.WaitForUploads(100 * time.Millisecond)
	if !completed {
		t.Error("WaitForUploads() should return true when no uploads")
	}
}

// TestWaitForUploads_WithUploads tests waiting for uploads to complete
func TestWaitForUploads_WithUploads(t *testing.T) {
	tracker := NewUploadTracker()

	tracker.StartUpload("upload-1", "test.txt", 1024)

	// Finish upload in background
	go func() {
		time.Sleep(10 * time.Millisecond)
		tracker.FinishUpload("upload-1")
	}()

	completed := tracker.WaitForUploads(1 * time.Second)
	if !completed {
		t.Error("WaitForUploads() should return true when uploads complete")
	}
}

// TestWaitForUploads_Timeout tests timeout during wait
func TestWaitForUploads_Timeout(t *testing.T) {
	tracker := NewUploadTracker()

	tracker.StartUpload("upload-1", "test.txt", 1024)
	// Don't finish the upload

	completed := tracker.WaitForUploads(50 * time.Millisecond)
	if completed {
		t.Error("WaitForUploads() should return false on timeout")
	}

	// Clean up
	tracker.FinishUpload("upload-1")
}

// TestWaitForUploadsWithContext_NoUploads tests context-based waiting with no uploads
func TestWaitForUploadsWithContext_NoUploads(t *testing.T) {
	tracker := NewUploadTracker()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	completed := tracker.WaitForUploadsWithContext(ctx)
	if !completed {
		t.Error("WaitForUploadsWithContext() should return true when no uploads")
	}
}

// TestWaitForUploadsWithContext_Cancelled tests context cancellation during wait
func TestWaitForUploadsWithContext_Cancelled(t *testing.T) {
	tracker := NewUploadTracker()

	tracker.StartUpload("upload-1", "test.txt", 1024)
	// Don't finish the upload

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	completed := tracker.WaitForUploadsWithContext(ctx)
	if completed {
		t.Error("WaitForUploadsWithContext() should return false when context cancelled")
	}

	// Clean up
	tracker.FinishUpload("upload-1")
}

// TestWaitForUploads_WithAssembly tests waiting for assembly workers to complete
func TestWaitForUploads_WithAssembly(t *testing.T) {
	tracker := NewUploadTracker()

	tracker.StartAssembly("upload-1")

	// Finish assembly in background
	go func() {
		time.Sleep(10 * time.Millisecond)
		tracker.FinishAssembly("upload-1")
	}()

	completed := tracker.WaitForUploads(1 * time.Second)
	if !completed {
		t.Error("WaitForUploads() should return true when assemblies complete")
	}
}

// TestGetUploadTracker tests the global tracker singleton
func TestGetUploadTracker(t *testing.T) {
	// Reset to ensure clean state
	ResetUploadTracker()

	tracker1 := GetUploadTracker()
	tracker2 := GetUploadTracker()

	if tracker1 != tracker2 {
		t.Error("GetUploadTracker() should return the same instance")
	}

	// Clean up
	ResetUploadTracker()
}

// TestResetUploadTracker tests resetting the global tracker
func TestResetUploadTracker(t *testing.T) {
	tracker1 := GetUploadTracker()
	tracker1.StartUpload("test", "test.txt", 100)

	ResetUploadTracker()

	tracker2 := GetUploadTracker()
	if tracker2.GetActiveCount() != 0 {
		t.Error("ResetUploadTracker() should create a fresh tracker")
	}

	// Clean up
	ResetUploadTracker()
}

// TestConcurrentUploads tests concurrent upload tracking
func TestConcurrentUploads(t *testing.T) {
	tracker := NewUploadTracker()

	var wg sync.WaitGroup
	numUploads := 100

	// Start uploads concurrently
	for i := 0; i < numUploads; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			uploadID := string(rune('A' + id%26)) + string(rune('0'+id%10))
			tracker.StartUpload(uploadID, "file.txt", 1024)
		}(i)
	}

	wg.Wait()

	// Should have some uploads (exact count depends on timing)
	count := tracker.GetActiveCount()
	if count == 0 {
		t.Error("Expected some active uploads")
	}

	// Finish all uploads
	uploads := tracker.GetActiveUploads()
	for _, u := range uploads {
		tracker.FinishUpload(u.ID)
	}

	if tracker.GetActiveCount() != 0 {
		t.Errorf("GetActiveCount() = %d, want 0 after finishing all", tracker.GetActiveCount())
	}
}
