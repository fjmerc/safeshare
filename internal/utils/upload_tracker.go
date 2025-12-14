// Package utils provides utility functions for SafeShare.
package utils

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// UploadTracker tracks in-progress uploads for graceful shutdown.
// It provides a mechanism to wait for all uploads to complete before shutting down.
type UploadTracker struct {
	mu            sync.RWMutex
	activeUploads map[string]*activeUpload
	wg            sync.WaitGroup
	assemblyWg    sync.WaitGroup // Tracks async assembly workers
	shuttingDown  atomic.Bool
	shutdownCh    chan struct{}
}

// activeUpload represents an in-progress upload operation.
type activeUpload struct {
	ID        string
	StartTime time.Time
	Filename  string
	Size      int64
}

// NewUploadTracker creates a new UploadTracker.
func NewUploadTracker() *UploadTracker {
	return &UploadTracker{
		activeUploads: make(map[string]*activeUpload),
		shutdownCh:    make(chan struct{}),
	}
}

// StartUpload registers a new upload as in-progress.
// Returns false if the server is shutting down and new uploads are not accepted.
func (ut *UploadTracker) StartUpload(id, filename string, size int64) bool {
	ut.mu.Lock()
	defer ut.mu.Unlock()

	// Check shutdown status inside lock to avoid TOCTOU race condition
	if ut.shuttingDown.Load() {
		return false
	}

	ut.activeUploads[id] = &activeUpload{
		ID:        id,
		StartTime: time.Now(),
		Filename:  filename,
		Size:      size,
	}
	ut.wg.Add(1)

	slog.Debug("upload started",
		"upload_id", id,
		"filename", filename,
		"size", size,
		"active_uploads", len(ut.activeUploads),
	)

	return true
}

// FinishUpload marks an upload as completed.
func (ut *UploadTracker) FinishUpload(id string) {
	ut.mu.Lock()
	defer ut.mu.Unlock()

	if _, exists := ut.activeUploads[id]; exists {
		delete(ut.activeUploads, id)
		ut.wg.Done()

		slog.Debug("upload finished",
			"upload_id", id,
			"active_uploads", len(ut.activeUploads),
		)
	} else {
		slog.Warn("FinishUpload called for non-existent upload",
			"upload_id", id,
			"active_uploads", len(ut.activeUploads),
		)
	}
}

// GetActiveCount returns the number of active uploads.
func (ut *UploadTracker) GetActiveCount() int {
	ut.mu.RLock()
	defer ut.mu.RUnlock()
	return len(ut.activeUploads)
}

// StartAssembly registers a new assembly worker.
// Returns false if the server is shutting down.
func (ut *UploadTracker) StartAssembly(uploadID string) bool {
	ut.mu.Lock()
	defer ut.mu.Unlock()

	if ut.shuttingDown.Load() {
		return false
	}

	ut.assemblyWg.Add(1)
	slog.Debug("assembly started", "upload_id", uploadID)
	return true
}

// FinishAssembly marks an assembly worker as completed.
func (ut *UploadTracker) FinishAssembly(uploadID string) {
	ut.assemblyWg.Done()
	slog.Debug("assembly finished", "upload_id", uploadID)
}

// GetActiveUploads returns information about all active uploads.
func (ut *UploadTracker) GetActiveUploads() []activeUpload {
	ut.mu.RLock()
	defer ut.mu.RUnlock()

	uploads := make([]activeUpload, 0, len(ut.activeUploads))
	for _, u := range ut.activeUploads {
		uploads = append(uploads, *u)
	}
	return uploads
}

// IsShuttingDown returns true if the server is in shutdown mode.
func (ut *UploadTracker) IsShuttingDown() bool {
	return ut.shuttingDown.Load()
}

// ShutdownCh returns a channel that is closed when shutdown begins.
// Handlers can select on this channel to detect shutdown.
func (ut *UploadTracker) ShutdownCh() <-chan struct{} {
	return ut.shutdownCh
}

// BeginShutdown signals that the server is shutting down.
// New uploads will be rejected after this call.
func (ut *UploadTracker) BeginShutdown() {
	if ut.shuttingDown.CompareAndSwap(false, true) {
		close(ut.shutdownCh)
		slog.Info("upload tracker: shutdown initiated, rejecting new uploads",
			"active_uploads", ut.GetActiveCount(),
		)
	}
}

// WaitForUploads waits for all active uploads and assembly workers to complete with a timeout.
// Returns true if all operations completed, false if timeout was reached.
func (ut *UploadTracker) WaitForUploads(timeout time.Duration) bool {
	ut.BeginShutdown()

	done := make(chan struct{})
	go func() {
		ut.wg.Wait()       // Wait for active uploads
		ut.assemblyWg.Wait() // Wait for assembly workers
		close(done)
	}()

	select {
	case <-done:
		slog.Info("upload tracker: all uploads and assemblies completed gracefully")
		return true
	case <-time.After(timeout):
		active := ut.GetActiveUploads()
		slog.Warn("upload tracker: timeout waiting for operations to complete",
			"remaining_uploads", len(active),
		)
		for _, u := range active {
			slog.Warn("upload tracker: abandoned upload",
				"upload_id", u.ID,
				"filename", u.Filename,
				"duration", time.Since(u.StartTime),
			)
		}
		return false
	}
}

// WaitForUploadsWithContext waits for all active uploads and assembly workers to complete,
// respecting context cancellation.
// Returns true if all operations completed, false if context was cancelled.
func (ut *UploadTracker) WaitForUploadsWithContext(ctx context.Context) bool {
	ut.BeginShutdown()

	done := make(chan struct{})
	go func() {
		ut.wg.Wait()       // Wait for active uploads
		ut.assemblyWg.Wait() // Wait for assembly workers
		close(done)
	}()

	select {
	case <-done:
		slog.Info("upload tracker: all uploads and assemblies completed gracefully")
		return true
	case <-ctx.Done():
		active := ut.GetActiveUploads()
		slog.Warn("upload tracker: context cancelled while waiting for operations",
			"remaining_uploads", len(active),
			"error", ctx.Err(),
		)
		return false
	}
}

// Global upload tracker instance
var globalUploadTracker *UploadTracker
var uploadTrackerOnce sync.Once

// GetUploadTracker returns the global upload tracker instance.
func GetUploadTracker() *UploadTracker {
	uploadTrackerOnce.Do(func() {
		globalUploadTracker = NewUploadTracker()
	})
	return globalUploadTracker
}

// ResetUploadTracker resets the global upload tracker (for testing only).
func ResetUploadTracker() {
	uploadTrackerOnce = sync.Once{}
	globalUploadTracker = nil
}
