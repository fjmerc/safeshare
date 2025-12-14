package handlers

import (
	"github.com/fjmerc/safeshare/internal/storage"
)

// storageBackend holds the shared storage backend instance.
// This is set during application initialization via SetStorageBackend.
var storageBackend storage.StorageBackend

// SetStorageBackend sets the storage backend to be used by handlers.
// This should be called during application initialization before any handlers are invoked.
func SetStorageBackend(sb storage.StorageBackend) {
	storageBackend = sb
}

// GetStorageBackend returns the configured storage backend.
// Returns nil if no storage backend has been configured.
func GetStorageBackend() storage.StorageBackend {
	return storageBackend
}
