package handlers

import (
	"testing"

	"github.com/fjmerc/safeshare/internal/storage/mock"
)

func TestSetStorageBackend(t *testing.T) {
	// Clear any existing backend
	storageBackend = nil

	// Create a mock storage backend
	mockBackend := mock.NewStorageBackend()

	// Set the backend
	SetStorageBackend(mockBackend)

	// Verify it was set correctly
	if storageBackend != mockBackend {
		t.Error("SetStorageBackend did not set the backend correctly")
	}
}

func TestGetStorageBackend(t *testing.T) {
	// Test with no backend set
	storageBackend = nil
	if GetStorageBackend() != nil {
		t.Error("GetStorageBackend should return nil when no backend is set")
	}

	// Set a mock backend
	mockBackend := mock.NewStorageBackend()
	storageBackend = mockBackend

	// Verify it returns the correct backend
	if GetStorageBackend() != mockBackend {
		t.Error("GetStorageBackend should return the set backend")
	}
}

func TestSetAndGetStorageBackend_RoundTrip(t *testing.T) {
	// Clear any existing backend
	storageBackend = nil

	// Create and set a mock backend
	mockBackend := mock.NewStorageBackend()
	SetStorageBackend(mockBackend)

	// Verify round-trip
	retrieved := GetStorageBackend()
	if retrieved != mockBackend {
		t.Error("Storage backend round-trip failed")
	}
}

func TestSetStorageBackend_Override(t *testing.T) {
	// Set initial backend
	backend1 := mock.NewStorageBackend()
	SetStorageBackend(backend1)

	// Override with a new backend
	backend2 := mock.NewStorageBackend()
	SetStorageBackend(backend2)

	// Verify the new backend is set
	if GetStorageBackend() != backend2 {
		t.Error("SetStorageBackend should override the previous backend")
	}
}

func TestSetStorageBackend_Nil(t *testing.T) {
	// Set a backend first
	mockBackend := mock.NewStorageBackend()
	SetStorageBackend(mockBackend)

	// Set to nil
	SetStorageBackend(nil)

	// Verify it was set to nil
	if GetStorageBackend() != nil {
		t.Error("SetStorageBackend should allow setting nil")
	}
}
