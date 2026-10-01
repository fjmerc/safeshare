package main

import (
	"strings"
	"testing"

	"github.com/fjmerc/safeshare/internal/config"
)

func TestRequireWiredBackends(t *testing.T) {
	tests := []struct {
		name        string
		dbType      string
		storageType string
		wantErr     string
	}{
		{name: "defaults", dbType: "sqlite", storageType: "filesystem"},
		{name: "empty values", dbType: "", storageType: ""},
		{name: "postgresql refused", dbType: "postgresql", storageType: "filesystem", wantErr: "DATABASE_TYPE=postgresql"},
		{name: "s3 refused", dbType: "sqlite", storageType: "s3", wantErr: "STORAGE_TYPE=s3"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{DatabaseType: tt.dbType, StorageType: tt.storageType}
			err := requireWiredBackends(cfg)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want one mentioning %q", err, tt.wantErr)
			}
		})
	}
}
