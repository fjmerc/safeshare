// Package audit writes and verifies SafeShare's tamper-evident audit log
// (ADR-018): every entry is HMAC-signed over all of its fields and chained
// to the one before it.
package audit

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// KeyFileName is the auto-generated key's file name, next to the database.
const KeyFileName = "audit.key"

// Key is the secret the audit log is signed with.
type Key struct {
	secret []byte
	// ID names the key without revealing it, so an entry signed with a
	// different key can be told apart from a tampered one.
	ID string
	// Source says where the key came from, for the startup log line.
	Source string
}

func newKey(secret []byte, source string) Key {
	sum := sha256.Sum256(append([]byte("safeshare-audit-key-id:"), secret...))
	return Key{secret: secret, ID: hex.EncodeToString(sum[:8]), Source: source}
}

// LoadKey returns the audit signing key: AUDIT_LOG_KEY (64 hex characters)
// if set, otherwise the key in dir/audit.key, generated on first start.
// The key must not live in the database - anyone able to rewrite the
// database could then re-sign what they changed.
func LoadKey(envValue, dir string) (Key, error) {
	if envValue = strings.TrimSpace(envValue); envValue != "" {
		secret, err := hex.DecodeString(envValue)
		if err != nil || len(secret) != 32 {
			return Key{}, errors.New("AUDIT_LOG_KEY must be 64 hexadecimal characters (32 bytes)")
		}
		return newKey(secret, "AUDIT_LOG_KEY"), nil
	}

	path := filepath.Join(dir, KeyFileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return createKeyFile(path)
	}
	if err != nil {
		return Key{}, fmt.Errorf("failed to read audit log key %s: %w", path, err)
	}
	secret, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(secret) != 32 {
		return Key{}, fmt.Errorf("audit log key %s is not 64 hexadecimal characters", path)
	}
	return newKey(secret, path), nil
}

func createKeyFile(path string) (Key, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return Key{}, fmt.Errorf("failed to generate audit log key: %w", err)
	}
	// O_EXCL: if another instance sharing this directory created it a
	// moment ago, use that one rather than overwriting it.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return LoadKey("", filepath.Dir(path))
	}
	if err != nil {
		return Key{}, fmt.Errorf("failed to create audit log key %s: %w", path, err)
	}
	if _, err := f.WriteString(hex.EncodeToString(secret) + "\n"); err != nil {
		f.Close()
		_ = os.Remove(path)
		return Key{}, fmt.Errorf("failed to write audit log key %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return Key{}, fmt.Errorf("failed to write audit log key %s: %w", path, err)
	}
	return newKey(secret, path+" (generated)"), nil
}
