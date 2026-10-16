package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync/atomic"

	"github.com/fjmerc/safeshare/internal/claimcode"
)

// claimCodeLength is the process-wide length of newly generated claim codes.
// It is set once at startup from CLAIM_CODE_LENGTH (and by the CLI tools that
// write the database directly); every generator, including the repository
// layer's claim-code regeneration which has no config access, reads it here.
var claimCodeLength atomic.Int32

func init() {
	claimCodeLength.Store(claimcode.DefaultLength)
}

// SetClaimCodeLength sets the length of newly generated claim codes. Values
// outside the accepted claim-code range are rejected so a bad call can never
// produce codes that fail ValidateClaimCode.
func SetClaimCodeLength(n int) error {
	if !claimcode.ValidLength(n) {
		return fmt.Errorf("claim code length must be between %d and %d, got %d",
			claimcode.MinLength, claimcode.MaxLength, n)
	}
	claimCodeLength.Store(int32(n))
	return nil
}

// ClaimCodeLength returns the length GenerateClaimCode currently produces.
func ClaimCodeLength() int {
	return int(claimCodeLength.Load())
}

// GenerateClaimCode generates a cryptographically secure random claim code
// of the configured length (default 16). The code is URL-safe.
func GenerateClaimCode() (string, error) {
	return GenerateClaimCodeN(ClaimCodeLength())
}

// GenerateClaimCodeN generates a cryptographically secure random claim code of
// exactly n URL-safe base64 characters (6 bits of entropy each).
func GenerateClaimCodeN(n int) (string, error) {
	if !claimcode.ValidLength(n) {
		return "", fmt.Errorf("claim code length must be between %d and %d, got %d",
			claimcode.MinLength, claimcode.MaxLength, n)
	}

	// ceil(6n/8) bytes encode to at least n unpadded base64 characters.
	buf := make([]byte, (n*6+7)/8)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(buf)[:n], nil
}
