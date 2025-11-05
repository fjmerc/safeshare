package utils

import (
	"golang.org/x/crypto/bcrypt"
)

const (
	// BcryptCost is the cost factor for bcrypt hashing
	// Higher = more secure but slower (range: 4-31, default: 10)
	BcryptCost = 10
)

// HashPassword hashes a plain text password using bcrypt
// Returns the hashed password or an error
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

// VerifyPassword checks if a plain text password matches a bcrypt hash
// Returns true if the password matches, false otherwise
func VerifyPassword(hashedPassword, password string) bool {
	// If no password hash is stored, no password is required
	if hashedPassword == "" {
		return password == ""
	}

	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// IsPasswordProtected returns true if a password hash is set
func IsPasswordProtected(passwordHash string) bool {
	return passwordHash != ""
}
