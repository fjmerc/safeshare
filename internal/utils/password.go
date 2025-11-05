package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"

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

// GenerateTemporaryPassword generates a secure random temporary password
// Format: 4 words separated by dashes (e.g., "correct-horse-battery-staple")
// This is memorable for users to type once before changing
func GenerateTemporaryPassword() (string, error) {
	// Simple word list for memorable passwords
	words := []string{
		"alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
		"india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
		"quebec", "romeo", "sierra", "tango", "uniform", "victor", "whiskey", "xray",
		"yankee", "zulu", "apple", "banana", "cherry", "dragon", "eagle", "falcon",
		"giraffe", "hawk", "iguana", "jaguar", "koala", "lion", "monkey", "newt",
		"octopus", "panda", "quail", "rabbit", "snake", "tiger", "unicorn", "vulture",
		"walrus", "yak", "zebra", "forest", "mountain", "ocean", "river", "storm",
		"thunder", "wind", "fire", "earth", "water", "cloud", "star", "moon",
	}

	// Select 3 random words
	var result string
	for i := 0; i < 3; i++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
		if err != nil {
			return "", err
		}
		if i > 0 {
			result += "-"
		}
		result += words[n.Int64()]
	}

	// Add a random number (100-999)
	n, err := rand.Int(rand.Reader, big.NewInt(900))
	if err != nil {
		return "", err
	}

	result += fmt.Sprintf("-%d", n.Int64()+100)

	return result, nil
}
