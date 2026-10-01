package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
	"github.com/fjmerc/safeshare/internal/repository"
	"github.com/fjmerc/safeshare/internal/utils"
	"github.com/pquerna/otp/totp"
)

func TestVerifyUserPassword(t *testing.T) {
	hash, err := utils.HashPassword("correct-horse")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	tests := []struct {
		name     string
		user     *models.User
		password string
		want     bool
	}{
		{"unknown user", nil, "correct-horse", false},
		{"empty hash never matches", &models.User{PasswordHash: ""}, "", false},
		{"empty hash with password", &models.User{PasswordHash: ""}, "anything", false},
		{"wrong password", &models.User{PasswordHash: hash}, "wrong", false},
		{"right password", &models.User{PasswordHash: hash}, "correct-horse", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verifyUserPassword(tt.user, tt.password); got != tt.want {
				t.Errorf("verifyUserPassword() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestVerifyUserPassword_UnknownUserRunsBcrypt checks that a missing user
// still pays for a full bcrypt comparison, so response time doesn't reveal
// whether a username exists. Cost-10 bcrypt takes tens of milliseconds;
// the skipped-compare path this replaced took microseconds.
func TestVerifyUserPassword_UnknownUserRunsBcrypt(t *testing.T) {
	hash, err := utils.HashPassword("correct-horse")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	known := &models.User{PasswordHash: hash}

	start := time.Now()
	verifyUserPassword(known, "wrong")
	knownElapsed := time.Since(start)

	start = time.Now()
	verifyUserPassword(nil, "wrong")
	unknownElapsed := time.Since(start)

	// Same order of magnitude as a real compare; the skipped-compare path
	// this replaced was thousands of times faster.
	if unknownElapsed < knownElapsed/4 {
		t.Errorf("unknown user took %v vs %v for a known user; expected a full bcrypt compare", unknownElapsed, knownElapsed)
	}
}

// setupTOTPUser creates a user with TOTP enabled and returns it with its
// TOTP secret.
func setupTOTPUser(t *testing.T, repos *repository.Repositories, username string) (*models.User, string) {
	t.Helper()
	ctx := context.Background()
	hash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	user, err := repos.Users.Create(ctx, username, username+"@example.com", hash, "user", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "SafeShare-Test", AccountName: username})
	if err != nil {
		t.Fatalf("generate TOTP: %v", err)
	}
	if err := repos.MFA.SetupTOTP(ctx, user.ID, key.Secret()); err != nil {
		t.Fatalf("setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("enable TOTP: %v", err)
	}
	return user, key.Secret()
}

// verifyOnFreshChallenge creates a new MFA challenge for userID bound to
// ip, submits code against it from ip, and returns the status and the
// challenge ID.
func verifyOnFreshChallenge(t *testing.T, h http.HandlerFunc, userID int64, ip, code string) (int, string) {
	t.Helper()
	challengeID, err := mfaLoginStore.Create(userID, ip, "TestAgent", 5)
	if err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	t.Cleanup(func() { mfaLoginStore.Delete(challengeID) })
	return verifyOnChallenge(h, challengeID, ip, code), challengeID
}

func verifyOnChallenge(h http.HandlerFunc, challengeID, ip, code string) int {
	body, _ := json.Marshal(MFAVerifyLoginRequest{ChallengeID: challengeID, Code: code})
	req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/verify", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":12345"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

// TestMFAVerifyLoginHandler_PerUserFailureLimit covers T48: wrong codes are
// limited per account across challenges and client IPs, and a per-user 429
// leaves the challenge intact.
func TestMFAVerifyLoginHandler_PerUserFailureLimit(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	user, secret := setupTOTPUser(t, repos, "victim")
	other, otherSecret := setupTOTPUser(t, repos, "bystander")
	h := MFAVerifyLoginHandler(repos, cfg)

	// Each wrong guess on its own fresh challenge from its own IP, so
	// neither the per-challenge cap nor any per-IP limit applies.
	ips := []string{"127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"}
	for i, ip := range ips {
		if got, _ := verifyOnFreshChallenge(t, h, user.ID, ip, "000000"); got != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: got %d, want 401", i+1, got)
		}
	}

	// Now even a correct code is refused for this account...
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	got, challengeID := verifyOnFreshChallenge(t, h, user.ID, "127.0.0.6", code)
	if got != http.StatusTooManyRequests {
		t.Fatalf("after 5 failures: got %d, want 429", got)
	}

	// ...but another account is unaffected.
	otherCode, err := totp.GenerateCode(otherSecret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if got, _ := verifyOnFreshChallenge(t, h, other.ID, "127.0.0.6", otherCode); got != http.StatusOK {
		t.Fatalf("other user: got %d, want 200", got)
	}

	// The per-user 429 neither consumed nor deleted the challenge: once
	// the window clears, the same challenge still works.
	mfaUserFailureLimiter.Reset()
	if got := verifyOnChallenge(h, challengeID, "127.0.0.6", code); got != http.StatusOK {
		t.Fatalf("same challenge after reset: got %d, want 200", got)
	}
}

// TestMFAVerifyLoginHandler_PerUserLimitRefundsSuccess checks that a
// correct code doesn't count toward the per-user limit.
func TestMFAVerifyLoginHandler_PerUserLimitRefundsSuccess(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	user, secret := setupTOTPUser(t, repos, "owner")
	h := MFAVerifyLoginHandler(repos, cfg)

	for i := 0; i < 4; i++ {
		if got, _ := verifyOnFreshChallenge(t, h, user.ID, "127.0.0.1", "000000"); got != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: got %d, want 401", i+1, got)
		}
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if got, _ := verifyOnFreshChallenge(t, h, user.ID, "127.0.0.1", code); got != http.StatusOK {
		t.Fatalf("correct code: got %d, want 200", got)
	}

	// 4 failures + a refunded success: one more failure is still allowed,
	// and only then is the account limited.
	if got, _ := verifyOnFreshChallenge(t, h, user.ID, "127.0.0.1", "000000"); got != http.StatusUnauthorized {
		t.Fatalf("5th wrong code: got %d, want 401", got)
	}
	if got, _ := verifyOnFreshChallenge(t, h, user.ID, "127.0.0.1", "000000"); got != http.StatusTooManyRequests {
		t.Fatalf("6th wrong code: got %d, want 429", got)
	}
}

// TestMFAVerifyLoginHandler_PerUserLimitIgnoresServerErrors checks that only
// a code actually checked and found wrong counts toward the per-user limit:
// server errors and an exhausted challenge are refunded.
func TestMFAVerifyLoginHandler_PerUserLimitIgnoresServerErrors(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()
	hash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	user, err := repos.Users.Create(ctx, "broken", "broken@example.com", hash, "user", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	// With encryption on, a stored secret that isn't valid base64 makes
	// every TOTP verification fail with a 500 before any code is checked.
	if err := repos.MFA.SetupTOTP(ctx, user.ID, "not-base64!!"); err != nil {
		t.Fatalf("setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("enable TOTP: %v", err)
	}
	cfg.EncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	h := MFAVerifyLoginHandler(repos, cfg)

	challengeID, err := mfaLoginStore.Create(user.ID, "127.0.0.1", "TestAgent", 5)
	if err != nil {
		t.Fatalf("create challenge: %v", err)
	}
	t.Cleanup(func() { mfaLoginStore.Delete(challengeID) })
	for i := 0; i < mfaMaxVerifyAttempts; i++ {
		if got := verifyOnChallenge(h, challengeID, "127.0.0.1", "000000"); got != http.StatusInternalServerError {
			t.Fatalf("request %d: got %d, want 500", i+1, got)
		}
	}
	// The challenge itself is now exhausted (its own 429, "log in again").
	if got := verifyOnChallenge(h, challengeID, "127.0.0.1", "000000"); got != http.StatusTooManyRequests {
		t.Fatalf("exhausted challenge: got %d, want 429", got)
	}

	// None of that counted against the account: with encryption off the
	// stored secret is used as-is and simply never matches, so the full
	// budget of 5 wrong codes is still available.
	cfg.EncryptionKey = ""
	for i := 0; i < mfaUserMaxFailures; i++ {
		if got, _ := verifyOnFreshChallenge(t, h, user.ID, "127.0.0.1", "000000"); got != http.StatusUnauthorized {
			t.Fatalf("wrong code %d: got %d, want 401", i+1, got)
		}
	}
	if got, _ := verifyOnFreshChallenge(t, h, user.ID, "127.0.0.1", "000000"); got != http.StatusTooManyRequests {
		t.Fatalf("after 5 wrong codes: got %d, want 429", got)
	}
}

// TestMFAVerifyLoginHandler_PerUserLimitCountsRecoveryCodes checks that
// wrong recovery codes share the per-user budget with TOTP codes.
func TestMFAVerifyLoginHandler_PerUserLimitCountsRecoveryCodes(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	user, _ := setupTOTPUser(t, repos, "recovery")
	// Only 2 stored codes: each wrong recovery code is bcrypt-compared
	// against every stored one, which is slow under the race detector.
	_, hashes, err := generateRecoveryCodes(2)
	if err != nil {
		t.Fatalf("generate recovery codes: %v", err)
	}
	if err := repos.MFA.CreateRecoveryCodes(context.Background(), user.ID, hashes); err != nil {
		t.Fatalf("store recovery codes: %v", err)
	}
	// A well-formed code that isn't one of the stored ones.
	wrongCodes, _, err := generateRecoveryCodes(1)
	if err != nil {
		t.Fatalf("generate wrong code: %v", err)
	}
	h := MFAVerifyLoginHandler(repos, cfg)

	submitRecovery := func() int {
		challengeID, err := mfaLoginStore.Create(user.ID, "127.0.0.1", "TestAgent", 5)
		if err != nil {
			t.Fatalf("create challenge: %v", err)
		}
		t.Cleanup(func() { mfaLoginStore.Delete(challengeID) })
		body, _ := json.Marshal(MFAVerifyLoginRequest{ChallengeID: challengeID, Code: wrongCodes[0], IsRecovery: true})
		req := httptest.NewRequest(http.MethodPost, "/api/auth/mfa/verify", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "127.0.0.1:12345"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	for i := 0; i < 3; i++ {
		if got := submitRecovery(); got != http.StatusUnauthorized {
			t.Fatalf("wrong recovery code %d: got %d, want 401", i+1, got)
		}
	}
	for i := 0; i < 2; i++ {
		if got, _ := verifyOnFreshChallenge(t, h, user.ID, "127.0.0.1", "000000"); got != http.StatusUnauthorized {
			t.Fatalf("wrong TOTP code %d: got %d, want 401", i+1, got)
		}
	}
	if got := submitRecovery(); got != http.StatusTooManyRequests {
		t.Fatalf("after 5 mixed failures: got %d, want 429", got)
	}
}

// TestMFAVerifyLoginHandler_TOTPRequiresEnrollment is a regression test: an
// account without TOTP enabled (e.g. security-key only) has no stored
// secret, and pquerna/otp accepts a code computed from an empty secret, so
// the TOTP branch must refuse it rather than let anyone with the password
// skip the security key.
func TestMFAVerifyLoginHandler_TOTPRequiresEnrollment(t *testing.T) {
	repos, cfg := setupMFATestEnv(t)
	ctx := context.Background()
	hash, err := utils.HashPassword("password123")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	user, err := repos.Users.Create(ctx, "keyonly", "keyonly@example.com", hash, "user", false)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	h := MFAVerifyLoginHandler(repos, cfg)

	emptySecretCode, err := totp.GenerateCode("", time.Now())
	if err != nil {
		t.Fatalf("generate empty-secret code: %v", err)
	}
	if !totp.Validate(emptySecretCode, "") {
		t.Fatal("precondition: library no longer accepts empty secrets; test needs updating")
	}

	// No TOTP enrollment at all.
	if got, _ := verifyOnFreshChallenge(t, h, user.ID, "127.0.0.1", emptySecretCode); got != http.StatusUnauthorized {
		t.Fatalf("no enrollment: got %d, want 401", got)
	}

	// Enrolled but then disabled (secret cleared).
	if err := repos.MFA.SetupTOTP(ctx, user.ID, "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatalf("setup TOTP: %v", err)
	}
	if err := repos.MFA.EnableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("enable TOTP: %v", err)
	}
	if err := repos.MFA.DisableTOTP(ctx, user.ID); err != nil {
		t.Fatalf("disable TOTP: %v", err)
	}
	if got, _ := verifyOnFreshChallenge(t, h, user.ID, "127.0.0.1", emptySecretCode); got != http.StatusUnauthorized {
		t.Fatalf("disabled TOTP: got %d, want 401", got)
	}
}
