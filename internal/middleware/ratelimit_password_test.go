package middleware

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/fjmerc/safeshare/internal/models"
)

func TestKeyedAttemptLimiter_ReserveRefundReset(t *testing.T) {
	l := NewKeyedAttemptLimiter(3, 15*time.Minute)

	var tokens []uint64
	for i := 0; i < 3; i++ {
		ok, tok := l.Reserve("user:1")
		if !ok {
			t.Fatalf("reserve %d: got !ok, want ok", i+1)
		}
		tokens = append(tokens, tok)
	}
	if ok, _ := l.Reserve("user:1"); ok {
		t.Fatal("4th reserve: got ok, want over limit")
	}

	// Other keys are independent.
	if ok, _ := l.Reserve("user:2"); !ok {
		t.Fatal("other key: got !ok, want ok")
	}

	// A refund frees exactly one slot.
	l.Refund("user:1", tokens[0])
	if ok, _ := l.Reserve("user:1"); !ok {
		t.Fatal("reserve after refund: got !ok, want ok")
	}
	if ok, _ := l.Reserve("user:1"); ok {
		t.Fatal("second reserve after one refund: got ok, want over limit")
	}

	// Reset forgets every key, and a refund from before the reset can't
	// credit the recreated entry (its epoch is new).
	l.Reset()
	ok, _ := l.Reserve("user:1")
	if !ok {
		t.Fatal("reserve after reset: got !ok, want ok")
	}
	l.Refund("user:1", tokens[1])
	l.Refund("user:1", tokens[2])
	for i := 0; i < 2; i++ {
		if ok, _ := l.Reserve("user:1"); !ok {
			t.Fatalf("reserve %d after reset: got !ok, want ok", i+2)
		}
	}
	if ok, _ := l.Reserve("user:1"); ok {
		t.Fatal("stale pre-reset refunds credited the new window")
	}
}

// statusHandler returns a handler that always responds with status and
// counts how often it ran.
func statusHandler(status int, calls *int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*calls++
		w.WriteHeader(status)
	})
}

func TestRateLimitAdminChangePassword_OnlyWrongCurrentPasswordCounts(t *testing.T) {
	limiter := RateLimitAdminChangePassword(false)

	// Validation errors (400) and successes (200) never count.
	var calls int
	for _, status := range []int{http.StatusBadRequest, http.StatusOK} {
		h := limiter(statusHandler(status, &calls))
		for i := 0; i < 10; i++ {
			req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/password", nil)
			req.RemoteAddr = "192.168.1.60:1234"
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != status {
				t.Fatalf("status %d request %d: got %d", status, i+1, rr.Code)
			}
		}
	}

	// Wrong current password (401) counts: 5 reach the handler, the 6th is
	// rejected without running it - even from rotating IPs, since there's
	// one legacy admin password and so one shared budget.
	calls = 0
	h := limiter(statusHandler(http.StatusUnauthorized, &calls))
	for i := 0; i < 6; i++ {
		req := httptest.NewRequest(http.MethodPost, "/admin/api/settings/password", nil)
		req.RemoteAddr = fmt.Sprintf("192.168.2.%d:1234", i+1)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		want := http.StatusUnauthorized
		if i == 5 {
			want = http.StatusTooManyRequests
		}
		if rr.Code != want {
			t.Fatalf("request %d: got %d, want %d", i+1, rr.Code, want)
		}
	}
	if calls != 5 {
		t.Fatalf("handler ran %d times, want 5", calls)
	}
}

func TestRateLimitChangePassword_KeyedByUser(t *testing.T) {
	var calls int
	h := RateLimitChangePassword(false)(statusHandler(http.StatusUnauthorized, &calls))

	send := func(userID int64, ip string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/auth/change-password", nil)
		req.RemoteAddr = ip + ":1234"
		req = req.WithContext(context.WithValue(req.Context(), ContextKeyUser, &models.User{ID: userID}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		return rr.Code
	}

	// User 1 from rotating IPs still runs out after 5 wrong passwords.
	for i := 0; i < 5; i++ {
		if got := send(1, fmt.Sprintf("10.0.0.%d", i+1)); got != http.StatusUnauthorized {
			t.Fatalf("user 1 request %d: got %d, want 401", i+1, got)
		}
	}
	if got := send(1, "10.0.0.9"); got != http.StatusTooManyRequests {
		t.Fatalf("user 1 6th request: got %d, want 429", got)
	}

	// User 2 on the same IP is unaffected.
	if got := send(2, "10.0.0.9"); got != http.StatusUnauthorized {
		t.Fatalf("user 2: got %d, want 401", got)
	}
}

func TestMFAVerifyLoginSuccess(t *testing.T) {
	tests := []struct {
		status int
		want   bool
	}{
		{http.StatusOK, true},
		{http.StatusTooManyRequests, true}, // handler's own limits: refunded
		{http.StatusUnauthorized, false},
		{http.StatusBadRequest, false},
		{http.StatusInternalServerError, false},
	}
	for _, tt := range tests {
		if got := MFAVerifyLoginSuccess(tt.status, http.Header{}); got != tt.want {
			t.Errorf("MFAVerifyLoginSuccess(%d) = %v, want %v", tt.status, got, tt.want)
		}
	}
}
