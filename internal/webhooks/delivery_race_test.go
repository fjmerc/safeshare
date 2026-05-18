package webhooks

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// TestDeliverWebhook_ConcurrentMixedTimeoutsNoRace is the SH-1.3 regression
// test. Before the fix, DeliverWebhook reused a single *http.Client and
// mutated its Timeout field on every call from worker goroutines; running
// many concurrent deliveries with different configured timeouts produced a
// data race on http.Client.Timeout (detectable under `go test -race`) and
// in practice meant that one webhook's timeout could transiently apply to
// another delivery in flight.
//
// Under the post-SH-1.3 design (shared *http.Transport, per-call *http.Client)
// concurrent deliveries with mixed timeouts must run cleanly under the race
// detector and each delivery must observe its own configured timeout.
func TestDeliverWebhook_ConcurrentMixedTimeoutsNoRace(t *testing.T) {
	// httptest binds 127.0.0.1, which the SH-1.1 SSRF guard would reject.
	prev := SetAllowPrivateNetworks(true)
	t.Cleanup(func() { SetAllowPrivateNetworks(prev) })

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	// Mix of timeout values, deliberately wide-ranging so a stale-timeout
	// data race would be observable in the result (a 1s call accidentally
	// inheriting a 60s timeout would still pass; a 60s call accidentally
	// inheriting a 1s timeout against a slow target would fail — but the
	// httptest handler responds immediately, so the race detector is what
	// actually fails this test pre-fix).
	timeouts := []int{1, 2, 5, 10, 30, 60}
	const callsPerTimeout = 25
	total := len(timeouts) * callsPerTimeout

	results := make(chan bool, total)
	var wg sync.WaitGroup
	wg.Add(total)
	start := make(chan struct{})

	for _, to := range timeouts {
		for i := 0; i < callsPerTimeout; i++ {
			to := to
			go func() {
				defer wg.Done()
				<-start
				res := DeliverWebhook(server.URL, "s", `{"e":"t"}`, to)
				results <- res.Success
			}()
		}
	}

	close(start)
	wg.Wait()
	close(results)

	successes := 0
	for ok := range results {
		if ok {
			successes++
		}
	}
	if successes != total {
		t.Fatalf("expected all %d concurrent deliveries to succeed, got %d", total, successes)
	}
}

// TestNewWebhookClient_PerCallTimeout confirms that two clients built back-
// to-back with different timeouts have distinct Timeout values — i.e. that
// they are not aliasing a single struct.
func TestNewWebhookClient_PerCallTimeout(t *testing.T) {
	c1 := newWebhookClient(1)
	c2 := newWebhookClient(60)
	if c1 == c2 {
		t.Fatal("newWebhookClient returned the same *http.Client twice — must be per-call")
	}
	if c1.Timeout != time.Second {
		t.Errorf("c1.Timeout = %v, want 1s", c1.Timeout)
	}
	if c2.Timeout != 60*time.Second {
		t.Errorf("c2.Timeout = %v, want 60s", c2.Timeout)
	}
	if c1.Transport != c2.Transport {
		t.Errorf("clients should share the underlying *http.Transport (connection pool)")
	}
	// CheckRedirect is a function value; pointing every per-call client at
	// the same function (rather than capturing per-call state) is part of
	// the design — confirm it stays that way.
	if c1.CheckRedirect == nil || c2.CheckRedirect == nil {
		t.Fatal("CheckRedirect must be set on every per-call client (SSRF guard)")
	}
}
