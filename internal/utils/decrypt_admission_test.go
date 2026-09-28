package utils

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestDecryptAdmission_Nil_AlwaysAdmits(t *testing.T) {
	var d *DecryptAdmission
	if _, err := d.Acquire(context.Background(), 1<<30); err != nil {
		t.Fatalf("nil DecryptAdmission.Acquire returned error: %v", err)
	}
	d.Release(1 << 30) // must not panic
	if got := d.Capacity(); got != 0 {
		t.Errorf("nil Capacity() = %d, want 0", got)
	}
}

func TestNewDecryptAdmission_NonPositiveDisables(t *testing.T) {
	if d := NewDecryptAdmission(0); d != nil {
		t.Errorf("NewDecryptAdmission(0) = %v, want nil", d)
	}
	if d := NewDecryptAdmission(-1); d != nil {
		t.Errorf("NewDecryptAdmission(-1) = %v, want nil", d)
	}
}

func TestDecryptAdmission_AcquireRelease_WithinCapacity(t *testing.T) {
	d := NewDecryptAdmission(100)
	if _, err := d.Acquire(context.Background(), 60); err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	if _, err := d.Acquire(context.Background(), 40); err != nil {
		t.Fatalf("second acquire (fits exactly): %v", err)
	}
	d.Release(60)
	d.Release(40)

	// After releasing everything, a full-capacity acquire must succeed
	// immediately.
	if _, err := d.Acquire(context.Background(), 100); err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	d.Release(100)
}

func TestDecryptAdmission_BlocksUntilReleased(t *testing.T) {
	d := NewDecryptAdmission(10)
	if _, err := d.Acquire(context.Background(), 10); err != nil {
		t.Fatalf("initial acquire: %v", err)
	}

	acquired := make(chan struct{})
	go func() {
		if _, err := d.Acquire(context.Background(), 10); err != nil {
			t.Errorf("blocked acquire failed: %v", err)
		}
		close(acquired)
	}()

	select {
	case <-acquired:
		t.Fatal("second acquire completed before the first was released")
	case <-time.After(100 * time.Millisecond):
	}

	d.Release(10)

	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("second acquire did not complete after release")
	}
	d.Release(10)
}

func TestDecryptAdmission_ContextTimeout(t *testing.T) {
	d := NewDecryptAdmission(10)
	if _, err := d.Acquire(context.Background(), 10); err != nil {
		t.Fatalf("initial acquire: %v", err)
	}
	defer d.Release(10)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := d.Acquire(ctx, 10)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected Acquire to fail once the budget is exhausted and ctx times out")
	}
	if elapsed > 2*time.Second {
		t.Errorf("Acquire took %v to observe ctx timeout, want well under 2s", elapsed)
	}
}

func TestDecryptAdmission_OversizedWeightClampedToCapacity(t *testing.T) {
	d := NewDecryptAdmission(10)
	// A weight larger than capacity must still be admittable alone rather
	// than rejected outright, and Acquire must report the actual (clamped)
	// weight admitted — not the requested one — so callers release exactly
	// what was reserved (code-review finding).
	admitted, err := d.Acquire(context.Background(), 1<<20)
	if err != nil {
		t.Fatalf("oversized acquire: %v", err)
	}
	if admitted != 10 {
		t.Fatalf("admitted weight = %d, want 10 (capacity)", admitted)
	}
	d.Release(admitted)

	d.mu.Lock()
	used := d.used
	d.mu.Unlock()
	if used != 0 {
		t.Errorf("used = %d after releasing the admitted (clamped) weight, want 0", used)
	}
}

func TestDecryptAdmission_ClampWeight(t *testing.T) {
	d := NewDecryptAdmission(100)
	cases := []struct {
		in, want int64
	}{
		{-5, 0},
		{0, 0},
		{50, 50},
		{100, 100},
		{101, 100},
		{1 << 30, 100},
	}
	for _, tc := range cases {
		if got := d.ClampWeight(tc.in); got != tc.want {
			t.Errorf("ClampWeight(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}

	var nilD *DecryptAdmission
	if got := nilD.ClampWeight(42); got != 42 {
		t.Errorf("nil.ClampWeight(42) = %d, want 42 (unlimited, no clamping)", got)
	}
	if got := nilD.ClampWeight(-5); got != 0 {
		t.Errorf("nil.ClampWeight(-5) = %d, want 0", got)
	}
}

func TestDecryptAdmission_ConcurrentAcquireRelease_NeverExceedsCapacity(t *testing.T) {
	const capacity = 50
	const weight = 7
	d := NewDecryptAdmission(capacity)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, err := d.Acquire(ctx, weight); err != nil {
				t.Errorf("acquire: %v", err)
				return
			}
			time.Sleep(time.Millisecond)
			d.Release(weight)
		}()
	}
	wg.Wait()

	d.mu.Lock()
	used := d.used
	d.mu.Unlock()
	if used != 0 {
		t.Errorf("used = %d after all releases, want 0", used)
	}
}

// TestDecryptAdmission_FIFO_LargeWaiterNotStarvedBySmallArrivals is a
// code-review regression test (ADR-017): the original sync.Cond-broadcast
// implementation let any waiter whose weight currently fit proceed on every
// Release, with no ordering guarantee — a large waiter queued behind a
// fully-held budget could be starved indefinitely by a steady stream of
// smaller waiters arriving after it, each individually fitting into
// whatever budget freed up. Strict FIFO admission fixes this: only the
// waiter at the front of the queue is ever considered, so nothing behind a
// blocked large waiter can be admitted ahead of it.
func TestDecryptAdmission_FIFO_LargeWaiterNotStarvedBySmallArrivals(t *testing.T) {
	d := NewDecryptAdmission(10)

	// Fully occupy the budget so every subsequent Acquire below must queue.
	if _, err := d.Acquire(context.Background(), 10); err != nil {
		t.Fatalf("initial acquire: %v", err)
	}

	largeAdmitted := make(chan struct{})
	largeDone := make(chan struct{})
	go func() {
		if _, err := d.Acquire(context.Background(), 10); err != nil {
			t.Errorf("large acquire: %v", err)
			close(largeAdmitted)
			close(largeDone)
			return
		}
		close(largeAdmitted)
		// Hold it briefly so the assertion below has a window in which the
		// large waiter is admitted but hasn't released yet.
		time.Sleep(100 * time.Millisecond)
		d.Release(10)
		close(largeDone)
	}()

	// Give the large waiter time to enqueue before the small ones arrive,
	// so it is guaranteed to be ahead of them in FIFO order.
	time.Sleep(50 * time.Millisecond)

	var mu sync.Mutex
	var order []int
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := d.Acquire(context.Background(), 1); err != nil {
				t.Errorf("small acquire %d: %v", i, err)
				return
			}
			mu.Lock()
			order = append(order, i)
			mu.Unlock()
			d.Release(1)
		}(i)
	}

	// Free the initial holder's budget. Admission of the queue's front
	// (the large, weight-10 waiter) happens synchronously, under the same
	// mutex, inside this Release call — so by the time it returns, whether
	// or not any small waiter was admitted is already decided
	// deterministically, not a timing race.
	d.Release(10)

	select {
	case <-largeAdmitted:
	case <-time.After(2 * time.Second):
		t.Fatal("large waiter was never admitted")
	}

	mu.Lock()
	smallAdmittedSoFar := len(order)
	mu.Unlock()
	if smallAdmittedSoFar != 0 {
		t.Fatalf("%d small waiter(s) admitted before the large waiter released its budget, want 0 (FIFO/head-of-line ordering violated)", smallAdmittedSoFar)
	}

	<-largeDone
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(order) != 5 {
		t.Fatalf("expected all 5 small waiters to eventually complete, got %d: %v", len(order), order)
	}
}
