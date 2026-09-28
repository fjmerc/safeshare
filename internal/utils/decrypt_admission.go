package utils

import (
	"context"
	"sync"
)

// DecryptAdmission bounds the total in-flight decrypt memory (bytes) shared
// by every concurrent claim download that needs to decrypt (SFSE1/SFSE2
// chunk buffers, legacy full-file decrypts). See ADR-017 (T34): each SFSE
// stream's gcm.Open call operates on a chunk-sized buffer (up to
// MaxSFSEChunkSize) and a legacy download decrypts its entire ciphertext
// into RAM (master finding #9) — with no admission control, an attacker (or
// just a burst of legitimate traffic) could open enough concurrent
// downloads to exhaust server memory regardless of any single request's own
// size limits.
//
// It is a weighted semaphore with **strict FIFO (head-of-line) admission**:
// arrivals are queued in order, and only the waiter at the front of the
// queue is ever considered for admission — a later, smaller-weight arrival
// is never let through ahead of an earlier, larger one just because it
// happens to fit in the currently-free budget. Without this, a large
// request (e.g. a legacy full-file decrypt near LEGACY_DECRYPT_MAX_BYTES)
// could be starved indefinitely by a steady stream of small SFSE
// chunk-sized requests each individually fitting into whatever budget the
// large one is waiting to accumulate (code-review finding — the original
// sync.Cond-broadcast implementation re-evaluated every waiter's own
// condition independently on every Release, with no ordering guarantee).
// The tradeoff is classic head-of-line blocking: once the front waiter
// doesn't fit, nothing behind it is admitted either, even if it would
// otherwise fit — this is the intended fairness property, not a bug.
//
// It is not a byte-accurate memory tracker — it charges an estimate at
// Acquire time (see the callers in internal/handlers for how each format's
// weight is chosen) — the goal is bounding aggregate concurrent decrypt
// memory to a configured ceiling with fair ordering, not perfect
// accounting.
//
// A nil *DecryptAdmission is a valid, unlimited budget: Acquire always
// succeeds immediately and Release is a no-op. This mirrors the
// nil-receiver convention already used in this codebase (e.g.
// internal/handlers.InFlightTracker) so tests and callers that never
// install a budget aren't forced to construct one.
type DecryptAdmission struct {
	mu       sync.Mutex
	capacity int64
	used     int64
	queue    []*decryptWaiter
}

// decryptWaiter is one Acquire call's place in the FIFO queue. ready is
// closed exactly once, under DecryptAdmission.mu, the moment this waiter is
// admitted (i.e. once it reaches the front of the queue and its weight fits
// in the remaining budget).
type decryptWaiter struct {
	weight int64
	ready  chan struct{}
}

// NewDecryptAdmission constructs a budget of capacityBytes. A non-positive
// capacity disables the budget (returns nil — see the type doc for what
// that means).
func NewDecryptAdmission(capacityBytes int64) *DecryptAdmission {
	if capacityBytes <= 0 {
		return nil
	}
	return &DecryptAdmission{capacity: capacityBytes}
}

// Capacity returns the configured budget in bytes, or 0 for a nil (disabled)
// budget.
func (d *DecryptAdmission) Capacity() int64 {
	if d == nil {
		return 0
	}
	return d.capacity
}

// ClampWeight returns the weight Acquire would actually admit for the given
// requested weight: max(weight, 0), then capped to d's total capacity.
// Exposed so a caller that needs to reserve accounting keyed on the
// eventual admitted amount BEFORE calling Acquire (e.g. the per-client
// decrypt-share reservation in internal/handlers/decrypt_admission.go)
// doesn't have to duplicate Acquire's clamping logic — and can't
// accidentally reserve or release a different (unclamped) amount than what
// Acquire/Release actually operate on. Safe on a nil receiver: returns
// max(weight, 0) unclamped (a nil budget has no capacity to clamp against).
func (d *DecryptAdmission) ClampWeight(weight int64) int64 {
	if weight < 0 {
		weight = 0
	}
	if d == nil {
		return weight
	}
	if weight > d.capacity {
		return d.capacity
	}
	return weight
}

// Acquire blocks until weight bytes of budget are available AND every
// earlier-arrived waiter still queued ahead of this one has either been
// admitted or given up — i.e. strict FIFO admission, not just eventual
// availability — or until ctx is done, whichever happens first. A negative
// weight is treated as zero. A weight larger than the total capacity is
// clamped to it (see ClampWeight), so a single oversized stream is admitted
// alone (once it reaches the front and nothing else is holding any budget)
// instead of being permanently unable to acquire.
//
// On success, Acquire returns the actual (clamped) weight that was
// admitted — the caller must Release exactly that amount, not the
// originally-requested weight, so a caller can never accidentally release
// more than was actually reserved. On error, the returned weight is always
// 0 (nothing was admitted, so there is nothing to release).
func (d *DecryptAdmission) Acquire(ctx context.Context, weight int64) (int64, error) {
	weight = d.ClampWeight(weight)
	if d == nil {
		return weight, nil
	}

	if err := ctx.Err(); err != nil {
		return 0, err
	}

	d.mu.Lock()
	w := &decryptWaiter{weight: weight, ready: make(chan struct{})}
	d.queue = append(d.queue, w)
	d.admitLocked()
	d.mu.Unlock()

	select {
	case <-w.ready:
		return weight, nil
	case <-ctx.Done():
		d.mu.Lock()
		select {
		case <-w.ready:
			// Won the race: admitted concurrently right as ctx fired.
			// Honor the grant rather than dropping acquired budget on the
			// floor (the caller would never call Release for a call that
			// returned an error).
			d.mu.Unlock()
			return weight, nil
		default:
			d.removeLocked(w)
			// Removing a queued (not-yet-admitted) waiter never frees any
			// budget it was holding (it never held any), but if it was
			// sitting at the front and blocking the queue, the new front
			// may now be admittable.
			d.admitLocked()
			d.mu.Unlock()
			return 0, ctx.Err()
		}
	}
}

// Release returns weight bytes of budget acquired by a matching, successful
// Acquire call (the same, already-clamped weight Acquire used — callers
// pass the same value to both, so no separate clamping is needed here). A
// negative weight is treated as zero. Safe to call on a nil receiver
// (no-op).
func (d *DecryptAdmission) Release(weight int64) {
	if d == nil {
		return
	}
	if weight < 0 {
		weight = 0
	}
	d.mu.Lock()
	d.used -= weight
	if d.used < 0 {
		d.used = 0
	}
	d.admitLocked()
	d.mu.Unlock()
}

// admitLocked grants admission to the queue's front waiter(s), in order,
// for as long as each one in turn fits in the remaining budget. It stops at
// the first waiter that doesn't fit — strict head-of-line blocking, the
// property that prevents a large waiter from being starved by a stream of
// smaller ones arriving after it. Must be called with d.mu held.
func (d *DecryptAdmission) admitLocked() {
	for len(d.queue) > 0 {
		front := d.queue[0]
		if d.used+front.weight > d.capacity {
			return
		}
		d.used += front.weight
		d.queue = d.queue[1:]
		close(front.ready)
	}
}

// removeLocked deletes w from the queue (wherever it is — a cancelled
// Acquire is not necessarily at the front) while preserving the order of
// the remaining waiters. A no-op if w is no longer queued (e.g. it was
// admitted in between). Must be called with d.mu held.
func (d *DecryptAdmission) removeLocked(w *decryptWaiter) {
	for i, q := range d.queue {
		if q == w {
			d.queue = append(d.queue[:i], d.queue[i+1:]...)
			return
		}
	}
}
