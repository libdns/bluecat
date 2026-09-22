package bluecat

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// deployState tracks a pending debounced deployment for a single zone.
type deployState struct {
	timer    *time.Timer
	deadline time.Time // hard cap; debouncing may not postpone past this
	writes   int
	done     chan struct{} // closed once the deploy for this batch finishes
	err      error         // valid only after done is closed
}

// scheduleDeploy debounces QuickDeploy calls for a zone and returns a function
// that blocks until the deploy covering this write has completed.
//
// Every write resets the debounce timer so a burst of concurrent ACME
// challenges collapses into one deploy. The reset is clamped to a hard
// deadline: without that cap, a sustained stream of writes postpones the
// deploy indefinitely and the records never reach the DNS servers at all.
func (p *Provider) scheduleDeploy(client *Client, zoneID int64) func(context.Context) error {
	if p.DisableDeploy {
		return func(context.Context) error { return nil }
	}

	delay := p.DeployDelay
	if delay <= 0 {
		delay = defaultDeployDelay
	}

	maxDelay := p.MaxDeployDelay
	if maxDelay <= 0 {
		maxDelay = 4 * delay
		if maxDelay < minMaxDeployDelay {
			maxDelay = minMaxDeployDelay
		}
	}
	if maxDelay < delay {
		maxDelay = delay
	}

	p.deployMu.Lock()
	defer p.deployMu.Unlock()

	return p.scheduleDeployLocked(client, zoneID, delay, maxDelay)
}

// scheduleDeployLocked does the work of scheduleDeploy. The caller must hold
// deployMu. It is split out so tests can hold the lock across the moment the
// timer fires, which is otherwise too narrow a window to hit reliably.
func (p *Provider) scheduleDeployLocked(client *Client, zoneID int64, delay, maxDelay time.Duration) func(context.Context) error {
	if p.pendingDeploys == nil {
		p.pendingDeploys = make(map[int64]*deployState)
	}

	if state, ok := p.pendingDeploys[zoneID]; ok {
		// Stop reports false once the callback has fired, even if it is still
		// blocked acquiring deployMu behind us. Resetting in that case would
		// run the callback a second time — and it closes state.done, so the
		// second run would panic. Fall through and start a fresh batch
		// instead; the old callback leaves the map alone once it sees the
		// entry is no longer its own.
		if state.timer.Stop() {
			state.writes++
			// Extend the debounce, but never past the batch's hard deadline.
			next := time.Now().Add(delay)
			if next.After(state.deadline) {
				next = state.deadline
			}
			d := time.Until(next)
			if d < 0 {
				d = 0
			}
			state.timer.Reset(d)
			return waiterFor(state)
		}
	}

	state := &deployState{
		deadline: time.Now().Add(maxDelay),
		writes:   1,
		done:     make(chan struct{}),
	}
	state.timer = time.AfterFunc(delay, func() {
		p.deployMu.Lock()
		// Only clear the entry if it's still ours; a later batch may have
		// replaced it.
		if p.pendingDeploys[zoneID] == state {
			delete(p.pendingDeploys, zoneID)
		}
		writes := state.writes
		p.deployMu.Unlock()

		// The caller's context is typically gone by now, so use a fresh one
		// bounded by how long a deploy can legitimately take.
		ctx, cancel := context.WithTimeout(context.Background(), client.deployPollTimeout+30*time.Second)
		defer cancel()

		state.err = client.DeployZone(ctx, zoneID)
		if state.err != nil {
			p.logger().Error("bluecat deploy failed",
				"zone_id", zoneID, "writes", writes, "error", state.err)
		} else {
			p.logger().Info("bluecat deploy complete", "zone_id", zoneID, "writes", writes)
		}
		close(state.done)
	})
	p.pendingDeploys[zoneID] = state

	return waiterFor(state)
}

// waiterFor returns a function that blocks until the deploy finishes, or
// until the caller's context expires.
func waiterFor(state *deployState) func(context.Context) error {
	return func(ctx context.Context) error {
		select {
		case <-state.done:
			return state.err
		case <-ctx.Done():
			return fmt.Errorf("waiting for bluecat deploy: %w", ctx.Err())
		}
	}
}

// keyedMutex provides per-key mutual exclusion. Entries are reference counted
// and removed at zero so the map doesn't grow without bound across renewals.
type keyedMutex struct {
	mu sync.Mutex
	m  map[string]*keyedMutexEntry
}

type keyedMutexEntry struct {
	mu   sync.Mutex
	refs int
}

// lock acquires the mutex for key and returns its unlock function.
func (k *keyedMutex) lock(key string) func() {
	k.mu.Lock()
	if k.m == nil {
		k.m = make(map[string]*keyedMutexEntry)
	}
	entry, ok := k.m[key]
	if !ok {
		entry = &keyedMutexEntry{}
		k.m[key] = entry
	}
	entry.refs++
	k.mu.Unlock()

	entry.mu.Lock()

	return func() {
		entry.mu.Unlock()

		k.mu.Lock()
		entry.refs--
		if entry.refs == 0 {
			delete(k.m, key)
		}
		k.mu.Unlock()
	}
}

// rrsetKeyOf builds the lock key identifying one RRset.
func rrsetKeyOf(zoneID int64, name, recType string) string {
	return fmt.Sprintf("%d\x00%s\x00%s", zoneID, name, recType)
}
