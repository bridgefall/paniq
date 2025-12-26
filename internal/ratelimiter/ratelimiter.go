package ratelimiter

import (
	"net/netip"
	"sync"
	"time"
)

const (
	defaultPacketsPerSecond = 20
	defaultPacketsBurstable = 5
	garbageCollectTime      = time.Second
)

type RatelimiterEntry struct {
	mu       sync.Mutex
	lastTime time.Time
	tokens   int64
}

type Ratelimiter struct {
	mu      sync.RWMutex
	timeNow func() time.Time

	stopReset  chan struct{}
	table      map[netip.Addr]*RatelimiterEntry
	packetCost int64
	maxTokens  int64
}

func (rate *Ratelimiter) Close() {
	rate.mu.Lock()
	defer rate.mu.Unlock()

	if rate.stopReset != nil {
		close(rate.stopReset)
		rate.stopReset = nil
	}
	rate.table = nil
}

func (rate *Ratelimiter) Init(pps, burst int) {
	rate.mu.Lock()
	defer rate.mu.Unlock()

	if pps <= 0 {
		pps = defaultPacketsPerSecond
	}
	if burst <= 0 {
		burst = defaultPacketsBurstable
	}

	rate.packetCost = int64(time.Second / time.Duration(pps))
	rate.maxTokens = rate.packetCost * int64(burst)

	if rate.timeNow == nil {
		rate.timeNow = time.Now
	}
	if rate.stopReset != nil {
		close(rate.stopReset)
	}

	rate.stopReset = make(chan struct{})
	rate.table = make(map[netip.Addr]*RatelimiterEntry)

	stopReset := rate.stopReset
	go func() {
		ticker := time.NewTicker(time.Second)
		ticker.Stop()
		for {
			select {
			case _, ok := <-stopReset:
				ticker.Stop()
				if !ok {
					return
				}
				ticker = time.NewTicker(time.Second)
			case <-ticker.C:
				if rate.cleanup() {
					ticker.Stop()
				}
			}
		}
	}()
}

func (rate *Ratelimiter) cleanup() (empty bool) {
	rate.mu.Lock()
	defer rate.mu.Unlock()

	for key, entry := range rate.table {
		entry.mu.Lock()
		if rate.timeNow().Sub(entry.lastTime) > garbageCollectTime {
			delete(rate.table, key)
		}
		entry.mu.Unlock()
	}

	return len(rate.table) == 0
}

func (rate *Ratelimiter) Allow(ip netip.Addr) bool {
	rate.mu.RLock()
	if rate.stopReset == nil {
		rate.mu.RUnlock()
		return true
	}
	var entry *RatelimiterEntry
	entry = rate.table[ip]
	rate.mu.RUnlock()

	if entry == nil {
		entry = new(RatelimiterEntry)
		entry.tokens = rate.maxTokens - rate.packetCost
		entry.lastTime = rate.timeNow()
		rate.mu.Lock()
		rate.table[ip] = entry
		stopReset := rate.stopReset
		if len(rate.table) == 1 && stopReset != nil {
			stopReset <- struct{}{}
		}
		rate.mu.Unlock()
		return true
	}

	entry.mu.Lock()
	now := rate.timeNow()
	entry.tokens += now.Sub(entry.lastTime).Nanoseconds()
	entry.lastTime = now
	if entry.tokens > rate.maxTokens {
		entry.tokens = rate.maxTokens
	}
	if entry.tokens > rate.packetCost {
		entry.tokens -= rate.packetCost
		entry.mu.Unlock()
		return true
	}
	entry.mu.Unlock()
	return false
}
