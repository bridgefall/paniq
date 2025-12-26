package envelope

import (
	"sync"
	"time"
)

type logLimiter struct {
	interval time.Duration
	mu       sync.Mutex
	buckets  map[string]*bucketState
	burst    float64
}

type bucketState struct {
	last   time.Time
	tokens float64
}

func newLogLimiter(interval time.Duration) *logLimiter {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &logLimiter{
		interval: interval,
		buckets:  make(map[string]*bucketState),
		burst:    1,
	}
}

func (l *logLimiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	state := l.buckets[key]
	if state == nil {
		state = &bucketState{last: now, tokens: l.burst}
		l.buckets[key] = state
	}
	elapsed := now.Sub(state.last)
	state.last = now
	if elapsed > 0 {
		state.tokens += elapsed.Seconds() / l.interval.Seconds()
		if state.tokens > l.burst {
			state.tokens = l.burst
		}
	}
	if state.tokens < 1 {
		return false
	}
	state.tokens -= 1
	return true
}
