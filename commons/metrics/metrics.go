package metrics

import (
	"math"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Counter is an atomic counter for metrics.
type Counter struct {
	value atomic.Int64
}

// Add increments the counter by n.
func (c *Counter) Add(n int64) {
	c.value.Add(n)
}

// Load returns the current value.
func (c *Counter) Load() int64 {
	return c.value.Load()
}

// Gauge is an atomic gauge for metrics.
type Gauge struct {
	value atomic.Int64
}

// Inc increments the gauge by 1.
func (g *Gauge) Inc() {
	g.value.Add(1)
}

// Dec decrements the gauge by 1.
func (g *Gauge) Dec() {
	g.value.Add(-1)
}

// Set sets the gauge to the provided value.
func (g *Gauge) Set(v int64) {
	g.value.Store(v)
}

// Load returns the current value.
func (g *Gauge) Load() int64 {
	return g.value.Load()
}

// LatencySampler stores recent latency samples for percentile calculations.
type LatencySampler struct {
	mu      sync.Mutex
	samples []int64
	index   int
	full    bool
}

// NewLatencySampler creates a sampler that keeps the last size samples.
func NewLatencySampler(size int) *LatencySampler {
	if size <= 0 {
		size = 128
	}
	return &LatencySampler{
		samples: make([]int64, size),
	}
}

// Add records a latency sample.
func (l *LatencySampler) Add(d time.Duration) {
	l.mu.Lock()
	l.samples[l.index] = d.Nanoseconds()
	l.index++
	if l.index >= len(l.samples) {
		l.index = 0
		l.full = true
	}
	l.mu.Unlock()
}

// SnapshotQuantiles returns percentile values for the provided quantiles.
func (l *LatencySampler) SnapshotQuantiles(quantiles []float64) map[float64]time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()

	count := l.index
	if l.full {
		count = len(l.samples)
	}
	if count == 0 {
		return map[float64]time.Duration{}
	}

	values := make([]int64, count)
	copy(values, l.samples[:count])
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })

	results := make(map[float64]time.Duration, len(quantiles))
	for _, q := range quantiles {
		if q <= 0 {
			results[q] = time.Duration(values[0])
			continue
		}
		if q >= 1 {
			results[q] = time.Duration(values[count-1])
			continue
		}
		pos := int(math.Ceil(q*float64(count))) - 1
		if pos < 0 {
			pos = 0
		}
		if pos >= count {
			pos = count - 1
		}
		results[q] = time.Duration(values[pos])
	}

	return results
}

// SampleCount returns the number of stored samples.
func (l *LatencySampler) SampleCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.full {
		return len(l.samples)
	}
	return l.index
}
