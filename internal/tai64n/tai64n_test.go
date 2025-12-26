package tai64n

import (
	"testing"
	"time"
)

func TestMonotonic(t *testing.T) {
	startTime := time.Unix(0, 123456789)
	tests := []struct {
		name      string
		t1, t2    time.Time
		wantAfter bool
	}{
		{"after_10_ns", startTime, startTime.Add(10 * time.Nanosecond), false},
		{"after_10_us", startTime, startTime.Add(10 * time.Microsecond), false},
		{"after_1_ms", startTime, startTime.Add(time.Millisecond), false},
		{"after_10_ms", startTime, startTime.Add(10 * time.Millisecond), false},
		{"after_20_ms", startTime, startTime.Add(20 * time.Millisecond), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts1, ts2 := stamp(tt.t1), stamp(tt.t2)
			got := ts2.After(ts1)
			if got != tt.wantAfter {
				t.Errorf("after = %v; want %v", got, tt.wantAfter)
			}
		})
	}
}
