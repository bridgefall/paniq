package config

import (
	"encoding/json"
	"fmt"
	"time"
)

// Duration wraps time.Duration for JSON string parsing.
type Duration struct {
	time.Duration
}

// UnmarshalJSON parses a duration string like "5s" or "2m".
func (d *Duration) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("duration must be a string: %w", err)
	}
	if raw == "" {
		d.Duration = 0
		return nil
	}

	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	d.Duration = parsed
	return nil
}

// String returns the duration string.
func (d Duration) String() string {
	return d.Duration.String()
}
