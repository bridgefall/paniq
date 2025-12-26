package obf

import "fmt"

// DefaultHeaderSpecs returns default header ranges for AWG types.
func DefaultHeaderSpecs() []string {
	return []string{"1", "2", "3", "4"}
}

// ParseHeadersWithDefaults parses headers and applies defaults for empty specs.
func ParseHeadersWithDefaults(specs []string) (*HeaderSet, error) {
	if len(specs) != 4 {
		return nil, fmt.Errorf("expected 4 header specs")
	}
	defaults := DefaultHeaderSpecs()
	resolved := make([]string, 4)
	for i, spec := range specs {
		if spec == "" {
			resolved[i] = defaults[i]
			continue
		}
		resolved[i] = spec
	}
	return ParseHeaders(resolved)
}
