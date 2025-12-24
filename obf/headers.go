package obf

import "fmt"

// HeaderSet contains parsed header ranges.
type HeaderSet struct {
	H1 *Header
	H2 *Header
	H3 *Header
	H4 *Header
}

// ParseHeaders parses the header specs and validates non-overlap.
func ParseHeaders(specs []string) (*HeaderSet, error) {
	if len(specs) != 4 {
		return nil, fmt.Errorf("expected 4 header specs")
	}

	parsed := make([]*Header, 4)
	for i, spec := range specs {
		if spec == "" {
			continue
		}
		h, err := ParseHeader(spec)
		if err != nil {
			return nil, fmt.Errorf("parse header %d: %w", i+1, err)
		}
		parsed[i] = h
	}

	for i := 0; i < len(parsed); i++ {
		for j := i + 1; j < len(parsed); j++ {
			left := parsed[i]
			right := parsed[j]
			if left == nil || right == nil {
				continue
			}
			if headersOverlap(left, right) {
				return nil, fmt.Errorf("headers must not overlap")
			}
		}
	}

	return &HeaderSet{H1: parsed[0], H2: parsed[1], H3: parsed[2], H4: parsed[3]}, nil
}

func headersOverlap(a *Header, b *Header) bool {
	return a.Validate(b.inner.start) || a.Validate(b.inner.end) || b.Validate(a.inner.start) || b.Validate(a.inner.end)
}
