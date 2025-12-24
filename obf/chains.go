package obf

import "fmt"

// ChainSet contains parsed chain specs.
type ChainSet struct {
	I1 *Chain
	I2 *Chain
	I3 *Chain
	I4 *Chain
	I5 *Chain
}

// ParseChains parses the chain specs into a ChainSet.
func ParseChains(specs []string) (*ChainSet, error) {
	if len(specs) != 5 {
		return nil, fmt.Errorf("expected 5 chain specs")
	}

	parsed := make([]*Chain, 5)
	for i, spec := range specs {
		if spec == "" {
			continue
		}
		c, err := ParseChain(spec)
		if err != nil {
			return nil, fmt.Errorf("parse chain %d: %w", i+1, err)
		}
		parsed[i] = c
	}

	return &ChainSet{I1: parsed[0], I2: parsed[1], I3: parsed[2], I4: parsed[3], I5: parsed[4]}, nil
}
