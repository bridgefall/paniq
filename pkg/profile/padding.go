package profile

import "fmt"

// TransportPadding configures MessageTransport padding policy.
type TransportPadding struct {
	Min       *int     `json:"pad_min"`
	Max       *int     `json:"pad_max"`
	BurstMin  *int     `json:"pad_burst_min"`
	BurstMax  *int     `json:"pad_burst_max"`
	BurstProb *float64 `json:"pad_burst_prob"`
}

// PaddingPolicy is the resolved padding policy used by the envelope.
type PaddingPolicy struct {
	Min       int
	Max       int
	BurstMin  int
	BurstMax  int
	BurstProb float64
}

func DefaultPaddingPolicy() PaddingPolicy {
	return PaddingPolicy{
		Min:       0,
		Max:       64,
		BurstMin:  128,
		BurstMax:  256,
		BurstProb: 0.02,
	}
}

func (p TransportPadding) Resolve() (PaddingPolicy, error) {
	hasAny := p.Min != nil || p.Max != nil || p.BurstMin != nil || p.BurstMax != nil || p.BurstProb != nil
	policy := PaddingPolicy{}
	if !hasAny {
		policy = DefaultPaddingPolicy()
	}
	if p.Min != nil {
		policy.Min = *p.Min
	}
	if p.Max != nil {
		policy.Max = *p.Max
	}
	if p.BurstMin != nil {
		policy.BurstMin = *p.BurstMin
	}
	if p.BurstMax != nil {
		policy.BurstMax = *p.BurstMax
	}
	if p.BurstProb != nil {
		policy.BurstProb = *p.BurstProb
	}
	if policy.Min < 0 || policy.Max < 0 || policy.BurstMin < 0 || policy.BurstMax < 0 {
		return PaddingPolicy{}, fmt.Errorf("padding values must be >= 0")
	}
	if policy.Max < policy.Min {
		return PaddingPolicy{}, fmt.Errorf("pad_max must be >= pad_min")
	}
	if policy.BurstMax < policy.BurstMin {
		return PaddingPolicy{}, fmt.Errorf("pad_burst_max must be >= pad_burst_min")
	}
	if policy.BurstProb < 0 || policy.BurstProb > 1 {
		return PaddingPolicy{}, fmt.Errorf("pad_burst_prob must be between 0 and 1")
	}
	if policy.BurstProb > 0 && policy.BurstMax == 0 {
		return PaddingPolicy{}, fmt.Errorf("pad_burst_max must be > 0 when pad_burst_prob > 0")
	}
	return policy, nil
}

func (p PaddingPolicy) Enabled() bool {
	return p.Max > 0 || p.BurstProb > 0
}
