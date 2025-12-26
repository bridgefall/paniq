package obf

import "fmt"

// Config defines the AWG obfuscation parameters.
type Config struct {
	Jc   int
	Jmin int
	Jmax int
	S1   int
	S2   int
	S3   int
	S4   int
	H1   string
	H2   string
	H3   string
	H4   string
	I1   string
	I2   string
	I3   string
	I4   string
	I5   string
}

// Validate verifies the configuration matches AWG constraints.
func (c Config) Validate() error {
	if c.Jc < 0 {
		return fmt.Errorf("jc must be non-negative")
	}
	if c.Jmin < 0 || c.Jmax < 0 {
		return fmt.Errorf("jmin/jmax must be non-negative")
	}
	if c.Jmax > 0 && c.Jmin > c.Jmax {
		return fmt.Errorf("jmin must be <= jmax")
	}
	if c.S1 < 0 || c.S2 < 0 || c.S3 < 0 || c.S4 < 0 {
		return fmt.Errorf("s1-s4 must be non-negative")
	}
	return nil
}

// HeaderSpecs returns the configured header specs.
func (c Config) HeaderSpecs() []string {
	return []string{c.H1, c.H2, c.H3, c.H4}
}

// ChainSpecs returns the configured chain specs.
func (c Config) ChainSpecs() []string {
	return []string{c.I1, c.I2, c.I3, c.I4, c.I5}
}
