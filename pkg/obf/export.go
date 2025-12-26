package obf

// Header wraps a magic header range.
type Header struct {
	inner *magicHeader
}

// Chain wraps an obfuscation chain.
type Chain struct {
	inner *obfChain
}

// ParseHeader parses a header spec string (e.g., "1-3").
func ParseHeader(spec string) (*Header, error) {
	h, err := newMagicHeader(spec)
	if err != nil {
		return nil, err
	}
	return &Header{inner: h}, nil
}

// ParseChain parses an obfuscation chain spec string.
func ParseChain(spec string) (*Chain, error) {
	c, err := newObfChain(spec)
	if err != nil {
		return nil, err
	}
	return &Chain{inner: c}, nil
}

// GenSpec returns the original spec for the header.
func (h *Header) GenSpec() string {
	return h.inner.GenSpec()
}

// Validate returns true if val is within the header range.
func (h *Header) Validate(val uint32) bool {
	return h.inner.Validate(val)
}

// Generate returns a random value in the header range.
func (h *Header) Generate() uint32 {
	return h.inner.Generate()
}

// Spec returns the original chain spec.
func (c *Chain) Spec() string {
	return c.inner.Spec
}

// Obfuscate writes obfuscated bytes to dst.
func (c *Chain) Obfuscate(dst, src []byte) {
	c.inner.Obfuscate(dst, src)
}

// Deobfuscate reads obfuscated bytes from src and writes to dst.
func (c *Chain) Deobfuscate(dst, src []byte) bool {
	return c.inner.Deobfuscate(dst, src)
}

// ObfuscatedLen returns the obfuscated length for a payload size.
func (c *Chain) ObfuscatedLen(n int) int {
	return c.inner.ObfuscatedLen(n)
}

// DeobfuscatedLen returns the deobfuscated length for a payload size.
func (c *Chain) DeobfuscatedLen(n int) int {
	return c.inner.DeobfuscatedLen(n)
}
