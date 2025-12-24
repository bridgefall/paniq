package obf

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

// MessageType represents framed message types.
type MessageType int

const (
	MessageInitiation MessageType = iota + 1
	MessageResponse
	MessageCookieReply
	MessageTransport
)

// Framer applies AWG-style obfuscation framing over UDP datagrams.
type Framer struct {
	cfg     Config
	headers *HeaderSet
	chains  *ChainSet
}

// NewFramer constructs a framer with validated config.
func NewFramer(cfg Config) (*Framer, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	headers, err := ParseHeadersWithDefaults(cfg.HeaderSpecs())
	if err != nil {
		return nil, err
	}
	chains, err := ParseChains(cfg.ChainSpecs())
	if err != nil {
		return nil, err
	}
	return &Framer{cfg: cfg, headers: headers, chains: chains}, nil
}

// Config returns the framer configuration.
func (f *Framer) Config() Config {
	return f.cfg
}

// EncodeFrame builds a single AWG-style datagram.
func (f *Framer) EncodeFrame(msgType MessageType, payload []byte) ([]byte, error) {
	padding := f.paddingFor(msgType)
	header := f.headerFor(msgType)
	if header == nil {
		return nil, fmt.Errorf("missing header for message type %d", msgType)
	}
	if padding < 0 {
		return nil, fmt.Errorf("invalid padding")
	}

	datagram := make([]byte, 0, padding+4+len(payload))
	if padding > 0 {
		buf := make([]byte, padding)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		datagram = append(datagram, buf...)
	}

	var typeBuf [4]byte
	binary.LittleEndian.PutUint32(typeBuf[:], header.Generate())
	datagram = append(datagram, typeBuf[:]...)
	datagram = append(datagram, payload...)
	return datagram, nil
}

// DecodeFrame parses an AWG-style datagram and returns its type and payload.
func (f *Framer) DecodeFrame(datagram []byte) (MessageType, []byte, error) {
	if len(datagram) < 4 {
		return 0, nil, fmt.Errorf("frame too short")
	}

	candidates := []MessageType{}
	for _, msgType := range []MessageType{MessageInitiation, MessageResponse, MessageCookieReply, MessageTransport} {
		padding := f.paddingFor(msgType)
		header := f.headerFor(msgType)
		if header == nil {
			continue
		}
		if len(datagram) < padding+4 {
			continue
		}
		typeVal := binary.LittleEndian.Uint32(datagram[padding : padding+4])
		if header.Validate(typeVal) {
			candidates = append(candidates, msgType)
		}
	}

	if len(candidates) != 1 {
		return 0, nil, fmt.Errorf("unable to determine message type")
	}

	msgType := candidates[0]
	padding := f.paddingFor(msgType)
	payload := datagram[padding+4:]
	return msgType, payload, nil
}

// JunkDatagrams builds the pre-handshake junk datagrams.
func (f *Framer) JunkDatagrams() ([][]byte, error) {
	if f.cfg.Jc == 0 || f.cfg.Jmin <= 0 || f.cfg.Jmax <= 0 {
		return nil, nil
	}
	out := make([][]byte, 0, f.cfg.Jc)
	for i := 0; i < f.cfg.Jc; i++ {
		length, err := randRange(f.cfg.Jmin, f.cfg.Jmax)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, length)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		out = append(out, buf)
	}
	return out, nil
}

// SignatureDatagrams builds the pre-handshake signature datagrams.
func (f *Framer) SignatureDatagrams() ([][]byte, error) {
	chains := []*Chain{f.chains.I1, f.chains.I2, f.chains.I3, f.chains.I4, f.chains.I5}
	out := make([][]byte, 0, len(chains))
	for _, chain := range chains {
		if chain == nil {
			continue
		}
		length := chain.ObfuscatedLen(0)
		buf := make([]byte, length)
		src := make([]byte, chain.DeobfuscatedLen(0))
		chain.Obfuscate(buf, src)
		out = append(out, buf)
	}
	return out, nil
}

// SignatureChains returns configured signature chains in order.
func (f *Framer) SignatureChains() []*Chain {
	chains := []*Chain{f.chains.I1, f.chains.I2, f.chains.I3, f.chains.I4, f.chains.I5}
	out := make([]*Chain, 0, len(chains))
	for _, chain := range chains {
		if chain == nil {
			continue
		}
		out = append(out, chain)
	}
	return out
}

// SignatureLengths returns expected signature datagram lengths.
func (f *Framer) SignatureLengths() []int {
	chains := []*Chain{f.chains.I1, f.chains.I2, f.chains.I3, f.chains.I4, f.chains.I5}
	out := make([]int, 0, len(chains))
	for _, chain := range chains {
		if chain == nil {
			continue
		}
		out = append(out, chain.ObfuscatedLen(0))
	}
	return out
}

func (f *Framer) headerFor(msgType MessageType) *Header {
	switch msgType {
	case MessageInitiation:
		return f.headers.H1
	case MessageResponse:
		return f.headers.H2
	case MessageCookieReply:
		return f.headers.H3
	case MessageTransport:
		return f.headers.H4
	default:
		return nil
	}
}

func (f *Framer) paddingFor(msgType MessageType) int {
	switch msgType {
	case MessageInitiation:
		return f.cfg.S1
	case MessageResponse:
		return f.cfg.S2
	case MessageCookieReply:
		return f.cfg.S3
	case MessageTransport:
		return f.cfg.S4
	default:
		return 0
	}
}

func randRange(min int, max int) (int, error) {
	if min > max {
		return 0, fmt.Errorf("invalid range")
	}
	if min == max {
		return min, nil
	}
	rangeSize := max - min + 1
	maxUint := uint32(rangeSize)
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return 0, err
	}
	val := binary.LittleEndian.Uint32(buf[:]) % maxUint
	return min + int(val), nil
}
