package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/bridgefall/paniq/commons/config"
	"github.com/bridgefall/paniq/obf"
	"github.com/bridgefall/paniq/profile"
	cborprofile "github.com/bridgefall/paniq/profile/cbor"
)

const (
	headerCount   = 4
	maxUint32     = ^uint32(0)
	msbBucketSize = 1 << 24
)

type rng interface {
	Uint32() uint32
}

type mathRNG struct{ *mrand.Rand }

func (m mathRNG) Uint32() uint32 { return m.Rand.Uint32() }

type headerRange struct {
	start uint32
	end   uint32
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		runKeygen(os.Args[2:])
	case "headergen":
		runHeadergen(os.Args[2:])
	case "profile-cbor":
		runProfileCBOR(os.Args[2:])
	case "create-profile":
		runCreateProfile(os.Args[2:])
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage: bf <command> [options]")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Commands:")
	fmt.Fprintln(os.Stderr, "  keygen      Generate server keypair")
	fmt.Fprintln(os.Stderr, "  headergen   Generate header ranges")
	fmt.Fprintln(os.Stderr, "  profile-cbor Encode/decode profile CBOR")
	fmt.Fprintln(os.Stderr, "  create-profile Generate a safe randomized profile")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Examples:")
	fmt.Fprintln(os.Stderr, "  bf keygen")
	fmt.Fprintln(os.Stderr, "  bf headergen -width 1024")
	fmt.Fprintln(os.Stderr, "  bf profile-cbor -in profile.json -out profile.cbor")
	fmt.Fprintln(os.Stderr, "  bf profile-cbor -decode -in profile.cbor -out profile.json")
	fmt.Fprintln(os.Stderr, "  bf profile-cbor -base64 < profile.json > profile.cbor.b64")
	fmt.Fprintln(os.Stderr, "  bf create-profile --mtu 1420 --profile-name user1")
}

func runKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	_ = fs.Parse(args)

	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		fatalf("keygen failed: %v", err)
	}
	pub, err := obf.DerivePublicKey(priv)
	if err != nil {
		fatalf("keygen failed: %v", err)
	}
	fmt.Printf("server_private_key=%s\n", base64.StdEncoding.EncodeToString(priv[:]))
	fmt.Printf("server_public_key=%s\n", base64.StdEncoding.EncodeToString(pub[:]))
}

func runHeadergen(args []string) {
	fs := flag.NewFlagSet("headergen", flag.ExitOnError)
	width := fs.Uint("width", 1024, "range width in uint32 units")
	min := fs.Uint64("min", 1, "minimum start value")
	max := fs.Uint64("max", uint64(maxUint32), "maximum end value")
	seed := fs.Int64("seed", 0, "math/rand seed (0 = crypto seed)")
	jsonOut := fs.Bool("json", true, "output as JSON key/value lines")
	distinctMSB := fs.Bool("distinct-msb", true, "ensure distinct high-order byte per header")
	_ = fs.Parse(args)

	if *width == 0 {
		fatalf("width must be > 0")
	}
	if *max <= *min {
		fatalf("max must be > min")
	}

	r := newRNG(*seed)
	ranges, err := generateRanges(r, uint32(*width), uint32(*min), uint32(*max), *distinctMSB)
	if err != nil {
		fatalf("%v", err)
	}

	if *jsonOut {
		for i, hr := range ranges {
			key := fmt.Sprintf("h%d", i+1)
			fmt.Printf("      %q: %q,\n", key, fmt.Sprintf("%d-%d", hr.start, hr.end))
		}
		return
	}

	for i, hr := range ranges {
		fmt.Printf("h%d=%d-%d\n", i+1, hr.start, hr.end)
	}
}

func runProfileCBOR(args []string) {
	fs := flag.NewFlagSet("profile-cbor", flag.ExitOnError)
	decode := fs.Bool("decode", false, "decode CBOR into JSON")
	inPath := fs.String("in", "", "input file (defaults to stdin)")
	outPath := fs.String("out", "", "output file (defaults to stdout)")
	base64Mode := fs.Bool("base64", false, "read/write base64-wrapped CBOR")
	_ = fs.Parse(args)

	input, err := readInput(*inPath)
	if err != nil {
		fatalf("profile-cbor read input: %v", err)
	}

	if *decode {
		if *base64Mode {
			input, err = decodeBase64(input)
			if err != nil {
				fatalf("profile-cbor decode base64: %v", err)
			}
		}
		out, err := cborprofile.DecodeCBORToJSON(input)
		if err != nil {
			fatalf("profile-cbor decode: %v", err)
		}
		if err := writeOutput(*outPath, out); err != nil {
			fatalf("profile-cbor write output: %v", err)
		}
		return
	}

	out, err := cborprofile.EncodeJSONProfile(input)
	if err != nil {
		fatalf("profile-cbor encode: %v", err)
	}
	if *base64Mode {
		out = []byte(base64.StdEncoding.EncodeToString(out))
	}
	if err := writeOutput(*outPath, out); err != nil {
		fatalf("profile-cbor write output: %v", err)
	}
}

func runCreateProfile(args []string) {
	fs := flag.NewFlagSet("create-profile", flag.ExitOnError)
	mtu := fs.Int("mtu", 1420, "path MTU budget for max_packet_size")
	profileName := fs.String("profile-name", "", "optional profile name")
	proxyAddr := fs.String("proxy-addr", "", "optional proxy server address (host:port)")
	_ = fs.Parse(args)

	if *mtu < 1280 {
		fatalf("mtu must be >= 1280")
	}

	r := newRNG(0)
	keys := generateKeys()
	obfCfg, maxPayload, padding := buildSafeObf(r, *mtu, keys)
	now := time.Now().UTC().Format("2006-01-02")

	p := profile.Profile{
		Name:              *profileName,
		ProxyAddr:         *proxyAddr,
		HandshakeTimeout:  config.Duration{Duration: 5 * time.Second},
		HandshakeAttempts: 3,
		PreambleDelayMs:   5,
		PreambleJitterMs:  5,
		Quic: profile.QuicConfig{
			MaxPacketSize: *mtu,
			MaxPayload:    maxPayload,
			KeepAlive:     config.Duration{Duration: 20 * time.Second},
			IdleTimeout:   config.Duration{Duration: 2 * time.Minute},
			MaxStreams:    256,
		},
		Obfuscation:      obfCfg,
		TransportPadding: padding,
	}

	if p.Name == "" {
		p.Name = "bf-" + now
	}
	if p.ProxyAddr == "" {
		fmt.Fprintln(os.Stderr, "warning: proxy_addr is empty; set --proxy-addr to generate a usable profile")
	}

	out, err := json.MarshalIndent(profileToJSON(p), "", "  ")
	if err != nil {
		fatalf("create-profile: %v", err)
	}
	if err := writeOutput("", out); err != nil {
		fatalf("create-profile write: %v", err)
	}
}

type keyPair struct {
	priv string
	pub  string
}

func generateKeys() keyPair {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		fatalf("keygen failed: %v", err)
	}
	pub, err := obf.DerivePublicKey(priv)
	if err != nil {
		fatalf("keygen failed: %v", err)
	}
	return keyPair{
		priv: base64.StdEncoding.EncodeToString(priv[:]),
		pub:  base64.StdEncoding.EncodeToString(pub[:]),
	}
}

func buildSafeObf(r rng, mtu int, keys keyPair) (profile.ObfConfig, int, profile.TransportPadding) {
	jc := randRange(r, 3, 5)
	jmin := randRange(r, 200, 600)
	jmaxCap := mtu - 100
	if jmaxCap < 900 {
		jmaxCap = 900
	}
	jmaxUpper := minInt(1400, jmaxCap)
	jmax := randRange(r, 900, jmaxUpper)
	if jmax <= jmin {
		jmax = jmin + randRange(r, 200, 600)
		if jmax > jmaxUpper {
			jmax = jmaxUpper
		}
	}

	s1 := randRange(r, 200, 520)
	s2 := randRange(r, 260, 640)
	s3 := randRange(r, 120, 360)
	s4 := randRange(r, 20, 80)

	width := uint32(randRange(r, 512, 2048))
	ranges, err := generateRanges(r, width, 1, maxUint32, true)
	if err != nil {
		fatalf("header ranges: %v", err)
	}

	overhead := s4 + 4 + 2
	maxS4 := mtu - (1200 + 6)
	if maxS4 < 0 {
		fatalf("mtu too small for payload budget")
	}
	if s4 > maxS4 {
		s4 = maxS4
		overhead = s4 + 6
	}
	budget := mtu - overhead
	if budget < 1200 {
		fatalf("mtu too small for minimum payload budget")
	}
	maxPayload := 1200
	headroom := mtu - overhead - maxPayload

	padding := buildPadding(headroom)

	obfCfg := profile.ObfConfig{
		Jc:                        jc,
		Jmin:                      jmin,
		Jmax:                      jmax,
		S1:                        s1,
		S2:                        s2,
		S3:                        s3,
		S4:                        s4,
		H1:                        fmt.Sprintf("%d-%d", ranges[0].start, ranges[0].end),
		H2:                        fmt.Sprintf("%d-%d", ranges[1].start, ranges[1].end),
		H3:                        fmt.Sprintf("%d-%d", ranges[2].start, ranges[2].end),
		H4:                        fmt.Sprintf("%d-%d", ranges[3].start, ranges[3].end),
		I1:                        "<t>",
		I2:                        "",
		I3:                        "",
		I4:                        "",
		I5:                        "",
		ServerPrivateKey:          keys.priv,
		ServerPublicKey:           keys.pub,
		SignatureValidate:         boolPtr(true),
		RequireTimestamp:          boolPtr(true),
		EncryptedTimestamp:        boolPtr(true),
		RequireEncryptedTimestamp: boolPtr(true),
		SkewSoftSeconds:           15,
		SkewHardSeconds:           30,
		ReplayWindowSeconds:       30,
		ReplayCacheSize:           4096,
		TransportReplay:           false,
		RateLimitPPS:              50,
		RateLimitBurst:            20,
	}
	return obfCfg, maxPayload, padding
}

type profileJSON struct {
	Name              string                   `json:"name"`
	ProxyAddr         string                   `json:"proxy_addr"`
	HandshakeTimeout  string                   `json:"handshake_timeout"`
	HandshakeAttempts int                      `json:"handshake_attempts"`
	PreambleDelayMs   int                      `json:"preamble_delay_ms"`
	PreambleJitterMs  int                      `json:"preamble_jitter_ms"`
	Quic              profileJSONQuic          `json:"quic"`
	Obfuscation       profile.ObfConfig        `json:"obfuscation"`
	TransportPadding  profile.TransportPadding `json:"transport_padding"`
}

type profileJSONQuic struct {
	MaxPacketSize int    `json:"max_packet_size"`
	MaxPayload    int    `json:"max_payload"`
	KeepAlive     string `json:"keepalive"`
	IdleTimeout   string `json:"idle_timeout"`
	MaxStreams    int    `json:"max_streams"`
}

func profileToJSON(p profile.Profile) profileJSON {
	return profileJSON{
		Name:              p.Name,
		ProxyAddr:         p.ProxyAddr,
		HandshakeTimeout:  p.HandshakeTimeout.Duration.String(),
		HandshakeAttempts: p.HandshakeAttempts,
		PreambleDelayMs:   p.PreambleDelayMs,
		PreambleJitterMs:  p.PreambleJitterMs,
		Quic: profileJSONQuic{
			MaxPacketSize: p.Quic.MaxPacketSize,
			MaxPayload:    p.Quic.MaxPayload,
			KeepAlive:     p.Quic.KeepAlive.Duration.String(),
			IdleTimeout:   p.Quic.IdleTimeout.Duration.String(),
			MaxStreams:    p.Quic.MaxStreams,
		},
		Obfuscation:      p.Obfuscation,
		TransportPadding: p.TransportPadding,
	}
}

func buildPadding(headroom int) profile.TransportPadding {
	if headroom <= 0 {
		zero := 0
		return profile.TransportPadding{
			Min:       &zero,
			Max:       &zero,
			BurstMin:  &zero,
			BurstMax:  &zero,
			BurstProb: floatPtr(0),
		}
	}
	minPad := minInt(16, headroom)
	maxPad := minInt(96, headroom)
	if headroom < 16 {
		minPad = 0
	}
	if maxPad < minPad {
		maxPad = minPad
	}
	burstMin := minInt(96, headroom)
	burstMax := minInt(128, headroom)
	burstProb := 0.02
	if headroom < 96 {
		burstMin = 0
		burstMax = 0
		burstProb = 0
	}
	return profile.TransportPadding{
		Min:       intPtr(minPad),
		Max:       intPtr(maxPad),
		BurstMin:  intPtr(burstMin),
		BurstMax:  intPtr(burstMax),
		BurstProb: floatPtr(burstProb),
	}
}

func randRange(r rng, min, max int) int {
	if max <= min {
		return min
	}
	span := uint32(max - min + 1)
	return min + int(r.Uint32()%span)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func intPtr(v int) *int {
	return &v
}

func boolPtr(v bool) *bool {
	return &v
}

func floatPtr(v float64) *float64 {
	return &v
}

func readInput(path string) ([]byte, error) {
	if path == "" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeOutput(path string, data []byte) error {
	if path == "" {
		_, err := os.Stdout.Write(data)
		if err != nil {
			return err
		}
		_, err = os.Stdout.Write([]byte("\n"))
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func decodeBase64(raw []byte) ([]byte, error) {
	trimmed := strings.TrimSpace(string(raw))
	if trimmed == "" {
		return nil, fmt.Errorf("empty base64 input")
	}
	clean := stripWhitespace(trimmed)
	return base64.StdEncoding.DecodeString(clean)
}

func stripWhitespace(input string) string {
	var b strings.Builder
	b.Grow(len(input))
	for _, r := range input {
		switch r {
		case ' ', '\n', '\r', '\t':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func generateRanges(r rng, width, min, max uint32, distinctMSB bool) ([]headerRange, error) {
	if max < min+width {
		return nil, fmt.Errorf("range bounds too small for width")
	}
	if distinctMSB && width >= msbBucketSize {
		return nil, fmt.Errorf("width must be < %d for distinct-msb", msbBucketSize)
	}

	ranges := make([]headerRange, 0, headerCount)
	usedMSB := map[uint8]bool{}
	for len(ranges) < headerCount {
		var start uint32
		if distinctMSB {
			msb := randomMSB(r, usedMSB)
			bucketMin := uint32(msb) << 24
			bucketMax := bucketMin + msbBucketSize - 1
			if bucketMax <= bucketMin+width {
				return nil, fmt.Errorf("bucket too small for width")
			}
			start = randomInRange(r, bucketMin, bucketMax-width)
			usedMSB[msb] = true
		} else {
			start = randomInRange(r, min, max-width)
		}
		hr := headerRange{start: start, end: start + width}
		if overlapsAny(hr, ranges) {
			if distinctMSB {
				delete(usedMSB, uint8(start>>24))
			}
			continue
		}
		ranges = append(ranges, hr)
	}

	sort.Slice(ranges, func(i, j int) bool {
		return ranges[i].start < ranges[j].start
	})
	return ranges, nil
}

func overlapsAny(target headerRange, ranges []headerRange) bool {
	for _, hr := range ranges {
		if target.start <= hr.end && target.end >= hr.start {
			return true
		}
	}
	return false
}

func randomMSB(r rng, used map[uint8]bool) uint8 {
	for {
		val := uint8(r.Uint32() >> 24)
		if used[val] {
			continue
		}
		return val
	}
}

func randomInRange(r rng, min, max uint32) uint32 {
	if max <= min {
		return min
	}
	span := uint64(max - min + 1)
	return min + uint32(uint64(r.Uint32())%span)
}

func newRNG(seed int64) rng {
	if seed != 0 {
		return mathRNG{mrand.New(mrand.NewSource(seed))}
	}
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return mathRNG{mrand.New(mrand.NewSource(time.Now().UnixNano()))}
	}
	seed = int64(binary.LittleEndian.Uint64(buf[:]))
	return mathRNG{mrand.New(mrand.NewSource(seed))}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
