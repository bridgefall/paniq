# Transport Protocol (UDP Envelope)

This document defines the UDP envelope used between the SOCKS5 client and proxy server, including all packet types, fields, and validation rules. It is based on the current implementation in `obf/` and `envelope/`.

## 1. Overview

All client↔server traffic uses UDP datagrams. The envelope has two phases:

1. **Preamble**: a sequence of unframed junk and signature packets followed by a framed initiation packet.
2. **Transport**: framed datagrams carrying the inner transport payload (QUIC datagrams).

Key configuration parameters (from `docs/config.md`) influence wire format:

- **Jc/Jmin/Jmax**: junk datagram count and size range.
- **S1/S2/S3/S4**: padding lengths for framed packets.
- **H1/H2/H3/H4**: header ranges for framed packet types.
- **I1..I5**: signature chain specifications.
- **encrypted_timestamp** / **require_encrypted_timestamp**: initiation payload format.
- **transport_replay** / **transport_replay_limit**: transport counter prefix and replay filter.

## 2. Common Framed Datagram Format

Used by MessageInitiation, MessageResponse, MessageCookieReply, and MessageTransport.

```
| padding (S*) | header (4 bytes, LE) | payload (variable) |
```

**Fields**

| Field   | Size | Encoding | Description |
|---------|------|----------|-------------|
| padding | S*   | raw      | Cryptographically random bytes. Length depends on message type. |
| header  | 4    | uint32 LE | Random value within the configured header range for that message type. |
| payload | var  | bytes    | Message-specific fields (see below). |

**Header ranges**

Header specs are configured as `start-end` decimal ranges (inclusive). If only one number is provided, the range is a single value.

Example: `"1662442204"` means only that value; `"100-200"` means any uint32 in [100,200].

At decode time, the receiver tries each message type by applying its padding length and checking if the header value falls within the configured range. If zero or multiple types match, the datagram is rejected.

## 3. Preamble Packet Types

Preamble packets are **not framed**. The server expects them in strict order: junk → signatures → initiation.

### 3.1 Junk (Preamble-only)

```
| random bytes (length in [Jmin, Jmax]) |
```

**Fields**

| Field | Size | Encoding | Description |
|-------|------|----------|-------------|
| junk  | var  | raw      | Cryptographically random bytes. |

**Notes**

- Exactly `Jc` junk packets must appear before signatures.
- Any junk packet is accepted during the junk phase; it is not parsed or validated.

### 3.2 Signature (Preamble-only)

```
| chain-obfuscated bytes (length = chain.ObfuscatedLen(0)) |
```

**Fields**

| Field | Size | Encoding | Description |
|-------|------|----------|-------------|
| sig   | fixed | chain-specific | Output of the signature chain obfuscation for a zero-length payload. |

**Validation**

- If `signature_validate` is enabled, the server deobfuscates and validates each chain.
- If any signature length mismatches or deobfuscation fails, the handshake resets.
- If a `<t>` tag is present, it is parsed as a Unix timestamp (seconds, big-endian uint32).

**Signature chain tags**

Signature chains are defined by `I1..I5` specs and parsed as a sequence of tags:

| Tag | Size (obfuscated) | Validation | Description |
|-----|------------------|------------|-------------|
| `<b HEX>` | len(HEX)/2 | exact match | Fixed bytes (hex string). |
| `<t>` | 4 | none (parses) | Unix time in seconds, big-endian uint32. |
| `<r N>` | N | none | Random bytes. |
| `<rc N>` | N | ascii alpha | Random A–Z/a–z bytes. |
| `<rd N>` | N | digits only | Random 0–9 bytes. |
| `<d>` | variable | copy | Raw data bytes (payload). |
| `<ds>` | variable | base64 | Raw payload bytes encoded in base64 (no padding). |
| `<dz N>` | N | none | Data length encoded in N bytes (big-endian). |

**Important**

- Signature datagrams use **only the obfuscated output**; there is no framed header.
- For preamble signatures the payload is treated as zero-length, so any `<d>/<ds>/<dz>` contributions are based on `n=0`.

## 4. Framed Packet Types

### 4.1 MessageInitiation (H1/S1)

**Purpose**: client initiates handshake after junk + signature packets.

**Payload Layout**

```
| encrypted_timestamp (optional) | MAC1 (optional, 16 bytes) |
```

#### 4.1.1 Encrypted Timestamp Payload (optional)

```
| version (1) | client_pub (32) | nonce (24) | ciphertext (28) |
```

**Fields**

| Field | Size | Encoding | Description |
|-------|------|----------|-------------|
| version | 1 | uint8 | Currently `0x01`. |
| client_pub | 32 | raw | Ephemeral X25519 public key. |
| nonce | 24 | raw | XChaCha20-Poly1305 nonce. |
| ciphertext | 28 | raw | AEAD-encrypted TAI64N timestamp (12 bytes) + 16‑byte tag. |

**Crypto**

- Shared secret: `X25519(client_priv, server_pub)`
- Key derivation: `blake2s("ts-encrypt" || shared)`
- AEAD: XChaCha20-Poly1305, empty associated data.
- Plaintext: 12‑byte TAI64N timestamp.

**Server validation**

- Decrypts payload if enabled.
- Requires monotonic increase per peer (per 4‑tuple).
- If `require_encrypted_timestamp=true`, initiation is rejected if missing or invalid.

#### 4.1.2 MAC1 (optional)

**Fields**

| Field | Size | Encoding | Description |
|-------|------|----------|-------------|
| mac1 | 16 | raw | MAC1 tag computed over the framed datagram. |

**Computation**

- MAC1 is appended to the initiation payload.
- The MAC1 bytes are zeroed in the framed datagram before computing.
- Key is derived from the server public key.

### 4.2 MessageResponse (H2/S2)

**Purpose**: server acknowledgement (“AWG OK”).

**Payload**

```
| empty |
```

**Notes**

- The client enables transport only after receiving this response.

### 4.3 MessageTransport (H4/S4)

**Purpose**: carries the inner transport datagram (QUIC).

**Payload Layout**

```
| counter (8 bytes, optional) | inner_len (2 bytes) | inner_payload (var) | padding (var) |
```

**Fields**

| Field | Size | Encoding | Description |
|-------|------|----------|-------------|
| counter | 8 | uint64 BE | Monotonic counter for replay detection (optional). |
| inner_len | 2 | uint16 BE | Length of the inner payload (bytes). |
| inner_payload | var | raw | Inner transport datagram bytes (QUIC). |
| padding | var | raw | Random padding bytes (optional). |

**Replay protection**

- If `transport_replay=true`, the counter is required.
- The server applies RFC6479 replay filter with a sliding window.
- Limit defaults to `replay.RejectAfterMessages` unless configured.

**Padding**

- Padding length is selected by `profile.transport_padding` policy.
- If padding is disabled, `padding` is zero-length.
- If the selected padding would exceed the max transport payload budget, it is clamped and recorded.
- To create padding headroom under load, deployments can cap QUIC payload size below the transport payload budget.

### 4.4 MessageCookieReply (H3/S3)

**Purpose**: reserved for cookie challenges.

**Payload**

```
| reserved |
```

**Notes**

- Cookie challenges are currently disabled. This type is reserved for future use.

## 5. Server Validation Order (Preamble Phase)

1. **Rate limit** (per IP token bucket).
2. **Junk counter** enforcement.
3. **Signature length** check.
4. **Signature content** validation (if enabled).
5. **Initiation decode** (framed).
6. **MAC1 verification** (if enabled).
7. **Encrypted timestamp** decrypt + monotonic check (if enabled).
8. **Legacy `<t>` timestamp** validation + replay cache (if enabled and encrypted timestamp absent).
9. **Send MessageResponse** and mark peer ready.

## 6. Size Constraints

For framed transport packets:

```
max_transport_payload = MaxPacketSize - (S4 + 4)
len(counter + inner_len + inner_payload + padding) <= max_transport_payload
```

Where:
- `MaxPacketSize` is the configured QUIC envelope packet size.
- `S4` is the MessageTransport frame padding length.
- `4` is the frame header length.

If `transport_replay=true`, the 8‑byte counter is part of the payload size.

Operational note: when `quic.max_payload` is set lower than `max_transport_payload`, the difference becomes padding headroom. This improves size variance but reduces peak throughput.

## 7. Notes and Best‑Practice Guidance

- Signature and junk packets are intentionally unframed.
- Encrypted timestamp is preferred; `<t>` is legacy and should be phased out.
- MAC1 and replay checks are only meaningful if keys are correctly paired between server and client.
- Preamble ordering is strict; unexpected packets reset state.
