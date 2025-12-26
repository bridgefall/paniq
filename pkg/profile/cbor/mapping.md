# CBOR Profile Mapping (v1)

This mapping defines a compact, schema-less CBOR representation of the JSON profile in `transport/profile`.

Encoding rules:
- CBOR map keys are unsigned integers.
- Durations are encoded as unsigned integer milliseconds.
- Public/private keys are CBOR byte strings (decoded from base64 JSON strings).
- Fields with default values are omitted.
- Optional fields are omitted when unset.

## Top-level map

| JSON field | CBOR key | Type |
| --- | --- | --- |
| `version` | `0` | uint |
| `name` | `1` | text |
| `proxy_addr` | `2` | text |
| `handshake_timeout` | `3` | uint (ms) |
| `handshake_attempts` | `4` | uint |
| `preamble_delay_ms` | `5` | uint |
| `preamble_jitter_ms` | `6` | uint |
| `quic` | `7` | map |
| `obfuscation` | `8` | map |
| `transport_padding` | `9` | map |

## QUIC map (`quic`)

| JSON field | CBOR key | Type |
| --- | --- | --- |
| `max_packet_size` | `1` | uint |
| `max_payload` | `2` | uint |
| `keepalive` | `3` | uint (ms) |
| `idle_timeout` | `4` | uint (ms) |
| `max_streams` | `5` | uint |

## Obfuscation map (`obfuscation`)

| JSON field | CBOR key | Type |
| --- | --- | --- |
| `jc` | `1` | uint |
| `jmin` | `2` | uint |
| `jmax` | `3` | uint |
| `s1` | `4` | uint |
| `s2` | `5` | uint |
| `s3` | `6` | uint |
| `s4` | `7` | uint |
| `h1` | `8` | text |
| `h2` | `9` | text |
| `h3` | `10` | text |
| `h4` | `11` | text |
| `i1` | `12` | text |
| `i2` | `13` | text |
| `i3` | `14` | text |
| `i4` | `15` | text |
| `i5` | `16` | text |
| `server_private_key` | `17` | bytes |
| `server_public_key` | `18` | bytes |
| `signature_validate` | `19` | bool |
| `require_timestamp` | `20` | bool |
| `encrypted_timestamp` | `21` | bool |
| `require_encrypted_timestamp` | `22` | bool |
| `legacy_mode_enabled` | `23` | bool |
| `legacy_mode_sunset` | `24` | text |
| `legacy_mode_max_days` | `25` | uint |
| `skew_soft_seconds` | `26` | uint |
| `skew_hard_seconds` | `27` | uint |
| `replay_window_seconds` | `28` | uint |
| `replay_cache_size` | `29` | uint |
| `transport_replay` | `30` | bool |
| `transport_replay_limit` | `31` | uint |
| `rate_limit_pps` | `32` | uint |
| `rate_limit_burst` | `33` | uint |

## Transport padding map (`transport_padding`)

| JSON field | CBOR key | Type |
| --- | --- | --- |
| `pad_min` | `1` | uint |
| `pad_max` | `2` | uint |
| `pad_burst_min` | `3` | uint |
| `pad_burst_max` | `4` | uint |
| `pad_burst_prob` | `5` | float |
