# Configuration

This project uses JSON config files. Each daemon can also be configured via CLI flags, but JSON is the source-of-truth format for validation and examples. When using files, pass the server config with `--config` and the shared profile with `--profile`.

## SOCKS5 Daemon (`socks5-daemon`)

Server config filSee `docs/examples/paniq-socks.json` for a full example. (shared): `docs/examples/profile.json`

Server config fields:

- `listen_addr` (string, required): TCP bind address, e.g. `127.0.0.1:1080`
- `username` / `password` (string, optional): SOCKS5 auth credentials. Both must be set or both empty.
- `workers` (int, optional): worker goroutines; default 8.
- `max_connections` (int, optional): max queued connections; default 128.
- `dial_timeout` (duration, optional): upstream dial timeout, e.g. `"5s"`.
- `accept_timeout` (duration, optional): e.g. `"500ms"`.
- `idle_timeout` (duration, optional): e.g. `"2m"`.
- `metrics_interval` (duration, optional): e.g. `"10s"` (set to `"0s"` to disable).
- `log_level` (string, optional): `"info"` or `"debug"` (default `"info"`). Debug enables transport size diagnostics.
- `verbose` (bool, optional): enable diagnostic logs for connection lifecycle.

Profile fields (portable between socks5-daemon and proxy-server):

- `proxy_addr` (string, required): proxy server address (`host:port`) for QUIC.
- `handshake_timeout` (duration, optional): e.g. `"5s"`.
- `handshake_attempts` (int, optional): preamble retry attempts; default 3.
- `preamble_delay_ms` (int, optional): delay between preamble packets (ms).
- `preamble_jitter_ms` (int, optional): random jitter added to preamble delay (ms).
- `quic` (object, optional): QUIC settings for the client↔proxy transport.
  - `max_packet_size` (int): total envelope datagram size (default 1350).
  - `max_payload` (int, optional): max inner QUIC payload size. Must be ≥1200 and ≤ the transport payload budget. If unset, uses the full transport payload budget.
  - `keepalive` (duration): QUIC keepalive period (default `20s`).
  - `idle_timeout` (duration): QUIC idle timeout (default `2m`).
  - `max_streams` (int): max concurrent QUIC streams (default 256).
- `obfuscation` (object, required): AWG obfuscation settings (required for QUIC).
- `transport_padding` (object, optional): MessageTransport padding policy.

Tip: use `bf create-profile --mtu 1420` to generate a safe randomized profile with fresh keys.

Transport payload budget is computed as:

```
max_packet_size - (S4 + 4 + 2 [+8 if transport_replay])
```

Obfuscation fields:

- `jc`, `jmin`, `jmax` (ints): junk packet count and size range.
- `s1`..`s4` (ints): padding sizes.
- `h1`..`h4` (strings): header ranges (`"x-y"` or `"x"`).
- `i1`..`i5` (strings): custom signature packet specs.
- `server_public_key` (string, optional): base64 server public key for MAC1.
- `encrypted_timestamp` (bool, optional): send encrypted timestamp in initiation payload (default true if server_public_key is set).
- `transport_replay` (bool, optional): enable RFC6479 replay filter for transport counters.
- `transport_replay_limit` (int, optional): max counter value; defaults to RFC6479 limit.

Note: when `require_timestamp` is true on the server, at least one signature spec must include `<t>`.
Operational note: `transport_replay` is disabled in examples to avoid false positives during early testing; it is strict about counter monotonicity and can drop valid packets if counters reset or reorder. Enable it only after validating your deployment’s transport stability.
Security note: client profiles should omit `server_private_key`. Remove it before encoding a profile for client distribution.

Transport padding fields (`profile.transport_padding`):
- `pad_min` (int, optional): minimum padding bytes per datagram.
- `pad_max` (int, optional): maximum padding bytes per datagram.
- `pad_burst_min` (int, optional): burst padding minimum.
- `pad_burst_max` (int, optional): burst padding maximum.
- `pad_burst_prob` (float, optional): burst probability in [0,1].

Defaults (obfuscation‑biased): `pad_min=0`, `pad_max=64`, `pad_burst_min=128`, `pad_burst_max=256`, `pad_burst_prob=0.02`.

Operational note: padding is clamped to the available headroom. To avoid excessive `pad_clamp`, keep `pad_max` (and `pad_burst_max`) ≤ `max_packet_size - (S4 + 4 + 2 [+8 if transport_replay]) - quic.max_payload`.

## Proxy Server (`proxy-server`)

Server config file: `docs/examples/proxy-server.json`
Profile file (shared): `docs/examples/profile.json`

Server config fields:

- `listen_addr` (string, required): UDP bind address for QUIC, e.g. `0.0.0.0:9000`.
- `workers` (int, optional): worker goroutines; default 8.
- `max_connections` (int, optional): max queued connections; default 128.
- `dial_timeout` (duration, optional): e.g. `"5s"`.
- `accept_timeout` (duration, optional): read deadline for the UDP socket used by QUIC, e.g. `"500ms"`.
- `idle_timeout` (duration, optional): e.g. `"2m"`.
- `metrics_interval` (duration, optional): e.g. `"10s"` (set to `"0s"` to disable).
- `log_level` (string, optional): `"info"` or `"debug"` (default `"info"`). Debug enables transport size diagnostics.
- `verbose` (bool, optional): enable diagnostic logs for connection lifecycle.

Obfuscation + security fields (under `profile.obfuscation`):

- `jc`, `jmin`, `jmax` (ints): junk packet count and size range.
- `s1`..`s4` (ints): padding sizes.
- `h1`..`h4` (strings): header ranges (`"x-y"` or `"x"`).
- `i1`..`i5` (strings): custom signature packet specs.
- `server_private_key` (string, required for proxy-server): base64 server private key for MAC1.
- `signature_validate` (bool, optional): validate signature contents (default true).
- `require_timestamp` (bool, optional): require `<t>` in signatures (default true).
- `encrypted_timestamp` (bool, optional): accept encrypted timestamp in initiation payload (default true if server_private_key is set).
- `require_encrypted_timestamp` (bool, optional): require encrypted timestamp (default false).
- `legacy_mode_enabled` (bool, optional): allow signatures without `<t>` (default false).
- `legacy_mode_sunset` (string, optional): hard sunset date (`YYYY-MM-DD` or RFC3339).
- `legacy_mode_max_days` (int, optional): max days to allow legacy mode.
- `skew_soft_seconds` (int, optional): soft skew threshold (default 15).
- `skew_hard_seconds` (int, optional): hard skew threshold (default 30).
- `replay_window_seconds` (int, optional): replay window (default 30).
- `replay_cache_size` (int, optional): replay cache capacity (default 4096).
- `transport_replay` (bool, optional): enable RFC6479 replay filter for transport counters.
- `transport_replay_limit` (int, optional): max counter value; defaults to RFC6479 limit.
- `rate_limit_pps` (int, optional): per-IP handshake packets per second (default 20 when set).
- `rate_limit_burst` (int, optional): per-IP burst size (default 5 when set).

Legacy mode requires a sunset (`legacy_mode_sunset` or `legacy_mode_max_days`) and will refuse to start if the sunset has passed.
When only `legacy_mode_max_days` is set, the sunset is computed relative to process start time.
When `require_encrypted_timestamp` is enabled, `<t>` in signature packets is optional.
Proxy server startup requires a private key. The key may be provided in `profile.obfuscation.server_private_key`, via the `BF_SERVER_PRIVATE_KEY` environment variable, or via the `--server-private-key-file` CLI flag.

## Duration Format

Durations use Go-style strings, for example:

- `"500ms"`
- `"5s"`
- `"2m"`
