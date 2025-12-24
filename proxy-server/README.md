# Proxy Server Prototype

This prototype exposes a minimal UDP proxy server that accepts an obfuscated connect request and forwards traffic to the upstream destination. Obfuscation is required in UDP mode.

## Request Format

- Byte 0: version (0x01)
- Byte 1: address type (0x01 IPv4, 0x03 domain, 0x04 IPv6)
- Address bytes (variable)
- Port (2 bytes, big-endian)

## Run

```
go run ./cmd/proxy-server --listen 127.0.0.1:9000 --obfuscation \
  --obf-jc 4 --obf-jmin 10 --obf-jmax 50 \
  --obf-s1 39 --obf-s2 32 \
  --obf-h1 1662442204 --obf-h2 793654571 --obf-h3 468452595 --obf-h4 1578142977
```

Optional tuning:

```
go run ./cmd/proxy-server --listen 127.0.0.1:9000 --obfuscation \
  --obf-jc 4 --obf-jmin 10 --obf-jmax 50 \
  --obf-s1 39 --obf-s2 32 \
  --obf-h1 1662442204 --obf-h2 793654571 --obf-h3 468452595 --obf-h4 1578142977 \
  --handshake-timeout 5s --dial-timeout 5s --idle-timeout 2m \
  --metrics-interval 10s
```

Verbose diagnostics (per-connection events):

```
go run ./cmd/proxy-server --config ../../docs/examples/proxy-server.json \
  --profile ../../docs/examples/profile.json --verbose
```

JSON config:

```
go run ./cmd/proxy-server --config ../../docs/examples/proxy-server.json \
  --profile ../../docs/examples/profile.json
```

Private key sources (required when using JSON config):
- `profile.obfuscation.server_private_key` in the profile file.
- `BF_SERVER_PRIVATE_KEY` environment variable.
- `--server-private-key-file` (base64 key file).

## Test

```
go test ./...
```
