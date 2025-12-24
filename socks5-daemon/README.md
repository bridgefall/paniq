# SOCKS5 Daemon Prototype

This is a minimal SOCKS5 server implementation with optional username/password authentication (no PAM). The daemon forwards traffic through the UDP proxy server; `proxy-addr` and obfuscation settings are required.

## Run

```
go run ./cmd/socks5d --listen 127.0.0.1:1080 --proxy-addr 127.0.0.1:9000 \
  --username user --password pass --obfuscation \
  --obf-jc 4 --obf-jmin 10 --obf-jmax 50 \
  --obf-s1 39 --obf-s2 32 --obf-h1 1662442204 --obf-h2 793654571 \
  --obf-h3 468452595 --obf-h4 1578142977
```

Optional tuning:

```
go run ./cmd/socks5d --listen 127.0.0.1:1080 --proxy-addr 127.0.0.1:9000 \
  --username user --password pass \
  --handshake-timeout 5s --dial-timeout 5s --idle-timeout 2m \
  --metrics-interval 10s
```

Verbose diagnostics (per-connection events):

```
go run ./cmd/socks5d --config ../../docs/examples/socks5d.json \
  --profile ../../docs/examples/profile.json --verbose
```

Handshake pacing (helps on lossy/reordering links):

```
go run ./cmd/socks5d --config ../../docs/examples/socks5d.json \
  --profile ../../docs/examples/profile.json \
  --handshake-attempts 3 --preamble-delay-ms 5 --preamble-jitter-ms 5
```

JSON config:

```
go run ./cmd/socks5d --config ../../docs/examples/socks5d.json \
  --profile ../../docs/examples/profile.json
```

## Test

```
go test ./...
```
