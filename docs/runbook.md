# Runbook (macOS + Linux)

This runbook covers the prototype daemons and test commands.

## Prerequisites

- Go 1.25+
- macOS or Linux

## Build

From the repo root:

```
make test
```

This runs tests for all prototype modules with an isolated module cache.

Build binaries (host OS):

```
make build
```

Cross-compile Linux (amd64):

```
make build-linux            # defaults ARCH from `go env GOARCH` (e.g., arm64 on Apple Silicon)
# override architecture if needed:
#   ARCH=amd64 make build-linux
```
Outputs: `bin/proxy-server-linux-<arch>`, `bin/socks5d-linux-<arch>`.

## Generate a Safe Profile

Use the `bf` tool to generate a randomized, MTU-aware profile with fresh keys:

```
cd transport
go run ./cmd/bf create-profile --mtu 1420 --profile-name user1 --proxy-addr 1.2.3.4:9000
```

Notes:
- Output is a JSON profile to stdout.
- The profile includes both `server_private_key` and `server_public_key`. Remove the private key before distributing to clients.
- `--mtu` sets `quic.max_packet_size` and drives safe `max_payload` + padding defaults.

## Run: Proxy Server

The proxy server listens on UDP for QUIC (make sure the UDP port is reachable).

Using CLI flags:

```
cd proxy-server

go run ./cmd/proxy-server --listen 127.0.0.1:9000 \
  --obfuscation --obf-jc 4 --obf-jmin 10 --obf-jmax 50 \
  --obf-s1 39 --obf-s2 32 \
  --obf-h1 1662442204 --obf-h2 793654571 --obf-h3 468452595 --obf-h4 1578142977 \
  --handshake-timeout 5s --dial-timeout 5s --idle-timeout 2m \
  --metrics-interval 10s --verbose
```

## Live Stability Tips

- Increase `idle_timeout` to `30s`–`2m` to avoid dropping idle TLS/HTTP2 sessions.
- If you see frequent handshake failures on lossy links, reduce or disable junk packets (`jc=0`) to make the handshake more tolerant.
- `bad record mac` usually indicates transport packet loss after handshake (TLS stream desync).

Using JSON config:

```
cd proxy-server

go run ./cmd/proxy-server --config ../../docs/examples/proxy-server.json \
  --profile ../../docs/examples/profile.json
# or from repo root:
./scripts/run-proxy.sh
```

Private key sources (required when using JSON config):
- `profile.obfuscation.server_private_key` in the profile file.
- `BF_SERVER_PRIVATE_KEY` environment variable.
- `--server-private-key-file` (base64 key file).

## Install: systemd (Debian/Ubuntu)

From `transport/` after building `bin/proxy-server` (via `make build`):

```
sudo make install-proxy-systemd
```

Installs:
- Binary: `/usr/local/bin/proxy-server`
- Configs: `/etc/bridgefall/proxy-server.json`, `/etc/bridgefall/profile.json` (copied from `docs/examples/`)
- Unit: `/etc/systemd/system/proxy-server.service` (from `systemd/proxy-server.service`)

## Run: SOCKS5 Daemon

Using CLI flags:

```
cd socks5-daemon

go run ./cmd/socks5d --listen 127.0.0.1:1080 --proxy-addr 127.0.0.1:9000 \
  --username user --password pass \
  --obfuscation --obf-jc 4 --obf-jmin 10 --obf-jmax 50 \
  --obf-s1 39 --obf-s2 32 \
  --obf-h1 1662442204 --obf-h2 793654571 --obf-h3 468452595 --obf-h4 1578142977 \
  --handshake-timeout 5s --dial-timeout 5s --idle-timeout 2m \
  --metrics-interval 10s --verbose
```

Using JSON config:

```
cd socks5-daemon

go run ./cmd/socks5d --config ../../docs/examples/socks5d.json \
  --profile ../../docs/examples/profile.json
# or from repo root:
./scripts/run-socks.sh
```

## Connectivity Smoke Test

1) Start the proxy server.
2) Start the SOCKS5 daemon.
3) Configure a client to use SOCKS5 at `127.0.0.1:1080` and attempt a simple HTTP request.

Example using curl to check the public IP through SOCKS5:

```
curl --socks5-hostname 127.0.0.1:1080 --proxy-user user:pass https://api.ipify.org
```

## Obfuscated End-to-End Smoke Test

1) Start the proxy server with obfuscation enabled (JSON or flags). Example:

```
cd proxy-server

go run ./cmd/proxy-server --config ../../docs/examples/proxy-server.json \
  --profile ../../docs/examples/profile.json
```

2) Start the SOCKS5 daemon (ensure `profile.proxy_addr` and `profile.obfuscation` match the proxy server profile):

```
cd socks5-daemon

go run ./cmd/socks5d --config ../../docs/examples/socks5d.json \
  --profile ../../docs/examples/profile.json
```

3) Use a SOCKS5-aware client to make a request through `127.0.0.1:1080`.

Expected results:

- Proxy server logs show obfuscation enabled and handshake metrics incrementing.
- SOCKS5 daemon logs show successful connections and byte counters increasing.



## Soak Test (Go)

The soak test uses a Go harness with vegeta and runs the QUIC obfuscated path end-to-end.

```
cd transport
SOAK_SECONDS=30s SOAK_RPS=5 go test -tags soak -run TestSoakObfuscatedQUIC -v ./socks5-daemon
```

Concurrency tuning:

```
SOAK_WORKERS=20 SOAK_MAX_WORKERS=100 SOAK_RPS=50 SOAK_SECONDS=2m \
  go test -tags soak -run TestSoakObfuscatedQUIC -v ./socks5-daemon
```

## Notes

- Metrics are logged at the configured interval (set to `0s` to disable).
- macOS builds use `MACOSX_DEPLOYMENT_TARGET=13.0` in the Makefile to silence linker warnings.
- QUIC handles loss and retransmission; packet loss will surface as higher latency or reduced throughput rather than stream corruption.
