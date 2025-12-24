# Bridgefall Paniq (Protocol and Proxy)

[![CI](https://github.com/bridgefall/paniq/actions/workflows/ci.yml/badge.svg)](https://github.com/bridgefall/paniq/actions/workflows/ci.yml)

Transport-layer: obfuscated proxy-server, socks5 daemon, framing, parity harness, and shared packages.

## Modules
- commons
- obf
- proxy-server
- socks5-daemon


## CBOR profile converter
The profile converter encodes JSON profiles into compact CBOR and back with deterministic encoding. It omits default values and replaces verbose field names with numeric keys.

- Mapping table: `profile/cbor/mapping.md`
- API: `github.com/bridgefall/paniq/profile/cbor`
  - `EncodeJSONProfile(jsonBytes []byte) ([]byte, error)`
  - `DecodeCBORToJSON(cborBytes []byte) ([]byte, error)`

## Build
```
./scripts/build-proto.sh
```

## Test
```
make test
```

## Local development
This repository uses a workspace file (`go.work`) so all modules build together without external module fetches.
