# Proxy and Routing Network PRD

## Overview

This PRD defines the Proxy and Routing Network component. The system delivers:

1. A proxy server whose obfuscation layer is 100% borrowed from AmneziaWG.
2. A proxy client that exposes a local SOCKS5 interface and forwards traffic through the proxy server using the AmneziaWG obfuscation layer.

The system is intended to validate end-to-end connectivity, censorship resilience characteristics, and operational feasibility.

## Compatibility Reference (Authoritative)

Use [amneziawg-go README](https://github.com/amnezia-vpn/amneziawg-go) as the compatibility baseline for the obfuscation layer only (junk packets, paddings, headers, custom signature packets). The implementation must match commit `e796d47` of `amneziawg-go`.

## Goals

- Achieve wire-level compatibility with AmneziaWG obfuscation behavior.
- Keep the obfuscation implementation aligned with AmneziaWG to enable future code sharing or branch merges.
- Provide a local SOCKS5 interface for applications without code changes.
- Enable deployable server and client binaries for controlled testing.
- Target platforms: macOS for development and Linux for deployment/testing.

## Non-Goals

- Full AmneziaWG config compatibility beyond the obfuscation fields listed here.
- Multi-hop routing.
- Advanced policy engines or per-request routing hints.
- Production-grade bootstrap/discovery mechanisms.
- Full client SDK APIs beyond SOCKS5.

## Users and Use Cases

- Operators deploy a proxy server and distribute AmneziaWG config to clients.
- End users run a client that exposes SOCKS5 and routes application traffic through the proxy.

## Functional Requirements

### Proxy Server (AmneziaWG-Compatible)

- Implement the AmneziaWG obfuscation layer (junk packets, paddings, headers, custom signature packets) with identical behavior.
- Support QUIC transport over AWG obfuscation (junk, headers, padding).
- Enforce server-side config constraints (allowed peers, keys, ports, MTU).
- Provide structured logs for session lifecycle and protocol errors.

### Proxy Client (SOCKS5)

- Expose local SOCKS5 interface with TCP support (UDP associate optional).
- Support optional SOCKS5 authentication via username/password only; no PAM integration.
- Load client config that maps cleanly to AmneziaWG obfuscation parameters (format may differ).
- Establish and maintain a tunnel to the proxy server that uses the AmneziaWG obfuscation layer.
- Route all SOCKS5 traffic through the tunnel.
- Handle reconnects and transient network failures without user intervention.

## Configuration

- The server and client must support the AmneziaWG obfuscation parameters listed below.
- Unspecified obfuscation params must be treated as `0` (per reference behavior).
- Junk packets (client-side recommended): `Jc`, `Jmin`, `Jmax`. Generate `Jc` packets with random sizes in `[Jmin, Jmax]` before every handshake.
- Message padding: `S1` (handshake init), `S2` (handshake response), `S3` (handshake cookie), `S4` (transport).
- Message header ranges: `H1`, `H2`, `H3`, `H4`. Accept `x-y` ranges or single values.
- Custom signature packets: `I1`..`I5` sent in order before every handshake. Support tags `<b 0x...>`, `<r n>`, `<rd n>`, `<rc n>`, `<t>`, `<c>`.
- Validate packet sizes and warn when configured sizes exceed system MTU to avoid fragmentation.
- Document any required fields and defaults for the chosen config format.
- Example templates must live in `docs/examples/` and highlight the obfuscation parameters.
- Provide minimal example configs in `docs/`.

## Non-Functional Requirements

- Deterministic protocol behavior matching AmneziaWG (bit-for-bit where applicable).
- Stable operation under packet loss and reordering typical of censored networks.
- Clear diagnostics for handshake failures and config mismatches.
- Safe defaults; no plaintext logging of keys or sensitive metadata.

## Interfaces and Compatibility

- Obfuscation behavior must match the reference AmneziaWG implementation.
- SOCKS5 compliance: RFC 1928 for basic CONNECT; username/password auth supported (no PAM).

## Security and Privacy

- Do not log private keys or full packet payloads.
- Prefer ephemeral session identifiers in logs.
- Validate all config inputs and reject malformed or unsafe values.

## Observability

- Observability footprint is unconstrained; prioritize debug visibility and performance monitoring.
- Metrics: active sessions, handshake success/failure, reconnect count, bytes in/out.
- Logs: startup config validation summary, session lifecycle, protocol errors.
- Respect `LOG_LEVEL=debug` for verbose logging parity with the reference implementation.

## Dependencies and Reuse

- Prefer open-source implementations for SOCKS5 and networking primitives.
- Borrow from AmneziaWG code for the obfuscation layer to reduce compatibility risk.
- Keep the obfuscation implementation modular to enable future code sharing or branch merges with AmneziaWG.
- Ensure any reused code is license-compatible and clearly attributed.

## Milestones

1. Obfuscation compatibility test harness (behavior parity with AmneziaWG).
2. Proxy server with AmneziaWG obfuscation parameter support.
3. SOCKS5 client and end-to-end routing.
4. Load/soak tests in controlled networks.

## Risks

- Protocol compatibility gaps due to incomplete AmneziaWG behavior matching.
- Hidden assumptions in AmneziaWG config fields or defaults.
- SOCKS5 traffic patterns triggering throttling in censored environments.
- QUIC handles loss and retransmission; packet loss should not corrupt streams, but can reduce throughput.

## Open Questions

- Future: what observability data must be reduced or redacted for privacy?
- Should SOCKS5 authentication remain username/password only, or allow a pluggable auth policy?
