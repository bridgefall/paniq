# Proxy Architecture Design

## Summary

This document specifies the architecture for the Proxy System: a SOCKS5 client and a proxy server that use AmneziaWG’s obfuscation layer verbatim (matching `amnezia-vpn/amneziawg-go` @ `e796d47`). The design prioritizes compatibility with AWG obfuscation, debug visibility, and a clean path to future code sharing with AmneziaWG.

## Goals

- Implement AmneziaWG obfuscation behavior exactly (junk packets, paddings, headers, custom signature packets).
- Provide a SOCKS5 client (with authentication) that forwards traffic through the proxy.
- Keep the obfuscation code modular and aligned with upstream to enable future merges.
- Target macOS for development and Linux for deployment/testing.

## Non-Goals

- Full AmneziaWG config compatibility beyond obfuscation fields.
- Multi-hop routing or policy engines.
- Bootstrap/discovery systems.
- Full application SDK APIs beyond SOCKS5.

## High-Level Architecture

Components:

1. **SOCKS5 Client**
   - Listens on a local TCP port.
   - Enforces username/password authentication.
   - Opens a proxied tunnel to the Proxy Server.

2. **Proxy Server**
   - Accepts proxied connections from clients.
   - Applies AmneziaWG obfuscation layer to all traffic.
   - Forwards to upstream destinations.

3. **Obfuscation Layer (AWG-derived)**
   - Shared library/module containing AWG obfuscation primitives.
   - Strictly aligned with AWG behavior (see [amneziawg-go](https://github.com/amnezia-vpn/amneziawg-go)).

Data flow (QUIC over AWG envelope):

1) Application → SOCKS5 Client (local).
2) SOCKS5 Client → Proxy Server (obfuscated QUIC transport).
3) Proxy Server → Upstream destination.

## Transport Model (QUIC-only)

- The client↔proxy link is QUIC over an AWG-style UDP envelope.
- QUIC provides stream multiplexing and reliability.
- No non-QUIC fallback is supported at this stage.

## Component Responsibilities

### SOCKS5 Client

- Accept SOCKS5 CONNECT requests (TCP).
- Authenticate using username/password only (no PAM).
- Map local requests to proxied sessions.
- Maintain reconnect and retry logic.
- Emit detailed metrics and logs (debug-first).

### Proxy Server

- Accept inbound client sessions.
- Apply AWG obfuscation to all packets.
- Enforce session timeouts and limits.
- Provide operational metrics and high-verbosity logs.

### Obfuscation Layer (AWG-derived)

- Implements AWG junk packets: `Jc`, `Jmin`, `Jmax`.
- Implements AWG paddings: `S1`, `S2`, `S3`, `S4`.
- Implements AWG header ranges: `H1`, `H2`, `H3`, `H4`.
- Implements custom signature packets: `I1`..`I5` with tags `<b>`, `<r>`, `<rd>`, `<rc>`, `<t>`, `<c>`.
- Unset parameters default to `0`.
- Behavior must match AWG bit-for-bit where applicable.

## Configuration

- Define a project-specific config format that includes:
  - SOCKS5 bind address, auth credentials.
  - Proxy server listen address.
  - AWG obfuscation parameters (J*, S*, H*, I*).
- Provide mapping to the AWG parameters with no behavioral deviations.
- Example configs live in `docs/examples/`.

## Observability

- Metrics: active sessions, auth failures, handshake success/failure, reconnect count, bytes in/out, p95/p99 latency.
- Logs: config validation summary, session lifecycle, obfuscation errors.
- Use `LOG_LEVEL=debug` for verbose output (parity with AWG tooling expectations).

## Security

- Enforce SOCKS5 authentication; reject anonymous access.
- Never log keys, raw payloads, or credentials.
- Validate all configuration values and bounds.

## Platform Considerations

- macOS: development target; use user-space networking.
- Linux: primary deployment target.

## Risks

- Obfuscation mismatch with AWG due to implementation drift.
- SOCKS5 auth complexity or misconfiguration.
- Performance overhead from obfuscation and logging.

## Open Questions

- Which upstream AmneziaWG files should be vendor-copied vs. imported as a module?
- What is the preferred config format (INI, YAML, or JSON)?
- Should UDP associate be supported?
