#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CFG="${ROOT_DIR}/docs/examples/socks5d.json"
PROFILE="${ROOT_DIR}/docs/examples/profile.json"
cd "${ROOT_DIR}/socks5-daemon"
go run ./cmd/socks5d --config "${CFG}" --profile "${PROFILE}"
