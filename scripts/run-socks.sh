#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONFIG_FILE="${CONFIG_FILE:-${ROOT_DIR}/docs/examples/paniq-socks.json}"
PROFILE="${ROOT_DIR}/docs/examples/profile.json"
cd "${ROOT_DIR}/socks5-daemon"
go run ./cmd/socks5d --config "${CONFIG_FILE}" --profile "${PROFILE}"
