#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONFIG_FILE="${CONFIG_FILE:-${ROOT_DIR}/docs/examples/paniq-socks.json}"
PROFILE="${ROOT_DIR}/docs/examples/profile.json"
cd "${ROOT_DIR}"
go run ./cmd/paniq-socks --config "${CONFIG_FILE}" --profile "${PROFILE}"
