#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CFG="${ROOT_DIR}/docs/examples/paniq-proxy.json"
PROFILE="${ROOT_DIR}/docs/examples/profile.json"
cd "${ROOT_DIR}"
go run ./cmd/paniq-proxy --config "${CFG}" --profile "${PROFILE}"
