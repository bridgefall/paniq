#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CFG="${ROOT_DIR}/docs/examples/proxy-server.json"
PROFILE="${ROOT_DIR}/docs/examples/profile.json"
cd "${ROOT_DIR}/proxy-server"
go run ./cmd/proxy-server --config "${CFG}" --profile "${PROFILE}"
