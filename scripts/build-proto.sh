#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

GOMODCACHE="${GOMODCACHE:-${ROOT_DIR}/.gomodcache}"
GOPATH="${GOPATH:-${ROOT_DIR}/.gopath}"
TARGET_GOOS="${GOOS:-$(go env GOOS)}"
TARGET_GOARCH="${GOARCH:-$(go env GOARCH)}"
BIN_SUFFIX="${BIN_SUFFIX:-}"
DEFAULT_CGO_ENABLED=1
if [ "${TARGET_GOOS}" = "android" ]; then
  DEFAULT_CGO_ENABLED=0
fi

# Darwin builds need a minimum target flag to avoid LC_UUID linker issues.
MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
MACOSX_DEPLOYMENT_FLAGS="-mmacosx-version-min=${MACOSX_DEPLOYMENT_TARGET}"

build_go() {
  local dir=$1
  local bin=$2
  local out="${ROOT_DIR}/bin/${bin}${BIN_SUFFIX}"

  echo "==> building ${bin}${BIN_SUFFIX} (GOOS=${TARGET_GOOS} GOARCH=${TARGET_GOARCH})"
  (
    cd "${dir}"
    GOMODCACHE="${GOMODCACHE}" \
    GOPATH="${GOPATH}" \
    GOOS="${TARGET_GOOS}" \
    GOARCH="${TARGET_GOARCH}" \
    CGO_ENABLED="${CGO_ENABLED:-${DEFAULT_CGO_ENABLED}}" \
    MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET}" \
    CGO_CFLAGS="$( [ "${TARGET_GOOS}" = "darwin" ] && echo "${MACOSX_DEPLOYMENT_FLAGS}" )" \
    CGO_LDFLAGS="$( [ "${TARGET_GOOS}" = "darwin" ] && echo "${MACOSX_DEPLOYMENT_FLAGS}" )" \
    go build -o "${out}" ./cmd/"${bin}"
  )
}

mkdir -p "${ROOT_DIR}/bin"

build_go "${ROOT_DIR}" "paniq-proxy"
build_go "${ROOT_DIR}" "paniq-socks"
build_go "${ROOT_DIR}" "bf"
