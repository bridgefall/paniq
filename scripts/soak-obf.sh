#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SOAK_SECONDS=${SOAK_SECONDS:-900}
HTTP_PORT=${HTTP_PORT:-18080}
SOCKS_ADDR=${SOCKS_ADDR:-127.0.0.1:1080}
PROXY_ADDR=${PROXY_ADDR:-127.0.0.1:9000}
USERNAME=${SOCKS_USERNAME:-user}
PASSWORD=${SOCKS_PASSWORD:-pass}
TMP_DIR=$(mktemp -d)
DATA_FILE="$TMP_DIR/large.bin"

cleanup() {
  if [[ -n "${HTTP_PID:-}" ]]; then kill "$HTTP_PID" >/dev/null 2>&1 || true; fi
  if [[ -n "${PROXY_PID:-}" ]]; then kill "$PROXY_PID" >/dev/null 2>&1 || true; fi
  if [[ -n "${SOCKS_PID:-}" ]]; then kill "$SOCKS_PID" >/dev/null 2>&1 || true; fi
  if [[ -z "${KEEP_TMP:-}" ]]; then
    rm -rf "$TMP_DIR"
  else
    printf "Keeping temp dir: %s\n" "$TMP_DIR"
  fi
}
trap cleanup EXIT

kill_port() {
  local port=$1
  pids=$(lsof -ti tcp:"$port" 2>/dev/null || true)
  udp_pids=$(lsof -ti udp:"$port" 2>/dev/null || true)
  pids="${pids} ${udp_pids}"
  if [[ -n "$pids" ]]; then
    kill $pids >/dev/null 2>&1 || true
  fi
}

# Ensure ports are free before starting
kill_port "$HTTP_PORT"
kill_port 9000
kill_port 1080

wait_for_port() {
  local host=$1
  local port=$2
  local proto=$3
  local name=$4
  local deadline=$(( $(date +%s) + 10 ))
  while [[ $(date +%s) -lt $deadline ]]; do
    if [[ "$proto" == "udp" ]]; then
      if nc -zu "$host" "$port" >/dev/null 2>&1; then
        return 0
      fi
    elif nc -z "$host" "$port" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  printf "Timeout waiting for %s on %s:%s (%s)\n" "$name" "$host" "$port" "$proto" >&2
  return 1
}

printf "Temp dir: %s\n" "$TMP_DIR"
printf "Preparing %s...\n" "$DATA_FILE"
dd if=/dev/zero of="$DATA_FILE" bs=1m count=5 status=none

printf "Starting HTTP server on %s...\n" "$HTTP_PORT"
python3 -m http.server --bind 127.0.0.1 --directory "$TMP_DIR" "$HTTP_PORT" >"$TMP_DIR/http.log" 2>&1 &
HTTP_PID=$!

printf "Starting proxy server (%s)...\n" "$PROXY_ADDR"
(
  cd "$ROOT_DIR/proxy-server"
  go run ./cmd/proxy-server --config ../../docs/examples/proxy-server.json \
    --profile ../../docs/examples/profile.json >"$TMP_DIR/proxy.log" 2>&1
) &
PROXY_PID=$!

printf "Starting socks5 daemon (%s)...\n" "$SOCKS_ADDR"
(
  cd "$ROOT_DIR/socks5-daemon"
  go run ./cmd/socks5d --config ../../docs/examples/socks5d.json \
    --profile ../../docs/examples/profile.json >"$TMP_DIR/socks.log" 2>&1
) &
SOCKS_PID=$!

wait_for_port 127.0.0.1 "$HTTP_PORT" tcp "http"
wait_for_port 127.0.0.1 9000 udp "proxy"
wait_for_port 127.0.0.1 1080 tcp "socks5"

printf "Running soak for %s seconds...\n" "$SOAK_SECONDS"
start=$(date +%s)
end=$((start + SOAK_SECONDS))
requests=0
total_bytes=0
total_time=0
failures=0

while [[ $(date +%s) -lt $end ]]; do
  stats=$(curl --max-time 5 --socks5-hostname "$SOCKS_ADDR" --proxy-user "$USERNAME:$PASSWORD" \
    -o /dev/null -s -w "%{size_download} %{time_total}" \
    "http://127.0.0.1:$HTTP_PORT/large.bin") || true
  curl_status=${PIPESTATUS[0]:-0}
  if [[ ${curl_status} -ne 0 ]]; then
    failures=$((failures + 1))
    continue
  fi
  size=$(echo "$stats" | awk '{print $1}')
  t=$(echo "$stats" | awk '{print $2}')
  total_bytes=$((total_bytes + size))
  total_time=$(awk -v a="$total_time" -v b="$t" 'BEGIN {printf "%.6f", a + b}')
  requests=$((requests + 1))
  if (( requests % 50 == 0 )); then
    printf "  %d requests...\n" "$requests"
  fi
done

elapsed=$(( $(date +%s) - start ))
mbps=$(awk -v bytes="$total_bytes" -v sec="$elapsed" 'BEGIN {printf "%.2f", (bytes * 8) / (sec * 1000000)}')
avg_latency=$(awk -v total="$total_time" -v count="$requests" 'BEGIN { if (count == 0) {print "0"} else {printf "%.3f", total / count} }')

printf "\nResults:\n"
printf "  Requests: %d\n" "$requests"
printf "  Failures: %d\n" "$failures"
printf "  Total bytes: %d\n" "$total_bytes"
printf "  Duration: %ds\n" "$elapsed"
printf "  Avg request time: %ss\n" "$avg_latency"
printf "  Throughput: %s Mbps\n" "$mbps"
printf "\nLogs: %s\n" "$TMP_DIR"
