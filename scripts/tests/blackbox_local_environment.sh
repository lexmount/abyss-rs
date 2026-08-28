#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/abyss-local-blackbox.XXXXXX")"
FAKE_BIN="${TEST_ROOT}/bin"
TEST_HOME="${TEST_ROOT}/home"
MANAGER="${REPO_ROOT}/scripts/abyss-local"
BLOCKER_PID=""

find_free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

BACKEND_PORT="$(find_free_port)"
DASHBOARD_PORT="$(find_free_port)"
while [[ "${DASHBOARD_PORT}" == "${BACKEND_PORT}" ]]; do
  DASHBOARD_PORT="$(find_free_port)"
done

run_local() {
  ABYSS_HOME="${TEST_HOME}" \
  ABYSS_RUNTIME_BIN_DIR="${FAKE_BIN}" \
  ABYSS_USER_BIN_DIR="${FAKE_BIN}" \
  ABYSS_LOCAL_BACKEND_PORT="${BACKEND_PORT}" \
  ABYSS_LOCAL_DASHBOARD_PORT="${DASHBOARD_PORT}" \
    "${MANAGER}" "$@"
}

cleanup() {
  if [[ -n "${BLOCKER_PID}" ]] && kill -0 "${BLOCKER_PID}" 2>/dev/null; then
    kill -TERM "${BLOCKER_PID}" 2>/dev/null || true
    wait "${BLOCKER_PID}" 2>/dev/null || true
  fi
  run_local stop >/dev/null 2>&1 || true
  rm -rf "${TEST_ROOT}"
}
trap cleanup EXIT

file_mode() {
  if [[ "$(uname -s)" == "Darwin" ]]; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

mkdir -p "${FAKE_BIN}"
install -m 0755 \
  "${REPO_ROOT}/scripts/tests/fixtures/fake_local_service.py" \
  "${FAKE_BIN}/abyss-backend"
install -m 0755 \
  "${REPO_ROOT}/scripts/tests/fixtures/fake_local_service.py" \
  "${FAKE_BIN}/abyss-dashboard"
install -m 0755 \
  "${REPO_ROOT}/scripts/tests/fixtures/fake_local_service.py" \
  "${FAKE_BIN}/port-blocker"
install -m 0755 \
  "${REPO_ROOT}/scripts/tests/fixtures/fake_abyss.sh" \
  "${FAKE_BIN}/abyss"

run_local init
[[ "$(file_mode "${TEST_HOME}/local/backend.token")" == "600" ]]
[[ "$(file_mode "${TEST_HOME}/local/backend.authorization")" == "600" ]]
[[ "$(file_mode "${TEST_HOME}/product-config.json")" == "600" ]]
grep -Fq "http://127.0.0.1:${BACKEND_PORT}/v1/agent-usage/events" \
  "${TEST_HOME}/product-config.json"
grep -Fq "\"url\": \"http://127.0.0.1:${DASHBOARD_PORT}\"" \
  "${TEST_HOME}/product-config.json"
token="$(tr -d '\r\n' <"${TEST_HOME}/local/backend.token")"
[[ "$(tr -d '\r\n' <"${TEST_HOME}/local/backend.authorization")" == "Bearer ${token}" ]]
unset token

start_output="$(run_local start)"
[[ "${start_output}" == *"Dashboard: http://127.0.0.1:${DASHBOARD_PORT}"* ]]
curl --noproxy '*' -fsS "http://127.0.0.1:${BACKEND_PORT}/readyz" >/dev/null
curl --noproxy '*' -fsS "http://127.0.0.1:${DASHBOARD_PORT}/healthz" >/dev/null
run_local status
run_local start
run_local stop
if run_local status >/dev/null 2>&1; then
  printf 'stopped environment unexpectedly reported healthy\n' >&2
  exit 1
fi

printf '%s\n' "$$" >"${TEST_HOME}/local/run/backend.pid"
run_local stop
[[ ! -e "${TEST_HOME}/local/run/backend.pid" ]]

"${FAKE_BIN}/port-blocker" "${DASHBOARD_PORT}" >/dev/null 2>&1 &
BLOCKER_PID=$!
for _attempt in {1..20}; do
  if curl --noproxy '*' -fsS "http://127.0.0.1:${DASHBOARD_PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
curl --noproxy '*' -fsS "http://127.0.0.1:${DASHBOARD_PORT}/healthz" >/dev/null
if run_local start >/dev/null 2>&1; then
  printf 'port conflict unexpectedly allowed local environment startup\n' >&2
  exit 1
fi
[[ ! -e "${TEST_HOME}/local/run/backend.pid" ]]
[[ ! -e "${TEST_HOME}/local/run/dashboard.pid" ]]
if curl --noproxy '*' -fsS "http://127.0.0.1:${BACKEND_PORT}/readyz" >/dev/null 2>&1; then
  printf 'failed startup did not roll back the backend\n' >&2
  exit 1
fi

kill -TERM "${BLOCKER_PID}"
wait "${BLOCKER_PID}" || true
BLOCKER_PID=""

printf 'abyss-local black-box test passed\n'
