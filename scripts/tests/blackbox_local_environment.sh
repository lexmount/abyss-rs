#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TEST_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/abyss-deploy-local-blackbox.XXXXXX")"
FAKE_BIN="${TEST_ROOT}/bin"
TEST_HOME="${TEST_ROOT}/home"
FOREIGN_HOME="${TEST_ROOT}/foreign-home"
PLATFORM_HOME="${TEST_ROOT}/platform-home"
BLOCKER_PID=""

cargo build --quiet --locked --manifest-path "${REPO_ROOT}/Cargo.toml" --package abyss-cli
TARGET_DIRECTORY="$(cargo metadata \
  --no-deps \
  --format-version 1 \
  --manifest-path "${REPO_ROOT}/Cargo.toml" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
ABYSS_BIN="${TARGET_DIRECTORY}/debug/abyss"

run_local() {
  ABYSS_HOME="${TEST_HOME}" \
  ABYSS_LOCAL_BACKEND_BIN="${FAKE_BIN}/abyss-backend" \
  ABYSS_LOCAL_DASHBOARD_BIN="${FAKE_BIN}/abyss-dashboard" \
  ABYSS_LOCAL_SKIP_PROXY=1 \
    "${ABYSS_BIN}" deploy-local "$@"
}

run_platform_default() (
  unset ABYSS_HOME
  HOME="${PLATFORM_HOME}" \
  ABYSS_LOCAL_BACKEND_BIN="${FAKE_BIN}/abyss-backend" \
  ABYSS_LOCAL_DASHBOARD_BIN="${FAKE_BIN}/abyss-dashboard" \
  ABYSS_LOCAL_SKIP_PROXY=1 \
    "${ABYSS_BIN}" deploy-local "$@"
)

read_state() {
  python3 -c \
    'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]])' \
    "${TEST_HOME}/local/deployment.json" "$1"
}

cleanup() {
  if [[ -n "${BLOCKER_PID}" ]] && kill -0 "${BLOCKER_PID}" 2>/dev/null; then
    kill -TERM "${BLOCKER_PID}" 2>/dev/null || true
    wait "${BLOCKER_PID}" 2>/dev/null || true
  fi
  run_local stop >/dev/null 2>&1 || true
  run_platform_default stop >/dev/null 2>&1 || true
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

case "$(uname -s)" in
  Darwin)
    PLATFORM_STATE_ROOT="${PLATFORM_HOME}/Library/Application Support/Abyss/cli"
    ;;
  Linux)
    PLATFORM_STATE_ROOT="${PLATFORM_HOME}/.abyss"
    ;;
  *)
    printf 'unsupported local deployment test platform\n' >&2
    exit 1
    ;;
esac
run_platform_default start >/dev/null
[[ -f "${PLATFORM_STATE_ROOT}/product-config.json" ]]
run_platform_default status >/dev/null
run_platform_default stop >/dev/null

start_output="$(run_local start)"
[[ "${start_output}" == *"Local environment is ready."* ]]
[[ "${start_output}" == *"Proxy: skipped"* ]]
backend_port="$(read_state backend_port)"
dashboard_port="$(read_state dashboard_port)"
[[ "${backend_port}" != "${dashboard_port}" ]]
[[ "${start_output}" == *"Backend: http://127.0.0.1:${backend_port}"* ]]
[[ "${start_output}" == *"Dashboard: http://127.0.0.1:${dashboard_port}"* ]]
curl --noproxy '*' -fsS "http://127.0.0.1:${backend_port}/readyz" >/dev/null
curl --noproxy '*' -fsS "http://127.0.0.1:${dashboard_port}/healthz" >/dev/null
[[ "$(file_mode "${TEST_HOME}/local/backend.token")" == "600" ]]
[[ "$(file_mode "${TEST_HOME}/local/backend.authorization")" == "600" ]]
[[ "$(file_mode "${TEST_HOME}/product-config.json")" == "600" ]]
grep -Fq "http://127.0.0.1:${backend_port}/v1/agent-usage/events" \
  "${TEST_HOME}/product-config.json"
grep -Fq "\"url\": \"http://127.0.0.1:${dashboard_port}\"" \
  "${TEST_HOME}/product-config.json"

run_local status
backend_pid="$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["pid"])' \
  "${TEST_HOME}/local/run/backend.json")"
dashboard_pid="$(python3 -c \
  'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["pid"])' \
  "${TEST_HOME}/local/run/dashboard.json")"
run_local start >/dev/null
[[ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' \
  "${TEST_HOME}/local/run/backend.json")" == "${backend_pid}" ]]
[[ "$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["pid"])' \
  "${TEST_HOME}/local/run/dashboard.json")" == "${dashboard_pid}" ]]

run_local stop
if run_local status >/dev/null 2>&1; then
  printf 'stopped local deployment unexpectedly reported healthy\n' >&2
  exit 1
fi

"${FAKE_BIN}/port-blocker" "${dashboard_port}" >/dev/null 2>&1 &
BLOCKER_PID=$!
for _attempt in {1..20}; do
  if curl --noproxy '*' -fsS "http://127.0.0.1:${dashboard_port}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
run_local start >/dev/null
replacement_dashboard_port="$(read_state dashboard_port)"
[[ "${replacement_dashboard_port}" != "${dashboard_port}" ]]
curl --noproxy '*' -fsS "http://127.0.0.1:${replacement_dashboard_port}/healthz" >/dev/null
run_local stop >/dev/null
kill -TERM "${BLOCKER_PID}"
wait "${BLOCKER_PID}" || true
BLOCKER_PID=""

ABYSS_HOME="${TEST_HOME}" \
ABYSS_LOCAL_BACKEND_BIN="${FAKE_BIN}/abyss-backend" \
ABYSS_LOCAL_DASHBOARD_BIN="/usr/bin/false" \
ABYSS_LOCAL_SKIP_PROXY=1 \
  "${ABYSS_BIN}" deploy-local start >/dev/null 2>&1 && {
    printf 'failed dashboard unexpectedly allowed local deployment startup\n' >&2
    exit 1
  }
failed_backend_port="$(read_state backend_port)"
if curl --noproxy '*' -fsS "http://127.0.0.1:${failed_backend_port}/readyz" >/dev/null 2>&1; then
  printf 'failed startup did not roll back the newly started backend\n' >&2
  exit 1
fi

mkdir -p "${FOREIGN_HOME}"
printf '%s\n' '{"delivery_worker":{"plugin_id":"example.foreign"}}' \
  >"${FOREIGN_HOME}/product-config.json"
if ABYSS_HOME="${FOREIGN_HOME}" \
  ABYSS_LOCAL_BACKEND_BIN="${FAKE_BIN}/abyss-backend" \
  ABYSS_LOCAL_DASHBOARD_BIN="${FAKE_BIN}/abyss-dashboard" \
  ABYSS_LOCAL_SKIP_PROXY=1 \
    "${ABYSS_BIN}" deploy-local start >/dev/null 2>&1; then
  printf 'foreign product configuration was unexpectedly replaced\n' >&2
  exit 1
fi
grep -Fq 'example.foreign' "${FOREIGN_HOME}/product-config.json"

printf 'abyss deploy-local black-box test passed\n'
