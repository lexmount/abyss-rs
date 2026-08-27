#!/usr/bin/env bash

set -euo pipefail

for command in cargo curl openssl python3; do
  command -v "${command}" >/dev/null || {
    echo "${command} is required for the SDK real-broker black-box test." >&2
    exit 2
  }
done
command -v node >/dev/null || {
  echo "node is required for the TypeScript SDK real-broker black-box test." >&2
  exit 2
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

TMP_ROOT="${ABYSS_SDK_BLACKBOX_TMP_DIR:-$(mktemp -d -t abyss-sdk-blackbox.XXXXXX)}"
BROKER_BINARY="${CARGO_TARGET_DIR:-target}/debug/abyss-broker"
CURRENT_BROKER_PID=""
CURRENT_BROKER_LOG=""

print_broker_log() {
  if [[ -n "${CURRENT_BROKER_LOG}" && -f "${CURRENT_BROKER_LOG}" ]]; then
    echo "---- real broker log: ${CURRENT_BROKER_LOG} ----" >&2
    tail -n 200 "${CURRENT_BROKER_LOG}" >&2 || true
  fi
}

stop_current_broker() {
  if [[ -z "${CURRENT_BROKER_PID}" ]]; then
    return 0
  fi
  if kill -0 "${CURRENT_BROKER_PID}" 2>/dev/null; then
    kill "${CURRENT_BROKER_PID}" 2>/dev/null || true
  fi
  wait "${CURRENT_BROKER_PID}" 2>/dev/null || true
  CURRENT_BROKER_PID=""
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ "${status}" -ne 0 ]]; then
    print_broker_log
  fi
  stop_current_broker
  if [[ -z "${ABYSS_SDK_BLACKBOX_TMP_DIR:-}" ]]; then
    rm -rf "${TMP_ROOT}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

write_ca() {
  local case_dir=$1
  local ca_dir="${case_dir}/ca"
  local openssl_config="${case_dir}/openssl.cnf"
  mkdir -p "${ca_dir}"
  cat >"${openssl_config}" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = Abyss SDK Blackbox Root

[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -days 1 \
    -sha256 \
    -config "${openssl_config}" \
    -keyout "${ca_dir}/abyss-root-ca-key.pem" \
    -out "${ca_dir}/abyss-root-ca.pem" >/dev/null 2>&1
  openssl x509 \
    -in "${ca_dir}/abyss-root-ca.pem" \
    -outform DER \
    -out "${ca_dir}/abyss-root-ca.der"
  chmod 600 "${ca_dir}/abyss-root-ca-key.pem"
}

write_config() {
  local case_dir=$1
  python3 - "${case_dir}" <<'PY'
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
config = {
    "log_location": json.dumps(str(root / "logs")),
    "ca_path": json.dumps(str(root / "ca")),
}
contents = f"""schema_version = 1

[devtools]
log_level = "info"
performance_trace = false
log_location = {config["log_location"]}

[ca]
path = {config["ca_path"]}

[proxy]
mode = "explicit"
listen_addr = "127.0.0.1:0"
"""
(root / "broker-config.toml").write_text(contents, encoding="utf-8")
PY
}

wait_for_broker() {
  local startup_info=$1
  local attempt=1
  while [[ "${attempt}" -le 200 ]]; do
    if [[ -s "${startup_info}" ]]; then
      local api_addr
      api_addr="$(python3 - "${startup_info}" <<'PY'
import json
import pathlib
import sys

try:
    value = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)
print(value["api_addr"])
PY
)" || true
      if [[ -n "${api_addr:-}" ]] && curl -fsS --max-time 2 "http://${api_addr}/healthz" >/dev/null 2>&1; then
        return 0
      fi
    fi
    if ! kill -0 "${CURRENT_BROKER_PID}" 2>/dev/null; then
      echo "real broker exited before SDK test readiness" >&2
      print_broker_log
      exit 1
    fi
    sleep 0.05
    attempt=$((attempt + 1))
  done
  echo "real broker did not publish readiness for SDK test" >&2
  print_broker_log
  exit 1
}

run_sdk_case() {
  local language=$1
  shift
  local case_dir="${TMP_ROOT}/${language}"
  local startup_info="${case_dir}/startup-info.json"
  mkdir -p "${case_dir}/home" "${case_dir}/logs"
  chmod 700 "${case_dir}" "${case_dir}/home" "${case_dir}/logs"
  write_ca "${case_dir}"
  write_config "${case_dir}"

  CURRENT_BROKER_LOG="${case_dir}/broker-stdio.log"
  ABYSS_HOME="${case_dir}/home" \
    "${BROKER_BINARY}" \
    --api 127.0.0.1:0 \
    --config "${case_dir}/broker-config.toml" \
    --auth-token-file "${case_dir}/broker.token" \
    --startup-info-file "${startup_info}" \
    >"${CURRENT_BROKER_LOG}" 2>&1 &
  CURRENT_BROKER_PID=$!
  wait_for_broker "${startup_info}"

  echo "Running ${language} SDK against real abyss-broker pid ${CURRENT_BROKER_PID}"
  ABYSS_BROKER_STARTUP_INFO="${startup_info}" "$@"

  local attempt=1
  while [[ "${attempt}" -le 100 ]]; do
    if ! kill -0 "${CURRENT_BROKER_PID}" 2>/dev/null; then
      wait "${CURRENT_BROKER_PID}"
      CURRENT_BROKER_PID=""
      return 0
    fi
    sleep 0.05
    attempt=$((attempt + 1))
  done
  echo "${language} SDK shutdown did not terminate the real broker" >&2
  exit 1
}

cargo build --locked --package abyss-broker

run_sdk_case \
  rust \
  cargo test --locked --package abyss-sdk --test broker_blackbox \
  real_broker_supports_rest_and_plugin_sdk -- --ignored --exact --nocapture
run_sdk_case typescript npm --prefix sdks/typescript run test:blackbox
run_sdk_case python env PYTHONPATH=sdks/python python3 sdks/python/tests/blackbox.py

echo "SDK real-broker black-box: ok"
