#!/usr/bin/env bash

set -euo pipefail

command -v cargo >/dev/null || {
  echo "cargo is required for the abyss-broker black-box test." >&2
  exit 2
}
command -v curl >/dev/null || {
  echo "curl is required for the abyss-broker black-box test." >&2
  exit 2
}
command -v python3 >/dev/null || {
  echo "python3 is required to run the local black-box upstream server." >&2
  exit 2
}
command -v openssl >/dev/null || {
  echo "openssl is required to generate temporary CA material." >&2
  exit 2
}

RUN_ID="$(date -u +%Y%m%d%H%M%S)-$$"
TMP_DIR="${ABYSS_BROKER_BLACKBOX_TMP_DIR:-$(mktemp -d -t abyss-broker-blackbox.XXXXXX)}"
UPSTREAM_DIR="${TMP_DIR}/upstream"
BROKER_LOG="${ABYSS_BROKER_BLACKBOX_BROKER_LOG:-${TMP_DIR}/abyss-broker.log}"
UPSTREAM_LOG="${ABYSS_BROKER_BLACKBOX_UPSTREAM_LOG:-${TMP_DIR}/upstream.log}"
AUTH_TOKEN_FILE="${ABYSS_BROKER_BLACKBOX_AUTH_TOKEN_FILE:-${TMP_DIR}/broker.token}"
BROKER_CONFIG="${TMP_DIR}/broker-config.toml"
CA_DIR="${ABYSS_BROKER_BLACKBOX_CA_DIR:-${TMP_DIR}/ca}"
OPENSSL_CONFIG="${TMP_DIR}/openssl.cnf"
TARGET_DOMAIN="${ABYSS_BROKER_BLACKBOX_DOMAIN:-localhost}"
UPSTREAM_BIND="${ABYSS_BROKER_BLACKBOX_UPSTREAM_BIND:-localhost}"
STARTUP_ATTEMPTS="${ABYSS_BROKER_BLACKBOX_STARTUP_ATTEMPTS:-180}"
CURL_TIMEOUT_SECONDS="${ABYSS_BROKER_BLACKBOX_CURL_TIMEOUT_SECONDS:-10}"
EXPECTED_BODY="abyss-broker-connect-blackbox:${RUN_ID}"

BROKER_PID=""
UPSTREAM_PID=""
LOG_PRINTED=0

reserve_port() {
  python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

API_ADDR="${ABYSS_BROKER_BLACKBOX_API_ADDR:-127.0.0.1:$(reserve_port)}"
PROXY_ADDR="${ABYSS_BROKER_BLACKBOX_PROXY_ADDR:-127.0.0.1:$(reserve_port)}"
UPSTREAM_PORT="${ABYSS_BROKER_BLACKBOX_UPSTREAM_PORT:-$(reserve_port)}"
BASE_URL="http://${API_ADDR}"
TARGET_URL="http://${TARGET_DOMAIN}:${UPSTREAM_PORT}/probe.txt"

print_logs() {
  if [[ "${LOG_PRINTED}" -eq 0 ]]; then
    LOG_PRINTED=1
    if [[ -f "${BROKER_LOG}" ]]; then
      echo "---- abyss-broker log: ${BROKER_LOG} ----" >&2
      tail -n 200 "${BROKER_LOG}" >&2 || true
    fi
    if [[ -f "${UPSTREAM_LOG}" ]]; then
      echo "---- upstream log: ${UPSTREAM_LOG} ----" >&2
      tail -n 200 "${UPSTREAM_LOG}" >&2 || true
    fi
  fi
}

fail() {
  echo "blackbox: $*" >&2
  print_logs
  exit 1
}

cleanup() {
  local status=$?

  if [[ "${status}" -ne 0 ]]; then
    print_logs
  fi

  shutdown_broker

  if [[ -n "${UPSTREAM_PID}" ]]; then
    kill "${UPSTREAM_PID}" 2>/dev/null || true
    wait "${UPSTREAM_PID}" 2>/dev/null || true
  fi

  if [[ -z "${ABYSS_BROKER_BLACKBOX_TMP_DIR:-}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
}
trap cleanup EXIT

require_contains() {
  local haystack=$1
  local needle=$2
  local message=$3

  case "${haystack}" in
    *"${needle}"*) ;;
    *) fail "${message}; expected ${needle}; response: ${haystack}" ;;
  esac
}

write_ca_fixture() {
  mkdir -p "${CA_DIR}"
  cat >"${OPENSSL_CONFIG}" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = Abyss Broker Explicit Proxy Blackbox ${RUN_ID}

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
    -config "${OPENSSL_CONFIG}" \
    -keyout "${CA_DIR}/abyss-root-ca-key.pem" \
    -out "${CA_DIR}/abyss-root-ca.pem" >/dev/null 2>&1
  openssl x509 \
    -in "${CA_DIR}/abyss-root-ca.pem" \
    -outform DER \
    -out "${CA_DIR}/abyss-root-ca.der"
}

wait_for_upstream() {
  local attempt=1

  while [[ "${attempt}" -le "${STARTUP_ATTEMPTS}" ]]; do
    if curl -fsS --max-time "${CURL_TIMEOUT_SECONDS}" --noproxy "*" "${TARGET_URL}" >/dev/null 2>&1; then
      return 0
    fi

    if ! kill -0 "${UPSTREAM_PID}" 2>/dev/null; then
      fail "upstream HTTP server exited before becoming ready"
    fi

    sleep 1
    attempt=$((attempt + 1))
  done

  fail "upstream HTTP server did not become ready at ${TARGET_URL}"
}

wait_for_broker() {
  local attempt=1
  local status_response

  while [[ "${attempt}" -le "${STARTUP_ATTEMPTS}" ]]; do
    if curl -fsS --max-time "${CURL_TIMEOUT_SECONDS}" "${BASE_URL}/healthz" >/dev/null 2>&1; then
      status_response="$(curl -fsS --max-time "${CURL_TIMEOUT_SECONDS}" "${BASE_URL}/v1/proxy/status")"
      require_contains "${status_response}" '"lifecycle":"running"' "broker proxy should be running"
      require_contains "${status_response}" '"mode":"explicit"' "broker proxy should report explicit mode"
      require_contains "${status_response}" '"source":"explicit_http"' "broker proxy should report explicit ingress"
      require_contains "${status_response}" "\"listen_addr\":\"${PROXY_ADDR}\"" "broker proxy should listen on the requested address"
      return 0
    fi

    if ! kill -0 "${BROKER_PID}" 2>/dev/null; then
      fail "abyss-broker exited before becoming ready"
    fi

    sleep 1
    attempt=$((attempt + 1))
  done

  fail "abyss-broker did not become ready at ${BASE_URL}"
}

wait_for_broker_log() {
  local needle=$1
  local attempt=1

  while [[ "${attempt}" -le 20 ]]; do
    if [[ -f "${BROKER_LOG}" ]] && grep -Fq "${needle}" "${BROKER_LOG}"; then
      return 0
    fi

    sleep 1
    attempt=$((attempt + 1))
  done

  fail "broker log did not contain ${needle}"
}

shutdown_broker() {
  if [[ -z "${BROKER_PID}" ]]; then
    return 0
  fi

  if kill -0 "${BROKER_PID}" 2>/dev/null && [[ -f "${AUTH_TOKEN_FILE}" ]]; then
    local token
    token="$(tr -d '\r\n' <"${AUTH_TOKEN_FILE}")"
    curl -fsS \
      --max-time "${CURL_TIMEOUT_SECONDS}" \
      -X POST \
      -H "Authorization: Bearer ${token}" \
      "${BASE_URL}/v1/broker/shutdown" >/dev/null 2>&1 || true
  fi

  local attempt=1
  while [[ "${attempt}" -le 20 ]]; do
    if ! kill -0 "${BROKER_PID}" 2>/dev/null; then
      wait "${BROKER_PID}" 2>/dev/null || true
      BROKER_PID=""
      return 0
    fi

    sleep 1
    attempt=$((attempt + 1))
  done

  kill "${BROKER_PID}" 2>/dev/null || true
  wait "${BROKER_PID}" 2>/dev/null || true
  BROKER_PID=""
}

raw_proxy_status() {
  local request_kind=$1
  python3 - "${PROXY_ADDR}" "${request_kind}" <<'PY'
import socket
import sys
from urllib.parse import urlsplit

proxy_authority = sys.argv[1]
request_kind = sys.argv[2]
parsed = urlsplit(f"//{proxy_authority}")
host = parsed.hostname
port = parsed.port
if host is None or port is None:
    raise SystemExit(f"invalid proxy authority: {proxy_authority}")

if request_kind == "self":
    request = (
        f"CONNECT {proxy_authority} HTTP/1.1\r\n"
        f"Host: {proxy_authority}\r\n\r\n"
    )
elif request_kind == "origin-form":
    request = "GET /not-valid-proxy-form HTTP/1.1\r\nHost: example.test\r\n\r\n"
else:
    raise SystemExit(f"unknown request kind: {request_kind}")

with socket.create_connection((host, port), timeout=5) as client:
    client.sendall(request.encode("ascii"))
    response = client.recv(4096)

status_line = response.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
parts = status_line.split(" ", 2)
if len(parts) < 2:
    raise SystemExit(f"invalid proxy response: {status_line}")
print(parts[1])
PY
}

mkdir -p "${UPSTREAM_DIR}"
printf '%s' "${EXPECTED_BODY}" >"${UPSTREAM_DIR}/probe.txt"
write_ca_fixture

python3 - "${BROKER_CONFIG}" "${CA_DIR}" "${PROXY_ADDR}" "${TMP_DIR}/logs" <<'PY'
import json
import sys

config_path, ca_path, listen_addr, log_location = sys.argv[1:]
with open(config_path, "w", encoding="utf-8") as config_file:
    config_file.write(
        "schema_version = 1\n\n"
        "[devtools]\n"
        "log_level = \"info\"\n"
        "performance_trace = false\n"
        f"log_location = {json.dumps(log_location)}\n\n"
        "[ca]\n"
        f"path = {json.dumps(ca_path)}\n\n"
        "[proxy]\n"
        "mode = \"explicit\"\n"
        f"listen_addr = {json.dumps(listen_addr)}\n"
    )
PY

python3 -m http.server "${UPSTREAM_PORT}" \
  --bind "${UPSTREAM_BIND}" \
  --directory "${UPSTREAM_DIR}" >"${UPSTREAM_LOG}" 2>&1 &
UPSTREAM_PID=$!
wait_for_upstream

ABYSS_HOME="${TMP_DIR}/home" cargo run --locked --package abyss-broker --quiet -- \
  --api "${API_ADDR}" \
  --config "${BROKER_CONFIG}" \
  --auth-token-file "${AUTH_TOKEN_FILE}" >"${BROKER_LOG}" 2>&1 &
BROKER_PID=$!
wait_for_broker

PROXY_RESPONSE="$(curl -fsS \
  --max-time "${CURL_TIMEOUT_SECONDS}" \
  --noproxy "" \
  --proxy "http://${PROXY_ADDR}" \
  --proxytunnel \
  "${TARGET_URL}")"
if [[ "${PROXY_RESPONSE}" != "${EXPECTED_BODY}" ]]; then
  fail "proxied curl response mismatch; expected ${EXPECTED_BODY}; response: ${PROXY_RESPONSE}"
fi

ABSOLUTE_RESPONSE="$(curl -fsS \
  --max-time "${CURL_TIMEOUT_SECONDS}" \
  --noproxy "" \
  --proxy "http://${PROXY_ADDR}" \
  "${TARGET_URL}")"
if [[ "${ABSOLUTE_RESPONSE}" != "${EXPECTED_BODY}" ]]; then
  fail "absolute-form proxy response mismatch; expected ${EXPECTED_BODY}; response: ${ABSOLUTE_RESPONSE}"
fi

SELF_TARGET_STATUS="$(raw_proxy_status self)"
[[ "${SELF_TARGET_STATUS}" == "403" ]] \
  || fail "self-targeting CONNECT should return 403; response status: ${SELF_TARGET_STATUS}"

ORIGIN_FORM_STATUS="$(raw_proxy_status origin-form)"
[[ "${ORIGIN_FORM_STATUS}" == "400" ]] \
  || fail "origin-form explicit request should return 400; response status: ${ORIGIN_FORM_STATUS}"

wait_for_broker_log "peer_addr"

echo "blackbox: ok (${TARGET_URL} via ${PROXY_ADDR}, run ${RUN_ID})"
