#!/usr/bin/env bash

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "abyss-broker config API black-box test currently runs on macOS." >&2
  exit 2
fi

command -v cargo >/dev/null || {
  echo "cargo is required for the abyss-broker config API black-box test." >&2
  exit 2
}
command -v curl >/dev/null || {
  echo "curl is required for the abyss-broker config API black-box test." >&2
  exit 2
}
command -v openssl >/dev/null || {
  echo "openssl is required to generate temporary CA material." >&2
  exit 2
}
command -v python3 >/dev/null || {
  echo "python3 is required for JSON assertions." >&2
  exit 2
}

RUN_ID="$(date -u +%Y%m%d%H%M%S)-$$"
TMP_DIR="${ABYSS_BROKER_CONFIG_API_BLACKBOX_TMP_DIR:-$(mktemp -d -t abyss-broker-config-api.XXXXXX)}"
CA_DIR="${ABYSS_BROKER_CONFIG_API_BLACKBOX_CA_DIR:-${TMP_DIR}/ca}"
OPENSSL_CONFIG="${TMP_DIR}/openssl.cnf"
CONFIG_FILE="${TMP_DIR}/broker-config.toml"
AUTH_TOKEN_FILE="${ABYSS_BROKER_CONFIG_API_BLACKBOX_AUTH_TOKEN_FILE:-${TMP_DIR}/broker.token}"
FLOW_SOCKET="${ABYSS_BROKER_CONFIG_API_BLACKBOX_FLOW_SOCKET:-${TMP_DIR}/flow.sock}"
BROKER_LOG="${ABYSS_BROKER_CONFIG_API_BLACKBOX_BROKER_LOG:-${TMP_DIR}/abyss-broker.log}"
STARTUP_ATTEMPTS="${ABYSS_BROKER_CONFIG_API_BLACKBOX_STARTUP_ATTEMPTS:-180}"
CURL_TIMEOUT_SECONDS="${ABYSS_BROKER_CONFIG_API_BLACKBOX_CURL_TIMEOUT_SECONDS:-10}"
ABYSS_HOME="${ABYSS_BROKER_CONFIG_API_BLACKBOX_ABYSS_HOME:-${TMP_DIR}/abyss-home}"
RUNTIME_POLICY_FILE="${ABYSS_HOME}/runtime-policy.toml"
LEGACY_RUNTIME_POLICY_FILE="${ABYSS_HOME}/runtime-policy.json"
export ABYSS_HOME

BROKER_PID=""
LOG_PRINTED=0

reserve_port() {
  python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

API_ADDR="${ABYSS_BROKER_CONFIG_API_BLACKBOX_API_ADDR:-127.0.0.1:$(reserve_port)}"
BASE_URL="http://${API_ADDR}"

print_logs() {
  if [[ "${LOG_PRINTED}" -eq 0 ]]; then
    LOG_PRINTED=1
    if [[ -f "${BROKER_LOG}" ]]; then
      echo "---- abyss-broker log: ${BROKER_LOG} ----" >&2
      tail -n 200 "${BROKER_LOG}" >&2 || true
    fi
  fi
}

fail() {
  echo "config API blackbox: $*" >&2
  print_logs
  exit 1
}

cleanup() {
  local status=$?

  if [[ "${status}" -ne 0 ]]; then
    print_logs
  fi

  shutdown_broker

  if [[ -z "${ABYSS_BROKER_CONFIG_API_BLACKBOX_TMP_DIR:-}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
}
trap cleanup EXIT

write_ca_fixture() {
  mkdir -p "${CA_DIR}"
  cat >"${OPENSSL_CONFIG}" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = Abyss Broker Config API Blackbox ${RUN_ID}

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

write_initial_config() {
  mkdir -p "${ABYSS_HOME}"
  cat >"${CONFIG_FILE}" <<EOF
schema_version = 1

[devtools]
log_level = "info"
performance_trace = false
log_location = "${TMP_DIR}/logs"

[ca]
path = "${CA_DIR}"

[proxy]
mode = "macos_network_extension"
socket_path = "${FLOW_SOCKET}"
EOF

  cat >"${RUNTIME_POLICY_FILE}" <<'EOF'
schema_version = 1

[mitm.tls_decryption]
default_action = "passthrough"
missing_sni_action = "passthrough"
rules = []

[hooks.harness_usage]
enabled = true

[hooks.harness_usage.config.content]
token_usage = true
conversation_text = true
tool_calls = true
images = true

[hooks.harness_usage.config.harnesses."claude-code".content]
token_usage = true
conversation_text = false
tool_calls = false
images = false
EOF
  chmod 0600 "${RUNTIME_POLICY_FILE}"

  cat >"${LEGACY_RUNTIME_POLICY_FILE}" <<'EOF'
{
  "hooks": {
    "harness_usage": {
      "config": {
        "content": {
          "mode": "usage_only"
        }
      }
    }
  }
}
EOF
  chmod 0600 "${LEGACY_RUNTIME_POLICY_FILE}"
}

wait_for_broker() {
  local attempt=1
  local status_response

  while [[ "${attempt}" -le "${STARTUP_ATTEMPTS}" ]]; do
    if curl -fsS --max-time "${CURL_TIMEOUT_SECONDS}" "${BASE_URL}/healthz" >/dev/null 2>&1; then
      status_response="$(curl -fsS --max-time "${CURL_TIMEOUT_SECONDS}" "${BASE_URL}/v1/proxy/status")"
      case "${status_response}" in
        *'"lifecycle":"running"'*) return 0 ;;
        *) fail "broker proxy should be running; status: ${status_response}" ;;
      esac
    fi

    if ! kill -0 "${BROKER_PID}" 2>/dev/null; then
      fail "abyss-broker exited before becoming ready"
    fi

    sleep 1
    attempt=$((attempt + 1))
  done

  fail "abyss-broker did not become ready at ${BASE_URL}"
}

start_broker() {
  cargo run --locked --package abyss-broker --quiet -- \
    --api "${API_ADDR}" \
    --config "${CONFIG_FILE}" \
    --auth-token-file "${AUTH_TOKEN_FILE}" >"${BROKER_LOG}" 2>&1 &
  BROKER_PID=$!
  wait_for_broker
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

request_config() {
  local token=$1
  local output_file=$2

  curl -fsS \
    --max-time "${CURL_TIMEOUT_SECONDS}" \
    -H "Authorization: Bearer ${token}" \
    "${BASE_URL}/v1/mitm/config" >"${output_file}"
}

put_config() {
  local token=$1
  local request_file=$2
  local output_file=$3

  curl -fsS \
    --max-time "${CURL_TIMEOUT_SECONDS}" \
    -X PUT \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    --data @"${request_file}" \
    "${BASE_URL}/v1/mitm/config" >"${output_file}"
}

http_status_for_put() {
  local token=$1
  local request_file=$2
  local output_file=$3

  curl -sS \
    --max-time "${CURL_TIMEOUT_SECONDS}" \
    -o "${output_file}" \
    -w '%{http_code}' \
    -X PUT \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    --data @"${request_file}" \
    "${BASE_URL}/v1/mitm/config"
}

request_hooks_config() {
  local token=$1
  local output_file=$2

  curl -fsS \
    --max-time "${CURL_TIMEOUT_SECONDS}" \
    -H "Authorization: Bearer ${token}" \
    "${BASE_URL}/v1/hooks/config" >"${output_file}"
}

request_diagnostics() {
  local token=$1
  local output_file=$2

  curl -fsS \
    --max-time "${CURL_TIMEOUT_SECONDS}" \
    -H "Authorization: Bearer ${token}" \
    "${BASE_URL}/v1/support/diagnostics" >"${output_file}"
}

put_hooks_config() {
  local token=$1
  local request_file=$2
  local output_file=$3

  curl -fsS \
    --max-time "${CURL_TIMEOUT_SECONDS}" \
    -X PUT \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    --data @"${request_file}" \
    "${BASE_URL}/v1/hooks/config" >"${output_file}"
}

http_status_for_hooks_put() {
  local token=$1
  local request_file=$2
  local output_file=$3

  curl -sS \
    --max-time "${CURL_TIMEOUT_SECONDS}" \
    -o "${output_file}" \
    -w '%{http_code}' \
    -X PUT \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    --data @"${request_file}" \
    "${BASE_URL}/v1/hooks/config"
}

assert_config_state() {
  local config_file=$1
  local default_action=$2
  local missing_sni_action=$3
  local rule_id=$4

  python3 - "${config_file}" "${default_action}" "${missing_sni_action}" "${rule_id}" <<'PY'
import json
import sys

path, expected_default, expected_missing_sni, expected_rule_id = sys.argv[1:5]
with open(path, "r", encoding="utf-8") as handle:
    config = json.load(handle)

tls = config["tls_decryption"]
actual_default = tls.get("default_action")
if actual_default != expected_default:
    raise SystemExit(f"default_action mismatch: {actual_default!r} != {expected_default!r}")

actual_missing_sni = tls.get("missing_sni_action")
expected_missing_sni = None if expected_missing_sni == "null" else expected_missing_sni
if actual_missing_sni != expected_missing_sni:
    raise SystemExit(
        f"missing_sni_action mismatch: {actual_missing_sni!r} != {expected_missing_sni!r}"
    )

rules = tls.get("rules", [])
if expected_rule_id == "none":
    if rules:
        raise SystemExit(f"expected no rules, got {rules!r}")
    raise SystemExit(0)

if len(rules) != 1:
    raise SystemExit(f"expected exactly one rule, got {rules!r}")
rule = rules[0]
if rule.get("id") != expected_rule_id:
    raise SystemExit(f"rule id mismatch: {rule.get('id')!r} != {expected_rule_id!r}")
if rule.get("enabled") is not True:
    raise SystemExit(f"expected rule enabled default to serialize as true, got {rule!r}")
if rule.get("action") != "intercept":
    raise SystemExit(f"expected intercept rule, got {rule!r}")
if rule.get("process_names") != ["codex"]:
    raise SystemExit(f"unexpected process_names: {rule!r}")
if rule.get("application_ids") != ["com.openai.codex"]:
    raise SystemExit(f"unexpected application_ids: {rule!r}")
if rule.get("destination_hosts") != ["api.openai.com"]:
    raise SystemExit(f"unexpected destination_hosts: {rule!r}")
PY
}

assert_hooks_config_state() {
  local config_file=$1
  local enabled=$2
  local default_controls=$3
  local codex_controls=$4
  local claude_controls=$5

  python3 - "${config_file}" "${enabled}" "${default_controls}" "${codex_controls}" "${claude_controls}" <<'PY'
import json
import sys

path, expected_enabled, expected_default, expected_codex, expected_claude = sys.argv[1:6]
with open(path, "r", encoding="utf-8") as handle:
    config = json.load(handle)

harness_usage = config["harness_usage"]
actual_enabled = str(harness_usage.get("enabled")).lower()
if actual_enabled != expected_enabled:
    raise SystemExit(f"enabled mismatch: {actual_enabled!r} != {expected_enabled!r}")

def controls(value):
    if value is None:
        return None
    return "".join(
        "1" if value.get(key) is True else "0"
        for key in ("token_usage", "conversation_text", "tool_calls", "images")
    )

content = harness_usage["config"]["content"]
if controls(content) != expected_default:
    raise SystemExit(f"default content controls mismatch: {content!r} != {expected_default!r}")

harnesses = harness_usage["config"].get("harnesses", {})
codex = controls(harnesses.get("codex", {}).get("content"))
expected_codex = None if expected_codex == "null" else expected_codex
if codex != expected_codex:
    raise SystemExit(f"codex controls mismatch: {codex!r} != {expected_codex!r}")

claude = controls(harnesses.get("claude-code", {}).get("content"))
expected_claude = None if expected_claude == "null" else expected_claude
if claude != expected_claude:
    raise SystemExit(f"claude-code controls mismatch: {claude!r} != {expected_claude!r}")
PY
}

assert_custom_harness_state() {
  local config_file=$1
  python3 - "${config_file}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    config = json.load(handle)

custom = config["harness_usage"]["config"]["harnesses"].get("acme-agent")
expected = [{
    "process_names": ["acme-agent"],
    "application_ids": ["com.acme.agent"],
}]
if custom is None or custom.get("enabled") is not True or custom.get("matchers") != expected:
    raise SystemExit(f"custom Harness mismatch: {custom!r}")
PY
}

assert_diagnostics_state() {
  local diagnostics_file=$1
  local api_addr=$2

  python3 - "${diagnostics_file}" "${api_addr}" <<'PY'
import json
import sys

path, expected_api_addr = sys.argv[1:3]
with open(path, "r", encoding="utf-8") as handle:
    diagnostics = json.load(handle)

if diagnostics.get("schema_version") != 1:
    raise SystemExit(f"unexpected schema_version: {diagnostics!r}")

broker = diagnostics.get("broker", {})
if broker.get("package_name") != "abyss-broker":
    raise SystemExit(f"unexpected broker package: {broker!r}")
if broker.get("api_addr") != expected_api_addr:
    raise SystemExit(f"unexpected broker api_addr: {broker!r}")
if not isinstance(broker.get("uptime_ms"), int):
    raise SystemExit(f"broker uptime should be an integer: {broker!r}")

proxy = diagnostics.get("proxy", {})
if proxy.get("lifecycle") != "running":
    raise SystemExit(f"proxy should be running: {proxy!r}")

flow = diagnostics.get("flow", {})
totals = flow.get("totals", {})
for key in ("accepted", "completed", "in_flight", "accept_errors"):
    if not isinstance(totals.get(key), int):
        raise SystemExit(f"flow total {key} should be an integer: {totals!r}")

aggregates = flow.get("aggregates", {})
for key in ("by_decision", "by_host", "by_process", "by_bundle_id", "by_miss_reason"):
    if not isinstance(aggregates.get(key), dict):
        raise SystemExit(f"flow aggregate {key} should be an object: {aggregates!r}")

PY
}

write_ca_fixture
write_initial_config
start_broker

TOKEN="$(tr -d '\r\n' <"${AUTH_TOKEN_FILE}")"
UNAUTH_STATUS="$(
  curl -sS \
    --max-time "${CURL_TIMEOUT_SECONDS}" \
    -o "${TMP_DIR}/unauth-config.json" \
    -w '%{http_code}' \
    "${BASE_URL}/v1/mitm/config"
)"
if [[ "${UNAUTH_STATUS}" != "401" ]]; then
  fail "unauthenticated config read should return 401; got ${UNAUTH_STATUS}"
fi
UNAUTH_DIAGNOSTICS_STATUS="$(
  curl -sS \
    --max-time "${CURL_TIMEOUT_SECONDS}" \
    -o "${TMP_DIR}/unauth-diagnostics.json" \
    -w '%{http_code}' \
    "${BASE_URL}/v1/support/diagnostics"
)"
if [[ "${UNAUTH_DIAGNOSTICS_STATUS}" != "401" ]]; then
  fail "unauthenticated diagnostics read should return 401; got ${UNAUTH_DIAGNOSTICS_STATUS}"
fi

INITIAL_RESPONSE="${TMP_DIR}/initial-config.json"
request_config "${TOKEN}" "${INITIAL_RESPONSE}"
assert_config_state "${INITIAL_RESPONSE}" "passthrough" "passthrough" "none"

INITIAL_HOOKS_RESPONSE="${TMP_DIR}/initial-hooks-config.json"
request_hooks_config "${TOKEN}" "${INITIAL_HOOKS_RESPONSE}"
assert_hooks_config_state "${INITIAL_HOOKS_RESPONSE}" "true" "1111" "null" "1000"

INITIAL_DIAGNOSTICS_RESPONSE="${TMP_DIR}/initial-diagnostics.json"
request_diagnostics "${TOKEN}" "${INITIAL_DIAGNOSTICS_RESPONSE}"
assert_diagnostics_state "${INITIAL_DIAGNOSTICS_RESPONSE}" "${API_ADDR}"

UPDATE_REQUEST="${TMP_DIR}/update-config.json"
cat >"${UPDATE_REQUEST}" <<'EOF'
{
  "tls_decryption": {
    "default_action": "passthrough",
    "missing_sni_action": "passthrough",
    "rules": [
      {
        "id": "decrypt-openai",
        "action": "intercept",
        "process_names": ["codex"],
        "application_ids": ["com.openai.codex"],
        "destination_hosts": ["api.openai.com"]
      }
    ]
  }
}
EOF
UPDATED_RESPONSE="${TMP_DIR}/updated-config.json"
put_config "${TOKEN}" "${UPDATE_REQUEST}" "${UPDATED_RESPONSE}"
assert_config_state "${UPDATED_RESPONSE}" "passthrough" "passthrough" "decrypt-openai"

READ_BACK_RESPONSE="${TMP_DIR}/read-back-config.json"
request_config "${TOKEN}" "${READ_BACK_RESPONSE}"
assert_config_state "${READ_BACK_RESPONSE}" "passthrough" "passthrough" "decrypt-openai"

INVALID_REQUEST="${TMP_DIR}/invalid-config.json"
cat >"${INVALID_REQUEST}" <<'EOF'
{
  "tls_decryption": {
    "default_action": "intercept",
    "rules": [
      {
        "id": "invalid-empty-hosts",
        "action": "passthrough",
        "destination_hosts": []
      }
    ]
  }
}
EOF
INVALID_STATUS="$(http_status_for_put "${TOKEN}" "${INVALID_REQUEST}" "${TMP_DIR}/invalid-response.json")"
if [[ "${INVALID_STATUS}" != "400" ]]; then
  fail "invalid config update should return 400; got ${INVALID_STATUS}"
fi

AFTER_INVALID_RESPONSE="${TMP_DIR}/after-invalid-config.json"
request_config "${TOKEN}" "${AFTER_INVALID_RESPONSE}"
assert_config_state "${AFTER_INVALID_RESPONSE}" "passthrough" "passthrough" "decrypt-openai"

HOOKS_UPDATE_REQUEST="${TMP_DIR}/hooks-update-config.json"
cat >"${HOOKS_UPDATE_REQUEST}" <<'EOF'
{
  "harness_usage": {
    "enabled": true,
    "config": {
      "content": {
        "token_usage": true,
        "conversation_text": false,
        "tool_calls": true,
        "images": false
      },
      "harnesses": {
        "codex": {
          "content": {
            "token_usage": false,
            "conversation_text": true,
            "tool_calls": false,
            "images": true
          }
        },
        "claude-code": {
          "content": {
            "token_usage": true,
            "conversation_text": false,
            "tool_calls": false,
            "images": false
          }
        },
        "acme-agent": {
          "enabled": true,
          "matchers": [{
            "process_names": ["acme-agent"],
            "application_ids": ["com.acme.agent"]
          }]
        }
      }
    }
  }
}
EOF
UPDATED_HOOKS_RESPONSE="${TMP_DIR}/updated-hooks-config.json"
put_hooks_config "${TOKEN}" "${HOOKS_UPDATE_REQUEST}" "${UPDATED_HOOKS_RESPONSE}"
assert_hooks_config_state "${UPDATED_HOOKS_RESPONSE}" "true" "1010" "0101" "1000"
assert_custom_harness_state "${UPDATED_HOOKS_RESPONSE}"

HOOKS_READ_BACK_RESPONSE="${TMP_DIR}/hooks-read-back-config.json"
request_hooks_config "${TOKEN}" "${HOOKS_READ_BACK_RESPONSE}"
assert_hooks_config_state "${HOOKS_READ_BACK_RESPONSE}" "true" "1010" "0101" "1000"
assert_custom_harness_state "${HOOKS_READ_BACK_RESPONSE}"

UNKNOWN_HOOK_REQUEST="${TMP_DIR}/unknown-hook-config.json"
cat >"${UNKNOWN_HOOK_REQUEST}" <<'EOF'
{
  "future_hook": {
    "enabled": true,
    "config": {}
  }
}
EOF
UNKNOWN_HOOK_STATUS="$(http_status_for_hooks_put "${TOKEN}" "${UNKNOWN_HOOK_REQUEST}" "${TMP_DIR}/unknown-hook-response.json")"
case "${UNKNOWN_HOOK_STATUS}" in
  4*) ;;
  *) fail "unknown hook config update should return a 4xx status; got ${UNKNOWN_HOOK_STATUS}" ;;
esac

AFTER_UNKNOWN_HOOK_RESPONSE="${TMP_DIR}/after-unknown-hook-config.json"
request_hooks_config "${TOKEN}" "${AFTER_UNKNOWN_HOOK_RESPONSE}"
assert_hooks_config_state "${AFTER_UNKNOWN_HOOK_RESPONSE}" "true" "1010" "0101" "1000"

RETIRED_MODE_REQUEST="${TMP_DIR}/retired-mode-config.json"
cat >"${RETIRED_MODE_REQUEST}" <<'EOF'
{
  "harness_usage": {
    "config": {
      "content": {
        "mode": "usage_only"
      }
    }
  }
}
EOF
cp "${RUNTIME_POLICY_FILE}" "${TMP_DIR}/policy-before-retired-mode.json"
RETIRED_MODE_STATUS="$(http_status_for_hooks_put "${TOKEN}" "${RETIRED_MODE_REQUEST}" "${TMP_DIR}/retired-mode-response.json")"
case "${RETIRED_MODE_STATUS}" in
  4*) ;;
  *) fail "retired aggregate content mode should return a 4xx status; got ${RETIRED_MODE_STATUS}" ;;
esac
cmp "${TMP_DIR}/policy-before-retired-mode.json" "${RUNTIME_POLICY_FILE}" \
  || fail "rejected aggregate content mode must not modify durable policy"

AFTER_RETIRED_MODE_RESPONSE="${TMP_DIR}/after-retired-mode-config.json"
request_hooks_config "${TOKEN}" "${AFTER_RETIRED_MODE_RESPONSE}"
assert_hooks_config_state "${AFTER_RETIRED_MODE_RESPONSE}" "true" "1010" "0101" "1000"

shutdown_broker

start_broker
TOKEN="$(tr -d '\r\n' <"${AUTH_TOKEN_FILE}")"
RESTARTED_MITM_RESPONSE="${TMP_DIR}/restarted-mitm-config.json"
request_config "${TOKEN}" "${RESTARTED_MITM_RESPONSE}"
assert_config_state "${RESTARTED_MITM_RESPONSE}" "passthrough" "passthrough" "decrypt-openai"
RESTARTED_HOOKS_RESPONSE="${TMP_DIR}/restarted-hooks-config.json"
request_hooks_config "${TOKEN}" "${RESTARTED_HOOKS_RESPONSE}"
assert_hooks_config_state "${RESTARTED_HOOKS_RESPONSE}" "true" "1010" "0101" "1000"
assert_custom_harness_state "${RESTARTED_HOOKS_RESPONSE}"
shutdown_broker

echo "config API blackbox: ok (${BASE_URL}, run ${RUN_ID})"
