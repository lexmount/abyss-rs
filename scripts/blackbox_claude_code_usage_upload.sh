#!/usr/bin/env bash

set -euo pipefail

# Keep CI credentials out of every setup subprocess. Values are exported only
# inside `run_claude_code` immediately before replacing the subshell with Claude.
CLAUDE_CODE_API_KEY_FOR_RUN="${CLAUDE_CODE_API_KEY-${ANTHROPIC_API_KEY-}}"
CLAUDE_CODE_BASE_URL_FOR_RUN="${CLAUDE_CODE_BASE_URL-${ANTHROPIC_BASE_URL-${CLAUDE_CODE_API_BASE_URL-https://api.anthropic.com}}}"
CLAUDE_CODE_MODEL_FOR_RUN="${CLAUDE_CODE_MODEL-${ANTHROPIC_MODEL-}}"
unset CLAUDE_CODE_API_KEY
unset CLAUDE_CODE_BASE_URL
unset CLAUDE_CODE_MODEL
unset ANTHROPIC_API_KEY
unset ANTHROPIC_BASE_URL
unset ANTHROPIC_MODEL
unset CLAUDE_CODE_API_BASE_URL
unset ANTHROPIC_AUTH_TOKEN
unset CLAUDE_CODE_OAUTH_TOKEN
unset ANTHROPIC_CUSTOM_HEADERS

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "the Claude Code usage upload black-box test requires Linux." >&2
  exit 2
fi

for command in cargo claude curl docker git jq openssl python3 sha256sum sudo update-ca-certificates; do
  command -v "${command}" >/dev/null || {
    echo "${command} is required for the Claude Code usage upload black-box test." >&2
    exit 2
  }
done

docker info >/dev/null 2>&1 || {
  echo "the Docker broker must be running for the Claude Code usage upload black-box test." >&2
  exit 2
}
sudo -n true >/dev/null 2>&1 || {
  echo "passwordless sudo is required to install the temporary Abyss CA." >&2
  exit 2
}

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

# shellcheck source=scripts/lib/blackbox_usage.sh
source "${REPO_ROOT}/scripts/lib/blackbox_usage.sh"

RUN_ID="$(date -u +%Y%m%d%H%M%S)-$$"
TMP_DIR="${ABYSS_CLAUDE_CODE_E2E_TMP_DIR:-$(mktemp -d -t abyss-claude-code-e2e.XXXXXX)}"
RUNTIME_TMP_DIR="${TMP_DIR}/runtime"
BROKER_HOME="${TMP_DIR}/broker-home"
CA_DIR="${TMP_DIR}/ca"
LOG_DIR="${TMP_DIR}/logs"
WORK_DIR="${TMP_DIR}/workspace"
HOME_DIR="${TMP_DIR}/home"
BROKER_CONFIG="${TMP_DIR}/broker-config.toml"
RUNTIME_POLICY="${BROKER_HOME}/runtime-policy.toml"
BROKER_AUTH_TOKEN_FILE="${TMP_DIR}/broker.token"
BROKER_STARTUP_INFO="${TMP_DIR}/broker-startup.json"
BROKER_LOG="${LOG_DIR}/broker-stdio.log"
BROKER_FILE_LOG="${LOG_DIR}/broker/abyss-broker.log"
DELIVERY_CONFIG="${TMP_DIR}/product-config.json"
DELIVERY_AUTH_FILE="${TMP_DIR}/delivery-authorization"
DELIVERY_LOG="${LOG_DIR}/delivery-plugin.log"
CLAUDE_LOG="${LOG_DIR}/claude-code.json"
CLAUDE_SECOND_LOG="${LOG_DIR}/claude-code-second.json"
CLAUDE_STDERR_LOG="${LOG_DIR}/claude-code.stderr.log"
CLAUDE_SECOND_STDERR_LOG="${LOG_DIR}/claude-code-second.stderr.log"
CA_UPDATE_LOG="${LOG_DIR}/update-ca-certificates.log"
EVENTS_RESPONSE="${TMP_DIR}/events.json"
SPOOL_PATH="${BROKER_HOME}/delivery/failed-events.jsonl"

BACKEND_IMAGE="${ABYSS_CLAUDE_CODE_E2E_BACKEND_IMAGE:-$(tr -d '\r\n' < "${REPO_ROOT}/scripts/ci/abyss-backend-image.txt")}"
BACKEND_PLATFORM="${ABYSS_CLAUDE_CODE_E2E_BACKEND_PLATFORM:-linux/amd64}"
POSTGRES_IMAGE="${ABYSS_CLAUDE_CODE_E2E_POSTGRES_IMAGE:-postgres:16}"
BROKER_BINARY="${CARGO_TARGET_DIR:-target}/debug/abyss-broker"
DELIVERY_BINARY="${CARGO_TARGET_DIR:-target}/debug/abyss-delivery-plugin"
POSTGRES_CONTAINER="abyss-claude-code-e2e-postgres-${RUN_ID}"
BACKEND_CONTAINER="abyss-claude-code-e2e-backend-${RUN_ID}"
SYSTEM_CA_FILE="/usr/local/share/ca-certificates/abyss-claude-code-e2e-${RUN_ID}.crt"
NATIVE_TOKEN="$(openssl rand -hex 32)"
NATIVE_TOKEN_HASH="$(printf '%s' "${NATIVE_TOKEN}" | sha256sum | awk '{print $1}')"
POSTGRES_PASSWORD="$(openssl rand -hex 16)"
PROMPT_MARKER="ABYSS_CLAUDE_CODE_PROMPT_${RUN_ID}"
SECOND_PROMPT_MARKER="ABYSS_CLAUDE_CODE_PROMPT_SECOND_${RUN_ID}"
STARTUP_ATTEMPTS="${ABYSS_CLAUDE_CODE_E2E_STARTUP_ATTEMPTS:-180}"
EVENT_ATTEMPTS="${ABYSS_CLAUDE_CODE_E2E_EVENT_ATTEMPTS:-60}"
CURL_TIMEOUT_SECONDS="${ABYSS_CLAUDE_CODE_E2E_CURL_TIMEOUT_SECONDS:-10}"
CLAUDE_CODE_BASE_HOST=""
EXPECTED_LLM_PROVIDER="anthropic"

BROKER_PID=""
DELIVERY_PID=""
POSTGRES_PORT=""
BACKEND_PORT="${ABYSS_CLAUDE_CODE_E2E_BACKEND_PORT:-39080}"
BACKEND_BASE_URL="http://127.0.0.1:${BACKEND_PORT}"
BROKER_BASE_URL=""
PROXY_URL=""
CA_INSTALLED=0
LOGS_PRINTED=0

mkdir -p \
  "${RUNTIME_TMP_DIR}" \
  "${BROKER_HOME}" \
  "${CA_DIR}" \
  "${LOG_DIR}" \
  "${WORK_DIR}" \
  "${HOME_DIR}"
chmod 700 \
  "${TMP_DIR}" \
  "${RUNTIME_TMP_DIR}" \
  "${BROKER_HOME}" \
  "${CA_DIR}" \
  "${LOG_DIR}" \
  "${HOME_DIR}"
git init --quiet "${WORK_DIR}"

print_logs() {
  if [[ "${LOGS_PRINTED}" -ne 0 ]]; then
    return 0
  fi
  LOGS_PRINTED=1

  if [[ -f "${BROKER_LOG}" ]]; then
    echo "---- abyss-broker stdout/stderr: ${BROKER_LOG} ----" >&2
    tail -n 200 "${BROKER_LOG}" >&2 || true
  elif [[ -f "${BROKER_FILE_LOG}" ]]; then
    echo "---- abyss-broker log: ${BROKER_FILE_LOG} ----" >&2
    tail -n 200 "${BROKER_FILE_LOG}" >&2 || true
  fi
  if [[ -f "${DELIVERY_LOG}" ]]; then
    echo "---- abyss-delivery-plugin stdout/stderr: ${DELIVERY_LOG} ----" >&2
    tail -n 200 "${DELIVERY_LOG}" >&2 || true
  fi
  if docker inspect "${BACKEND_CONTAINER}" >/dev/null 2>&1; then
    echo "---- abyss-backend container log: ${BACKEND_CONTAINER} ----" >&2
    docker logs --tail 200 "${BACKEND_CONTAINER}" >&2 || true
  fi
  if docker inspect "${POSTGRES_CONTAINER}" >/dev/null 2>&1; then
    echo "---- PostgreSQL container log: ${POSTGRES_CONTAINER} ----" >&2
    docker logs --tail 100 "${POSTGRES_CONTAINER}" >&2 || true
  fi
  if [[ -f "${CLAUDE_LOG}" ]]; then
    echo "Claude Code output retained at ${CLAUDE_LOG}; contents omitted to protect request context." >&2
  fi
  if [[ -f "${CLAUDE_SECOND_LOG}" ]]; then
    echo "Second Claude Code output retained at ${CLAUDE_SECOND_LOG}; contents omitted to protect request context." >&2
  fi
}

print_claude_error_summary() {
  local output_log="$1"
  local stderr_log="$2"
  local summary

  echo "---- Claude Code error summary ----" >&2
  if [[ -s "${output_log}" ]] && jq -e . "${output_log}" >/dev/null 2>&1; then
    summary="$(jq -r '
      [
        ("subtype=" + ((.subtype // "unknown") | tostring)),
        ("is_error=" + ((.is_error // false) | tostring)),
        ("api_error_status=" + ((.api_error_status // "unknown") | tostring)),
        ("terminal_reason=" + ((.terminal_reason // "unknown") | tostring)),
        ("message=" + ((.result // .error // .message // "unknown") | tostring
          | gsub("[[:space:]]+"; " ")
          | gsub("Bearer[[:space:]]+[A-Za-z0-9._~+/-]+"; "<redacted>")
          | gsub("sk-[A-Za-z0-9_-]+"; "<redacted>")
          | .[0:1200]))
      ] | join("\n")
    ' "${output_log}" 2>/dev/null || true)"
    [[ -n "${summary}" ]] && printf '%s\n' "${summary}" >&2
  else
    echo "Claude Code did not produce structured JSON output." >&2
  fi

  if [[ -s "${stderr_log}" ]]; then
    local stderr_summary
    stderr_summary="$(
      tr '\r\n' '  ' <"${stderr_log}" \
        | sed -E 's/(sk-[A-Za-z0-9_-]+|Bearer[[:space:]]+[A-Za-z0-9._~+\/-]+)/<redacted>/g' \
        | cut -c 1-1200
    )"
    [[ -n "${stderr_summary}" ]] && printf 'stderr=%s\n' "${stderr_summary}" >&2
  fi
}

fail() {
  echo "blackbox: $*" >&2
  exit 1
}

shutdown_broker() {
  if [[ -z "${BROKER_PID}" ]]; then
    return 0
  fi

  if kill -0 "${BROKER_PID}" 2>/dev/null \
    && [[ -f "${BROKER_AUTH_TOKEN_FILE}" ]] \
    && [[ -n "${BROKER_BASE_URL}" ]]; then
    local broker_token
    broker_token="$(tr -d '\r\n' <"${BROKER_AUTH_TOKEN_FILE}")"
    curl -fsS \
      --max-time "${CURL_TIMEOUT_SECONDS}" \
      -X POST \
      -H "Authorization: Bearer ${broker_token}" \
      "${BROKER_BASE_URL}/v1/broker/shutdown" >/dev/null 2>&1 || true
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

shutdown_delivery_plugin() {
  if [[ -z "${DELIVERY_PID}" ]]; then
    return 0
  fi
  kill "${DELIVERY_PID}" 2>/dev/null || true
  wait "${DELIVERY_PID}" 2>/dev/null || true
  DELIVERY_PID=""
}

cleanup() {
  local status=$?
  trap - EXIT INT TERM

  if [[ "${status}" -ne 0 ]]; then
    print_logs
  fi

  shutdown_delivery_plugin
  shutdown_broker

  docker rm -f "${BACKEND_CONTAINER}" >/dev/null 2>&1 || true
  docker rm -f "${POSTGRES_CONTAINER}" >/dev/null 2>&1 || true

  if [[ "${CA_INSTALLED}" -eq 1 ]]; then
    sudo rm -f "${SYSTEM_CA_FILE}" >/dev/null 2>&1 || true
    sudo update-ca-certificates >"${CA_UPDATE_LOG}" 2>&1 || true
  fi

  CLAUDE_CODE_API_KEY_FOR_RUN=""
  CLAUDE_CODE_BASE_URL_FOR_RUN=""
  CLAUDE_CODE_MODEL_FOR_RUN=""
  NATIVE_TOKEN=""
  POSTGRES_PASSWORD=""
  if [[ -z "${ABYSS_CLAUDE_CODE_E2E_TMP_DIR:-}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

validate_claude_code_config() {
  [[ -n "${CLAUDE_CODE_API_KEY_FOR_RUN}" ]] \
    || fail "CLAUDE_CODE_API_KEY or ANTHROPIC_API_KEY is required"
  [[ -n "${CLAUDE_CODE_BASE_URL_FOR_RUN}" ]] \
    || fail "CLAUDE_CODE_BASE_URL, ANTHROPIC_BASE_URL, or CLAUDE_CODE_API_BASE_URL is required"

  CLAUDE_CODE_BASE_HOST="$(
    python3 - "${CLAUDE_CODE_BASE_URL_FOR_RUN}" <<'PY'
import sys
from urllib.parse import urlparse

url = sys.argv[1]
parsed = urlparse(url)
if parsed.scheme != "https":
    raise SystemExit("Claude Code base URL must use https")
if not parsed.hostname:
    raise SystemExit("Claude Code base URL must include a host")
print(parsed.hostname.rstrip(".").lower())
PY
  )" || fail "invalid Claude Code base URL"

  # Provider resolution preserves this Anthropic-compatible gateway's host
  # instead of labeling it as the first-party Anthropic service.
  if [[ "${CLAUDE_CODE_BASE_HOST}" == "www.dmxapi.cn" ]]; then
    EXPECTED_LLM_PROVIDER="${CLAUDE_CODE_BASE_HOST}"
  fi
}

write_ca() {
  local root_config="${TMP_DIR}/root-openssl.cnf"

  cat >"${root_config}" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = Abyss Claude Code E2E Root ${RUN_ID}

[v3_ca]
basicConstraints = critical, CA:true
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -days 1 \
    -sha256 \
    -config "${root_config}" \
    -keyout "${CA_DIR}/abyss-root-ca-key.pem" \
    -out "${CA_DIR}/abyss-root-ca.pem" >/dev/null 2>&1
  openssl x509 \
    -in "${CA_DIR}/abyss-root-ca.pem" \
    -outform DER \
    -out "${CA_DIR}/abyss-root-ca.der"

  chmod 600 "${CA_DIR}/abyss-root-ca-key.pem"
}

install_ca() {
  sudo install -m 0644 "${CA_DIR}/abyss-root-ca.pem" "${SYSTEM_CA_FILE}"
  CA_INSTALLED=1
  sudo update-ca-certificates >"${CA_UPDATE_LOG}" 2>&1
}

pull_backend_image() {
  docker pull --platform "${BACKEND_PLATFORM}" "${BACKEND_IMAGE}"
}

start_postgres() {
  local postgres_publish="127.0.0.1::5432"
  if [[ -n "${ABYSS_CLAUDE_CODE_E2E_POSTGRES_PORT:-}" ]]; then
    postgres_publish="127.0.0.1:${ABYSS_CLAUDE_CODE_E2E_POSTGRES_PORT}:5432"
  fi

  docker run \
    --name "${POSTGRES_CONTAINER}" \
    -p "${postgres_publish}" \
    -e POSTGRES_USER=abyss \
    -e "POSTGRES_PASSWORD=${POSTGRES_PASSWORD}" \
    -e POSTGRES_DB=abyss \
    -d "${POSTGRES_IMAGE}" >/dev/null

  POSTGRES_PORT="$(
    docker port "${POSTGRES_CONTAINER}" 5432/tcp \
      | awk -F: 'NR == 1 {print $NF}'
  )"
  [[ -n "${POSTGRES_PORT}" ]] || fail "could not discover published PostgreSQL port"

  local attempt=1
  while [[ "${attempt}" -le "${STARTUP_ATTEMPTS}" ]]; do
    if docker exec "${POSTGRES_CONTAINER}" \
      pg_isready -h 127.0.0.1 -p 5432 -U abyss -d abyss >/dev/null 2>&1; then
      return 0
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "${POSTGRES_CONTAINER}" 2>/dev/null || true)" != "true" ]]; then
      fail "PostgreSQL exited before becoming ready"
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  fail "PostgreSQL did not become ready"
}

start_backend() {
  local database_url="postgres://abyss:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/abyss?sslmode=disable"
  docker run \
    --platform "${BACKEND_PLATFORM}" \
    --name "${BACKEND_CONTAINER}" \
    --network host \
    -e "ABYSS_BACKEND_ADDR=127.0.0.1:${BACKEND_PORT}" \
    -e ABYSS_BACKEND_ENV=blackbox \
    -e "ABYSS_BACKEND_API_TOKEN_SHA256=${NATIVE_TOKEN_HASH}" \
    -e "ABYSS_BACKEND_DATABASE_URL=${database_url}" \
    -e ABYSS_BACKEND_RUN_MIGRATIONS=true \
    -d "${BACKEND_IMAGE}" >/dev/null

  local attempt=1
  while [[ "${attempt}" -le "${STARTUP_ATTEMPTS}" ]]; do
    if curl -fsS --max-time "${CURL_TIMEOUT_SECONDS}" "${BACKEND_BASE_URL}/readyz" >/dev/null 2>&1; then
      return 0
    fi
    if [[ "$(docker inspect -f '{{.State.Running}}' "${BACKEND_CONTAINER}" 2>/dev/null || true)" != "true" ]]; then
      fail "abyss-backend exited before becoming ready"
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  fail "abyss-backend did not become ready"
}

write_broker_config() {
  cat >"${BROKER_CONFIG}" <<EOF
schema_version = 1

[devtools]
log_level = "info"
performance_trace = false
log_location = "${LOG_DIR}/broker"

[ca]
path = "${CA_DIR}"

[proxy]
mode = "explicit"
listen_addr = "127.0.0.1:${ABYSS_CLAUDE_CODE_E2E_PROXY_PORT:-0}"
EOF
  cat >"${RUNTIME_POLICY}" <<'EOF'
schema_version = 1

[mitm.tls_decryption]
default_action = "passthrough"
missing_sni_action = "passthrough"

[[mitm.tls_decryption.rules]]
id = "decrypt-anthropic-claude-code"
action = "intercept"
destination_hosts = ["anthropic.com", "*.anthropic.com", "claude.ai", "*.claude.ai", "dmxapi.cn", "*.dmxapi.cn"]

[hooks.harness_usage]
enabled = true

[hooks.harness_usage.config.content]
token_usage = true
conversation_text = true
tool_calls = true
images = true

[hooks.harness_usage.config.harnesses."claude-code"]
enabled = true

[hooks.harness_usage.config.harnesses."claude-code".content]
token_usage = true
conversation_text = true
tool_calls = true
images = true
EOF
}

write_delivery_config() {
  printf 'Bearer %s\n' "${NATIVE_TOKEN}" >"${DELIVERY_AUTH_FILE}"
  chmod 600 "${DELIVERY_AUTH_FILE}"
  jq -n \
    --arg endpoint "${BACKEND_BASE_URL}/v1/agent-usage/events" \
    --arg auth_path "${DELIVERY_AUTH_FILE}" \
    --arg spool_path "${SPOOL_PATH}" \
    '{
      schema_version: 1,
      product: {kind: "cli"},
      delivery_worker: {
        plugin_id: "lexmount.abyss.claude-code-e2e-delivery",
        delivery: {
          endpoint: $endpoint,
          spool_enabled: true,
          spool_path: $spool_path
        },
        authentication: {
          mode: "authorization_header_file",
          path: $auth_path
        }
      }
    }' >"${DELIVERY_CONFIG}"
}

start_broker() {
  local api_addr="127.0.0.1:${ABYSS_CLAUDE_CODE_E2E_API_PORT:-0}"
  rm -f "${BROKER_STARTUP_INFO}"
  ABYSS_HOME="${BROKER_HOME}" \
  TMPDIR="${RUNTIME_TMP_DIR}" \
  "${BROKER_BINARY}" \
    --api "${api_addr}" \
    --config "${BROKER_CONFIG}" \
    --auth-token-file "${BROKER_AUTH_TOKEN_FILE}" \
    --startup-info-file "${BROKER_STARTUP_INFO}" \
    >"${BROKER_LOG}" 2>&1 &
  BROKER_PID=$!

  local attempt=1
  local status_response
  while [[ "${attempt}" -le "${STARTUP_ATTEMPTS}" ]]; do
    if [[ -s "${BROKER_STARTUP_INFO}" ]]; then
      local broker_listen_addr
      broker_listen_addr="$(jq -r '.api_addr // empty' "${BROKER_STARTUP_INFO}")"
      if [[ -n "${broker_listen_addr}" ]]; then
        BROKER_BASE_URL="http://${broker_listen_addr}"
      fi
    fi
    if [[ -n "${BROKER_BASE_URL}" ]] \
      && curl -fsS --max-time "${CURL_TIMEOUT_SECONDS}" "${BROKER_BASE_URL}/healthz" >/dev/null 2>&1; then
      status_response="$(curl -fsS --max-time "${CURL_TIMEOUT_SECONDS}" "${BROKER_BASE_URL}/v1/proxy/status")"
      jq -e \
        '.lifecycle == "running" and .mode == "explicit" and any(.ingresses[]; .source == "explicit_http" and (.listen_addr | type == "string" and length > 0))' \
        <<<"${status_response}" >/dev/null \
        || fail "broker proxy status did not report the expected explicit listener"
      local proxy_listen_addr
      proxy_listen_addr="$(jq -r '[.ingresses[] | select(.source == "explicit_http") | .listen_addr][0] // empty' <<<"${status_response}")"
      [[ -n "${proxy_listen_addr}" ]] || fail "could not discover explicit proxy listener"
      PROXY_URL="http://${proxy_listen_addr}"
      return 0
    fi
    if ! kill -0 "${BROKER_PID}" 2>/dev/null; then
      fail "abyss-broker exited before becoming ready"
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  fail "abyss-broker did not become ready"
}

start_delivery_plugin() {
  ABYSS_HOME="${BROKER_HOME}" \
  ABYSS_BROKER_STARTUP_INFO="${BROKER_STARTUP_INFO}" \
  "${DELIVERY_BINARY}" --config "${DELIVERY_CONFIG}" >"${DELIVERY_LOG}" 2>&1 &
  DELIVERY_PID=$!
  sleep 1
  kill -0 "${DELIVERY_PID}" 2>/dev/null \
    || fail "abyss-delivery-plugin exited before Agent traffic started"
}

verify_broker_runtime_policy() {
  [[ "${RUNTIME_POLICY}" == "${BROKER_HOME}/runtime-policy.toml" ]] \
    || fail "runtime policy path is outside the broker ABYSS_HOME"
  [[ -s "${RUNTIME_POLICY}" ]] || fail "broker runtime policy was not written"

  local broker_token
  broker_token="$(tr -d '\r\n' <"${BROKER_AUTH_TOKEN_FILE}")"
  curl -fsS \
    --max-time "${CURL_TIMEOUT_SECONDS}" \
    -H "Authorization: Bearer ${broker_token}" \
    "${BROKER_BASE_URL}/v1/mitm/config" \
    | jq -e \
      '.tls_decryption.rules | any(.id == "decrypt-anthropic-claude-code" and .action == "intercept")' \
      >/dev/null \
    || fail "broker did not load the Claude Code MITM runtime policy"
  curl -fsS \
    --max-time "${CURL_TIMEOUT_SECONDS}" \
    -H "Authorization: Bearer ${broker_token}" \
    "${BROKER_BASE_URL}/v1/hooks/config" \
    | jq -e \
      '.harness_usage.enabled == true and .harness_usage.config.harnesses["claude-code"].enabled == true' \
      >/dev/null \
    || fail "broker did not load the Claude Code Hook runtime policy"
}

run_claude_code() {
  local marker="$1"
  local output_log="$2"
  local stderr_log="$3"
  local prompt="$4"

  if ! (
    cd "${WORK_DIR}"
    unset ALL_PROXY all_proxy
    unset ANTHROPIC_AUTH_TOKEN CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_CUSTOM_HEADERS
    export HOME="${HOME_DIR}"
    export ANTHROPIC_API_KEY="${CLAUDE_CODE_API_KEY_FOR_RUN}"
    export ANTHROPIC_BASE_URL="${CLAUDE_CODE_BASE_URL_FOR_RUN}"
    export CLAUDE_CODE_API_BASE_URL="${CLAUDE_CODE_BASE_URL_FOR_RUN}"
    export HTTP_PROXY="${PROXY_URL}"
    export HTTPS_PROXY="${PROXY_URL}"
    export http_proxy="${PROXY_URL}"
    export https_proxy="${PROXY_URL}"
    export NO_PROXY='localhost,127.0.0.1,::1'
    export no_proxy='localhost,127.0.0.1,::1'
    export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
    export NODE_EXTRA_CA_CERTS=/etc/ssl/certs/ca-certificates.crt
    export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1
    export CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=1
    export CLAUDE_CODE_DISABLE_FAST_MODE=1
    export CLAUDE_CODE_SKIP_FAST_MODE_ORG_CHECK=1
    export CLAUDE_CODE_DISABLE_EXPERIMENTAL_BETAS=1
    export DISABLE_TELEMETRY=1
    export CLAUDE_CODE_ENABLE_TELEMETRY=0
    claude_args=(
      --bare
      --print
      --output-format json
      --no-session-persistence
      --permission-mode dontAsk
    )
    if [[ -n "${CLAUDE_CODE_MODEL_FOR_RUN}" ]]; then
      claude_args+=(--model "${CLAUDE_CODE_MODEL_FOR_RUN}")
    fi
    exec claude "${claude_args[@]}" "${prompt}" </dev/null
  ) >"${output_log}" 2>"${stderr_log}"; then
    print_claude_error_summary "${output_log}" "${stderr_log}"
    fail "Claude Code did not complete against its configured Anthropic-compatible service"
  fi

  [[ -s "${output_log}" ]] || fail "Claude Code completed without producing output for ${marker}"
}

validate_claude_pair() {
  local marker="$1"
  local pair_json="$2"

  blackbox_assert_pair_identity "${pair_json}" \
    || fail "Claude Code event pair for ${marker} failed identity checks"
  jq -e \
    --arg marker "${marker}" \
    --arg expected_provider "${EXPECTED_LLM_PROVIDER}" \
    '
      (.request.text | type == "string" and contains($marker))
      and .request.agent_name == "claude-code"
      and .response.agent_name == "claude-code"
      and .request.llm_provider == $expected_provider
      and .response.llm_provider == $expected_provider
      and (.request.llm_model | type == "string" and length > 0 and . != "unknown")
      and .response.llm_model == .request.llm_model
      and .request.input_tokens > 0
      and .request.output_tokens == 0
      and .request.total_tokens == .request.input_tokens
      and (.response.text | type == "string" and length > 0)
      and .response.input_tokens == 0
      and .response.output_tokens > 0
      and .response.total_tokens == .response.output_tokens
    ' <<<"${pair_json}" >/dev/null \
    || fail "Claude Code event pair for ${marker} failed structured event checks"
}

validate_claude_summary() {
  local first_pair="$1"
  local second_pair="$2"
  local first_session
  local second_session
  local summary_json
  local pairs_json

  first_session="$(jq -r '.request.session_id' <<<"${first_pair}")"
  second_session="$(jq -r '.request.session_id' <<<"${second_pair}")"
  if [[ "${first_session}" == "${second_session}" ]]; then
    pairs_json="$(jq -cn \
      --argjson first "${first_pair}" \
      --argjson second "${second_pair}" \
      '[ $first, $second ]')"
    summary_json="$(blackbox_fetch_summary \
      "${BACKEND_BASE_URL}" \
      "${NATIVE_TOKEN}" \
      claude-code \
      "${EXPECTED_LLM_PROVIDER}" \
      "${first_session}" \
      "${CURL_TIMEOUT_SECONDS}")" \
      || fail "backend usage summary request failed for Claude Code sessions"
    blackbox_assert_summary_matches_pairs "${summary_json}" "${pairs_json}" \
      || fail "backend usage summary did not match the Claude Code event pairs"
    return 0
  fi

  summary_json="$(blackbox_fetch_summary \
    "${BACKEND_BASE_URL}" \
    "${NATIVE_TOKEN}" \
    claude-code \
    "${EXPECTED_LLM_PROVIDER}" \
    "${first_session}" \
    "${CURL_TIMEOUT_SECONDS}")" \
    || fail "backend usage summary request failed for first Claude Code session"
  blackbox_assert_summary_matches_pair "${summary_json}" "${first_pair}" \
    || fail "backend usage summary did not match the first Claude Code event pair"
  summary_json="$(blackbox_fetch_summary \
    "${BACKEND_BASE_URL}" \
    "${NATIVE_TOKEN}" \
    claude-code \
    "${EXPECTED_LLM_PROVIDER}" \
    "${second_session}" \
    "${CURL_TIMEOUT_SECONDS}")" \
    || fail "backend usage summary request failed for second Claude Code session"
  blackbox_assert_summary_matches_pair "${summary_json}" "${second_pair}" \
    || fail "backend usage summary did not match the second Claude Code event pair"
}

wait_for_uploaded_events() {
  local attempt=1
  local first_pair=""
  local second_pair=""
  while [[ "${attempt}" -le "${EVENT_ATTEMPTS}" ]]; do
    if curl -fsS \
      --max-time "${CURL_TIMEOUT_SECONDS}" \
      -H "Authorization: Bearer ${NATIVE_TOKEN}" \
      "${BACKEND_BASE_URL}/v1/agent-usage/events?agent_name=claude-code&llm_provider=${EXPECTED_LLM_PROVIDER}&limit=100" \
      >"${EVENTS_RESPONSE}" 2>/dev/null; then
      first_pair="$(blackbox_extract_event_pair \
        "${EVENTS_RESPONSE}" "${PROMPT_MARKER}" claude-code "${EXPECTED_LLM_PROVIDER}")" \
        || fail "backend returned malformed Claude Code usage events"
      second_pair="$(blackbox_extract_event_pair \
        "${EVENTS_RESPONSE}" "${SECOND_PROMPT_MARKER}" claude-code "${EXPECTED_LLM_PROVIDER}")" \
        || fail "backend returned malformed second Claude Code usage events"
      if [[ -n "${first_pair}" && -n "${second_pair}" ]]; then
        validate_claude_pair "${PROMPT_MARKER}" "${first_pair}"
        validate_claude_pair "${SECOND_PROMPT_MARKER}" "${second_pair}"
        validate_claude_summary "${first_pair}" "${second_pair}"
        return 0
      fi
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  fail "backend did not expose the expected Claude Code request and response events"
}

verify_no_spool() {
  if [[ -s "${SPOOL_PATH}" ]]; then
    fail "delivery plugin wrote a spool record despite successful backend upload"
  fi
}

validate_claude_code_config
write_ca
install_ca
pull_backend_image
cargo build --locked --package abyss-broker --package abyss-delivery-plugin
start_postgres
start_backend
write_broker_config
write_delivery_config
start_broker
verify_broker_runtime_policy
start_delivery_plugin
run_claude_code \
  "${PROMPT_MARKER}" \
  "${CLAUDE_LOG}" \
  "${CLAUDE_STDERR_LOG}" \
  "Do not use tools. Reply briefly and include this exact audit marker: ${PROMPT_MARKER}"
run_claude_code \
  "${SECOND_PROMPT_MARKER}" \
  "${CLAUDE_SECOND_LOG}" \
  "${CLAUDE_SECOND_STDERR_LOG}" \
  "Do not use tools. This is a second coverage case: reply briefly, preserve the Unicode text 雪山 / café, and acknowledge the multiline input with punctuation such as em dashes and brackets. Include this exact audit marker on its own line:
${SECOND_PROMPT_MARKER}"
wait_for_uploaded_events
verify_no_spool

echo "blackbox: Claude Code MITM context upload ok (run ${RUN_ID})"
