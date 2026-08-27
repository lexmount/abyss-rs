#!/usr/bin/env bash

set -euo pipefail

# Keep CI credentials out of every setup subprocess. The value is exported only
# inside `run_codex` immediately before replacing the subshell with Codex.
CODEX_API_KEY_FOR_RUN="${CODEX_API_KEY-}"
unset CODEX_API_KEY

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "the Codex usage upload black-box test requires Linux." >&2
  exit 2
fi

for command in cargo codex curl docker git jq openssl python3 sha256sum sudo update-ca-certificates; do
  command -v "${command}" >/dev/null || {
    echo "${command} is required for the Codex usage upload black-box test." >&2
    exit 2
  }
done

docker info >/dev/null 2>&1 || {
  echo "the Docker broker must be running for the Codex usage upload black-box test." >&2
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
TMP_DIR="${ABYSS_CODEX_E2E_TMP_DIR:-$(mktemp -d -t abyss-codex-e2e.XXXXXX)}"
RUNTIME_TMP_DIR="${TMP_DIR}/runtime"
BROKER_HOME="${TMP_DIR}/broker-home"
CA_DIR="${TMP_DIR}/ca"
LOG_DIR="${TMP_DIR}/logs"
WORK_DIR="${TMP_DIR}/workspace"
BROKER_CONFIG="${TMP_DIR}/broker-config.toml"
RUNTIME_POLICY="${BROKER_HOME}/runtime-policy.toml"
BROKER_AUTH_TOKEN_FILE="${TMP_DIR}/broker.token"
BROKER_STARTUP_INFO="${TMP_DIR}/broker-startup.json"
BROKER_LOG="${LOG_DIR}/broker-stdio.log"
BROKER_FILE_LOG="${LOG_DIR}/broker/abyss-broker.log"
DELIVERY_CONFIG="${TMP_DIR}/product-config.json"
DELIVERY_AUTH_FILE="${TMP_DIR}/delivery-authorization"
DELIVERY_LOG="${LOG_DIR}/delivery-plugin.log"
CODEX_LOG="${LOG_DIR}/codex.jsonl"
CODEX_SECOND_LOG="${LOG_DIR}/codex-second.jsonl"
CODEX_STDERR_LOG="${LOG_DIR}/codex.stderr.log"
CODEX_SECOND_STDERR_LOG="${LOG_DIR}/codex-second.stderr.log"
CA_UPDATE_LOG="${LOG_DIR}/update-ca-certificates.log"
EVENTS_RESPONSE="${TMP_DIR}/events.json"
SPOOL_PATH="${BROKER_HOME}/delivery/failed-events.jsonl"

BACKEND_IMAGE="${ABYSS_CODEX_E2E_BACKEND_IMAGE:-$(tr -d '\r\n' < "${REPO_ROOT}/scripts/ci/abyss-backend-image.txt")}"
BACKEND_PLATFORM="${ABYSS_CODEX_E2E_BACKEND_PLATFORM:-linux/amd64}"
POSTGRES_IMAGE="${ABYSS_CODEX_E2E_POSTGRES_IMAGE:-postgres:16}"
BROKER_BINARY="${CARGO_TARGET_DIR:-target}/debug/abyss-broker"
DELIVERY_BINARY="${CARGO_TARGET_DIR:-target}/debug/abyss-delivery-plugin"
POSTGRES_CONTAINER="abyss-codex-e2e-postgres-${RUN_ID}"
BACKEND_CONTAINER="abyss-codex-e2e-backend-${RUN_ID}"
SYSTEM_CA_FILE="/usr/local/share/ca-certificates/abyss-codex-e2e-${RUN_ID}.crt"
NATIVE_TOKEN="$(openssl rand -hex 32)"
NATIVE_TOKEN_HASH="$(printf '%s' "${NATIVE_TOKEN}" | sha256sum | awk '{print $1}')"
PROMPT_MARKER="ABYSS_CODEX_PROMPT_${RUN_ID}"
SECOND_PROMPT_MARKER="ABYSS_CODEX_PROMPT_SECOND_${RUN_ID}"
STARTUP_ATTEMPTS="${ABYSS_CODEX_E2E_STARTUP_ATTEMPTS:-180}"
EVENT_ATTEMPTS="${ABYSS_CODEX_E2E_EVENT_ATTEMPTS:-60}"
CURL_TIMEOUT_SECONDS="${ABYSS_CODEX_E2E_CURL_TIMEOUT_SECONDS:-10}"

BROKER_PID=""
DELIVERY_PID=""
POSTGRES_PORT=""
CA_INSTALLED=0
LOGS_PRINTED=0
CODEX_USAGE_ONE=""
CODEX_USAGE_TWO=""

reserve_port() {
  python3 - <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

BACKEND_PORT="${ABYSS_CODEX_E2E_BACKEND_PORT:-$(reserve_port)}"
API_PORT="${ABYSS_CODEX_E2E_API_PORT:-$(reserve_port)}"
PROXY_PORT="${ABYSS_CODEX_E2E_PROXY_PORT:-$(reserve_port)}"
BACKEND_BASE_URL="http://127.0.0.1:${BACKEND_PORT}"
BROKER_BASE_URL="http://127.0.0.1:${API_PORT}"
PROXY_URL="http://127.0.0.1:${PROXY_PORT}"

mkdir -p \
  "${RUNTIME_TMP_DIR}" \
  "${BROKER_HOME}" \
  "${CA_DIR}" \
  "${LOG_DIR}" \
  "${WORK_DIR}"
chmod 700 \
  "${TMP_DIR}" \
  "${RUNTIME_TMP_DIR}" \
  "${BROKER_HOME}" \
  "${CA_DIR}" \
  "${LOG_DIR}"
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
  if [[ -f "${CODEX_LOG}" ]]; then
    echo "Codex output retained at ${CODEX_LOG}; contents omitted to protect request context." >&2
  fi
  if [[ -f "${CODEX_SECOND_LOG}" ]]; then
    echo "Second Codex output retained at ${CODEX_SECOND_LOG}; contents omitted to protect request context." >&2
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

  if kill -0 "${BROKER_PID}" 2>/dev/null && [[ -f "${BROKER_AUTH_TOKEN_FILE}" ]]; then
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

  CODEX_API_KEY_FOR_RUN=""
  NATIVE_TOKEN=""
  if [[ -z "${ABYSS_CODEX_E2E_TMP_DIR:-}" ]]; then
    rm -rf "${TMP_DIR}"
  fi
  exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

write_ca() {
  local root_config="${TMP_DIR}/root-openssl.cnf"

  cat >"${root_config}" <<EOF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = Abyss Codex E2E Root ${RUN_ID}

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
  POSTGRES_PORT="${ABYSS_CODEX_E2E_POSTGRES_PORT:-$(reserve_port)}"
  docker run \
    --name "${POSTGRES_CONTAINER}" \
    --network host \
    -e POSTGRES_USER=abyss \
    -e POSTGRES_PASSWORD=abyss \
    -e POSTGRES_DB=abyss \
    -d "${POSTGRES_IMAGE}" \
    -c listen_addresses=127.0.0.1 \
    -c "port=${POSTGRES_PORT}" >/dev/null

  local attempt=1
  while [[ "${attempt}" -le "${STARTUP_ATTEMPTS}" ]]; do
    if docker exec "${POSTGRES_CONTAINER}" \
      pg_isready -h 127.0.0.1 -p "${POSTGRES_PORT}" -U abyss -d abyss >/dev/null 2>&1; then
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
  local database_url="postgres://abyss:abyss@127.0.0.1:${POSTGRES_PORT}/abyss?sslmode=disable"
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
listen_addr = "127.0.0.1:${PROXY_PORT}"
EOF
  cat >"${RUNTIME_POLICY}" <<'EOF'
schema_version = 1

[mitm.tls_decryption]
default_action = "passthrough"
missing_sni_action = "passthrough"

[[mitm.tls_decryption.rules]]
id = "decrypt-openai-codex"
action = "intercept"
destination_hosts = ["openai.com", "*.openai.com", "chatgpt.com", "*.chatgpt.com"]

[hooks.harness_usage]
enabled = true

[hooks.harness_usage.config.content]
token_usage = true
conversation_text = true
tool_calls = true
images = true

[hooks.harness_usage.config.harnesses.codex]
enabled = true

[hooks.harness_usage.config.harnesses.codex.content]
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
        plugin_id: "lexmount.abyss.codex-e2e-delivery",
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
  rm -f "${BROKER_STARTUP_INFO}"
  ABYSS_HOME="${BROKER_HOME}" \
  TMPDIR="${RUNTIME_TMP_DIR}" \
  "${BROKER_BINARY}" \
    --api "127.0.0.1:${API_PORT}" \
    --config "${BROKER_CONFIG}" \
    --auth-token-file "${BROKER_AUTH_TOKEN_FILE}" \
    --startup-info-file "${BROKER_STARTUP_INFO}" \
    >"${BROKER_LOG}" 2>&1 &
  BROKER_PID=$!

  local attempt=1
  local status_response
  while [[ "${attempt}" -le "${STARTUP_ATTEMPTS}" ]]; do
    if curl -fsS --max-time "${CURL_TIMEOUT_SECONDS}" "${BROKER_BASE_URL}/healthz" >/dev/null 2>&1; then
      status_response="$(curl -fsS --max-time "${CURL_TIMEOUT_SECONDS}" "${BROKER_BASE_URL}/v1/proxy/status")"
      jq -e \
        --arg listen "127.0.0.1:${PROXY_PORT}" \
        '.lifecycle == "running" and .mode == "explicit" and any(.ingresses[]; .source == "explicit_http" and .listen_addr == $listen)' \
        <<<"${status_response}" >/dev/null \
        || fail "broker proxy status did not report the expected explicit listener"
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
      '.tls_decryption.rules | any(.id == "decrypt-openai-codex" and .action == "intercept")' \
      >/dev/null \
    || fail "broker did not load the Codex MITM runtime policy"
  curl -fsS \
    --max-time "${CURL_TIMEOUT_SECONDS}" \
    -H "Authorization: Bearer ${broker_token}" \
    "${BROKER_BASE_URL}/v1/hooks/config" \
    | jq -e \
      '.harness_usage.enabled == true and .harness_usage.config.harnesses.codex.enabled == true' \
      >/dev/null \
    || fail "broker did not load the Codex Hook runtime policy"
}

run_codex() {
  local marker="$1"
  local jsonl_log="$2"
  local stderr_log="$3"
  local prompt="$4"

  if ! (
    unset ALL_PROXY all_proxy
    if [[ -n "${CODEX_API_KEY_FOR_RUN}" ]]; then
      export CODEX_API_KEY="${CODEX_API_KEY_FOR_RUN}"
    fi
    export HTTP_PROXY="${PROXY_URL}"
    export HTTPS_PROXY="${PROXY_URL}"
    export http_proxy="${PROXY_URL}"
    export https_proxy="${PROXY_URL}"
    export NO_PROXY='localhost,127.0.0.1,::1'
    export no_proxy='localhost,127.0.0.1,::1'
    export CODEX_CA_CERTIFICATE=/etc/ssl/certs/ca-certificates.crt
    export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
    exec codex exec \
      --json \
      -C "${WORK_DIR}" \
      "${prompt}" \
      </dev/null
  ) >"${jsonl_log}" 2>"${stderr_log}"; then
    fail "Codex did not complete against its configured OpenAI service"
  fi

  [[ -s "${jsonl_log}" ]] || fail "Codex completed without producing JSON events for ${marker}"
}

validate_codex_pair() {
  local marker="$1"
  local usage_json="$2"
  local pair_json="$3"

  blackbox_assert_pair_identity "${pair_json}" \
    || fail "Codex event pair for ${marker} failed identity checks"
  jq -e \
    --arg marker "${marker}" \
    '
      (.request.text | type == "string" and contains($marker))
      and .request.agent_name == "codex"
      and .response.agent_name == "codex"
      and .request.llm_provider == "openai"
      and .response.llm_provider == "openai"
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
    || fail "Codex event pair for ${marker} failed structured event checks"

  blackbox_assert_codex_usage_matches_pair "${usage_json}" "${pair_json}" \
    || fail "Codex native usage did not match the Abyss event pair for ${marker}"
}

validate_codex_summary() {
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
      codex \
      openai \
      "${first_session}" \
      "${CURL_TIMEOUT_SECONDS}")" \
      || fail "backend usage summary request failed for Codex sessions"
    blackbox_assert_summary_matches_pairs "${summary_json}" "${pairs_json}" \
      || fail "backend usage summary did not match the Codex event pairs"
    return 0
  fi

  summary_json="$(blackbox_fetch_summary \
    "${BACKEND_BASE_URL}" \
    "${NATIVE_TOKEN}" \
    codex \
    openai \
    "${first_session}" \
    "${CURL_TIMEOUT_SECONDS}")" \
    || fail "backend usage summary request failed for first Codex session"
  blackbox_assert_summary_matches_pair "${summary_json}" "${first_pair}" \
    || fail "backend usage summary did not match the first Codex event pair"
  summary_json="$(blackbox_fetch_summary \
    "${BACKEND_BASE_URL}" \
    "${NATIVE_TOKEN}" \
    codex \
    openai \
    "${second_session}" \
    "${CURL_TIMEOUT_SECONDS}")" \
    || fail "backend usage summary request failed for second Codex session"
  blackbox_assert_summary_matches_pair "${summary_json}" "${second_pair}" \
    || fail "backend usage summary did not match the second Codex event pair"
}

wait_for_uploaded_events() {
  local attempt=1
  local first_pair=""
  local second_pair=""
  while [[ "${attempt}" -le "${EVENT_ATTEMPTS}" ]]; do
    if curl -fsS \
      --max-time "${CURL_TIMEOUT_SECONDS}" \
      -H "Authorization: Bearer ${NATIVE_TOKEN}" \
      "${BACKEND_BASE_URL}/v1/agent-usage/events?agent_name=codex&llm_provider=openai&limit=100" \
      >"${EVENTS_RESPONSE}" 2>/dev/null; then
      first_pair="$(blackbox_extract_event_pair \
        "${EVENTS_RESPONSE}" "${PROMPT_MARKER}" codex openai)" \
        || fail "backend returned malformed Codex usage events"
      second_pair="$(blackbox_extract_event_pair \
        "${EVENTS_RESPONSE}" "${SECOND_PROMPT_MARKER}" codex openai)" \
        || fail "backend returned malformed second Codex usage events"
      if [[ -n "${first_pair}" && -n "${second_pair}" ]]; then
        validate_codex_pair "${PROMPT_MARKER}" "${CODEX_USAGE_ONE}" "${first_pair}"
        validate_codex_pair "${SECOND_PROMPT_MARKER}" "${CODEX_USAGE_TWO}" "${second_pair}"
        validate_codex_summary "${first_pair}" "${second_pair}"
        return 0
      fi
    fi
    sleep 1
    attempt=$((attempt + 1))
  done
  fail "backend did not expose the expected Codex request and response events"
}

verify_no_spool() {
  if [[ -s "${SPOOL_PATH}" ]]; then
    fail "delivery plugin wrote a spool record despite successful backend upload"
  fi
}

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
run_codex \
  "${PROMPT_MARKER}" \
  "${CODEX_LOG}" \
  "${CODEX_STDERR_LOG}" \
  "Do not use tools. Reply briefly and include this exact audit marker: ${PROMPT_MARKER}"
if ! CODEX_USAGE_ONE="$(blackbox_extract_codex_usage "${CODEX_LOG}")"; then
  fail "Codex first run did not expose a valid turn.completed usage payload"
fi
run_codex \
  "${SECOND_PROMPT_MARKER}" \
  "${CODEX_SECOND_LOG}" \
  "${CODEX_SECOND_STDERR_LOG}" \
  "Do not use tools. This is a second coverage case: reply briefly, preserve the Unicode text 雪山 / café, and acknowledge the multiline input with punctuation such as em dashes and brackets. Include this exact audit marker on its own line:
${SECOND_PROMPT_MARKER}"
if ! CODEX_USAGE_TWO="$(blackbox_extract_codex_usage "${CODEX_SECOND_LOG}")"; then
  fail "Codex second run did not expose a valid turn.completed usage payload"
fi
wait_for_uploaded_events
verify_no_spool

echo "blackbox: Codex MITM context upload ok (run ${RUN_ID})"
