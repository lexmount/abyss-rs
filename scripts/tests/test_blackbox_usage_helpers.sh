#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/blackbox_usage.sh
source "${SCRIPT_DIR}/lib/blackbox_usage.sh"

TMP_DIR="$(mktemp -d -t abyss-blackbox-helpers.XXXXXX)"
trap 'rm -rf "${TMP_DIR}"' EXIT

MARKER="helper-test-marker"
EVENTS_FILE="${TMP_DIR}/events.json"
CODEX_LOG="${TMP_DIR}/codex.jsonl"

jq -n \
  --arg marker "${MARKER}" \
  '{
    events: [
      {
        event_id: "request-event",
        event_type: "request",
        agent_name: "codex",
        llm_provider: "openai",
        llm_model: "gpt-test",
        session_id: "session-test",
        turn_index: 3,
        text: $marker,
        input_tokens: 11,
        output_tokens: 0,
        cache_read_tokens: 2,
        cache_write_tokens: 1,
        reasoning_tokens: 0,
        total_tokens: 11,
        metadata: {provider_usage: {input_tokens: 11, output_tokens: 7, total_tokens: 21}}
      },
      {
        event_id: "response-event",
        event_type: "response",
        agent_name: "codex",
        llm_provider: "openai",
        llm_model: "gpt-test",
        session_id: "session-test",
        turn_index: 3,
        text: "response",
        input_tokens: 0,
        output_tokens: 7,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 3,
        total_tokens: 7,
        metadata: {}
      }
    ]
  }' >"${EVENTS_FILE}"

printf '%s\n' \
  '{"type":"thread.started"}' \
  '{"type":"turn.completed","usage":{"input_tokens":11,"cached_input_tokens":2,"cache_write_input_tokens":1,"output_tokens":7,"reasoning_output_tokens":3}}' \
  >"${CODEX_LOG}"

PAIR_JSON="$(blackbox_extract_event_pair "${EVENTS_FILE}" "${MARKER}" codex openai)"
blackbox_assert_pair_identity "${PAIR_JSON}"
USAGE_JSON="$(blackbox_extract_codex_usage "${CODEX_LOG}")"
blackbox_assert_codex_usage_matches_pair "${USAGE_JSON}" "${PAIR_JSON}"

SUMMARY_JSON='{
  "rows": [
    {"event_type":"request","requests":1,"responses":0,"input_tokens":11,"output_tokens":0,"cache_read_tokens":2,"cache_write_tokens":1,"reasoning_tokens":0,"total_tokens":11},
    {"event_type":"response","requests":0,"responses":1,"input_tokens":0,"output_tokens":7,"cache_read_tokens":0,"cache_write_tokens":0,"reasoning_tokens":3,"total_tokens":7}
  ]
}'
blackbox_assert_summary_matches_pair "${SUMMARY_JSON}" "${PAIR_JSON}"

TWO_PAIRS_JSON="$(jq -cn --argjson pair "${PAIR_JSON}" '[ $pair, $pair ]')"
SUMMARY_TWO_JSON='{
  "rows": [
    {"event_type":"request","requests":2,"responses":0,"input_tokens":22,"output_tokens":0,"cache_read_tokens":4,"cache_write_tokens":2,"reasoning_tokens":0,"total_tokens":22},
    {"event_type":"response","requests":0,"responses":2,"input_tokens":0,"output_tokens":14,"cache_read_tokens":0,"cache_write_tokens":0,"reasoning_tokens":6,"total_tokens":14}
  ]
}'
blackbox_assert_summary_matches_pairs "${SUMMARY_TWO_JSON}" "${TWO_PAIRS_JSON}"

printf '%s\n' \
  '{"type":"turn.completed","usage":{"input_tokens":5,"output_tokens":4}}' \
  >"${TMP_DIR}/codex-optional-fields.jsonl"
EXPECTED_OPTIONAL_USAGE='{"input_tokens":5,"cached_input_tokens":0,"cache_write_input_tokens":0,"output_tokens":4,"reasoning_output_tokens":0}'
ACTUAL_OPTIONAL_USAGE="$(blackbox_extract_codex_usage "${TMP_DIR}/codex-optional-fields.jsonl")"
[[ "${ACTUAL_OPTIONAL_USAGE}" == "${EXPECTED_OPTIONAL_USAGE}" ]]

printf '%s\n' \
  '{"type":"turn.failed","error":{"message":"provider failure"}}' \
  >"${TMP_DIR}/codex-failed.jsonl"
if blackbox_extract_codex_usage "${TMP_DIR}/codex-failed.jsonl" >/dev/null 2>&1; then
  echo "Codex failure events must fail usage extraction" >&2
  exit 1
fi

echo "blackbox helper tests: ok"
