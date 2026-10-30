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
        input_tokens: 8,
        output_tokens: 0,
        cache_read_tokens: 2,
        cache_write_tokens: 1,
        reasoning_tokens: 0,
        total_tokens: 11,
        conversation: {entries: [{role: "user", text: $marker}], completeness: "complete"},
        metadata: {
          provider_usage: {input_tokens: 11, output_tokens: 7, total_tokens: 21}
        }
      },
      {
        event_id: "response-event",
        event_type: "response",
        agent_name: "codex",
        llm_provider: "openai",
        llm_model: "gpt-test",
        session_id: "session-test",
        turn_index: 3,
        input_tokens: 0,
        output_tokens: 7,
        cache_read_tokens: 0,
        cache_write_tokens: 0,
        reasoning_tokens: 3,
        total_tokens: 7,
        conversation: {
          entries: [{role: "assistant", text: "response"}],
          completeness: "complete"
        }
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

# Codex 0.144.3 reports these four counters but no cache-write counter. Keep
# that absence distinct from zero while retaining strict input-total checks.
printf '%s\n' \
  '{"type":"turn.completed","usage":{"input_tokens":11,"cached_input_tokens":2,"output_tokens":7,"reasoning_output_tokens":3}}' \
  >"${TMP_DIR}/codex-0.144.3.jsonl"
LEGACY_USAGE_JSON="$(blackbox_extract_codex_usage "${TMP_DIR}/codex-0.144.3.jsonl")"
jq -e 'has("cache_write_input_tokens") | not' <<<"${LEGACY_USAGE_JSON}" >/dev/null
blackbox_assert_codex_usage_matches_pair "${LEGACY_USAGE_JSON}" "${PAIR_JSON}"
for field in input_tokens cached_input_tokens output_tokens reasoning_output_tokens; do
  BAD_USAGE_JSON="$(jq -c --arg field "${field}" '.[$field] += 1' <<<"${LEGACY_USAGE_JSON}")"
  if blackbox_assert_codex_usage_matches_pair "${BAD_USAGE_JSON}" "${PAIR_JSON}" >/dev/null 2>&1; then
    echo "Missing cache-write evidence must not hide ${field} mismatches" >&2
    exit 1
  fi
done
ZERO_WRITE_USAGE_JSON="$(jq -c '.cache_write_input_tokens = 0' <<<"${LEGACY_USAGE_JSON}")"
if blackbox_assert_codex_usage_matches_pair "${ZERO_WRITE_USAGE_JSON}" "${PAIR_JSON}" >/dev/null 2>&1; then
  echo "Explicit zero cache writes must still match the backend" >&2
  exit 1
fi
printf '%s\n' \
  '{"type":"turn.completed","usage":{"input_tokens":11,"output_tokens":7,"cache_write_input_tokens":null}}' \
  >"${TMP_DIR}/codex-invalid-cache-write.jsonl"
if blackbox_extract_codex_usage "${TMP_DIR}/codex-invalid-cache-write.jsonl" >/dev/null 2>&1; then
  echo "Invalid cache writes must not be treated as an absent counter" >&2
  exit 1
fi

SUMMARY_JSON='{
  "rows": [
    {"event_type":"request","requests":1,"responses":0,"input_tokens":8,"output_tokens":0,"cache_read_tokens":2,"cache_write_tokens":1,"reasoning_tokens":0,"total_tokens":11},
    {"event_type":"response","requests":0,"responses":1,"input_tokens":0,"output_tokens":7,"cache_read_tokens":0,"cache_write_tokens":0,"reasoning_tokens":3,"total_tokens":7}
  ]
}'
blackbox_assert_summary_matches_pair "${SUMMARY_JSON}" "${PAIR_JSON}"

TWO_PAIRS_JSON="$(jq -cn --argjson pair "${PAIR_JSON}" '[ $pair, $pair ]')"
SUMMARY_TWO_JSON='{
  "rows": [
    {"event_type":"request","requests":2,"responses":0,"input_tokens":16,"output_tokens":0,"cache_read_tokens":4,"cache_write_tokens":2,"reasoning_tokens":0,"total_tokens":22},
    {"event_type":"response","requests":0,"responses":2,"input_tokens":0,"output_tokens":14,"cache_read_tokens":0,"cache_write_tokens":0,"reasoning_tokens":6,"total_tokens":14}
  ]
}'
blackbox_assert_summary_matches_pairs "${SUMMARY_TWO_JSON}" "${TWO_PAIRS_JSON}"

# A completed WebSocket prewarm can report input usage without a response
# message. The session summary must include that request, while the native
# turn.completed usage still matches only the marker request/response pair.
PREWARM_EVENTS_JSON="$(jq -c '.events + [(.events[0] | .event_id = "prewarm-event"
  | .conversation.entries = [{role: "system", text: "prewarm instructions"}]
  | .input_tokens = 6 | .cache_read_tokens = 0
  | .cache_write_tokens = 0 | .total_tokens = 6
  | .metadata.purpose = "prewarm")]' "${EVENTS_FILE}")"
PREWARM_SUMMARY_JSON="$(jq -c '.rows[0].requests += 1
  | .rows[0].input_tokens += 6 | .rows[0].total_tokens += 6' <<<"${SUMMARY_JSON}")"
blackbox_assert_summary_matches_events "${PREWARM_SUMMARY_JSON}" "${PREWARM_EVENTS_JSON}"
blackbox_assert_codex_usage_matches_pair "${USAGE_JSON}" "${PAIR_JSON}"
COMPLETED_USAGE_JSON="$(jq -cn --argjson usage "${USAGE_JSON}" '[$usage]')"
blackbox_assert_codex_session_usage "${COMPLETED_USAGE_JSON}" "${PREWARM_EVENTS_JSON}" >/dev/null
UNMARKED_EVENTS_JSON="$(jq -c 'map(del(.metadata.purpose))' <<<"${PREWARM_EVENTS_JSON}")"
if blackbox_assert_codex_session_usage "${COMPLETED_USAGE_JSON}" "${UNMARKED_EVENTS_JSON}" >/dev/null 2>&1; then
  echo "Unmarked initial requests must remain in inference usage" >&2
  exit 1
fi
if blackbox_assert_summary_matches_pair "${PREWARM_SUMMARY_JSON}" "${PAIR_JSON}" >/dev/null 2>&1; then
  echo "Pair-only summary must detect the additional prewarm request" >&2
  exit 1
fi
if blackbox_assert_summary_matches_events "${SUMMARY_JSON}" "${PREWARM_EVENTS_JSON}" >/dev/null 2>&1; then
  echo "Summary must not omit prewarm request counts and tokens" >&2
  exit 1
fi
BAD_PREWARM_SUMMARY="$(jq -c '.rows[0].input_tokens += 1' <<<"${PREWARM_SUMMARY_JSON}")"
if blackbox_assert_summary_matches_events "${BAD_PREWARM_SUMMARY}" "${PREWARM_EVENTS_JSON}" >/dev/null 2>&1; then
  echo "Summary must still reject a one-token mismatch" >&2
  exit 1
fi

printf '%s\n' \
  '{"type":"turn.completed","usage":{"input_tokens":5,"output_tokens":4}}' \
  >"${TMP_DIR}/codex-optional-fields.jsonl"
EXPECTED_OPTIONAL_USAGE='{"input_tokens":5,"cached_input_tokens":0,"output_tokens":4,"reasoning_output_tokens":0}'
ACTUAL_OPTIONAL_USAGE="$(blackbox_extract_codex_usage "${TMP_DIR}/codex-optional-fields.jsonl")"
[[ "${ACTUAL_OPTIONAL_USAGE}" == "${EXPECTED_OPTIONAL_USAGE}" ]]

printf '%s\n' \
  '{"type":"turn.failed","error":{"message":"provider failure"}}' \
  >"${TMP_DIR}/codex-failed.jsonl"
if blackbox_extract_codex_usage "${TMP_DIR}/codex-failed.jsonl" >/dev/null 2>&1; then
  echo "Codex failure events must fail usage extraction" >&2
  exit 1
fi

printf '%s\n' \
  'not a JSON event' \
  '["not an event object"]' \
  '{"type":"item.completed","item":{"text":"private conversation"}}' \
  '{"type":"error","message":"request failed: Bearer test-token and sk-test-secret"}' \
  '{"type":"turn.failed","error":{"message":"provider failure"}}' \
  >"${TMP_DIR}/codex-errors.jsonl"
ERROR_SUMMARY="$(blackbox_codex_error_summary "${TMP_DIR}/codex-errors.jsonl")"
jq -e '. == ["provider failure", "request failed: <redacted> and <redacted>"]' \
  <<<"${ERROR_SUMMARY}" >/dev/null
jq -cn '{type: "error", message: ("x" * 2000)}' >"${TMP_DIR}/codex-long-error.jsonl"
blackbox_codex_error_summary "${TMP_DIR}/codex-long-error.jsonl" \
  | jq -e 'length == 1 and (.[0] | length) == 1200' >/dev/null
blackbox_codex_error_summary "${CODEX_LOG}" | jq -e '. == []' >/dev/null

echo "blackbox helper tests: ok"
